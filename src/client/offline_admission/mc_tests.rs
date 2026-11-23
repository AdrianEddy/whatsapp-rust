//! WF16 through the read loop: after `<success>` the host is asked once per
//! connection, with the preview's counts, before any of the backlog is asked
//! for or handled; what waits for it is handled in wire order once it answers,
//! while the connection's own traffic goes on; a refusal ends the connection
//! for a redial; and a connection the server previews nothing on asks too,
//! unless the client has ended its drain by itself, which leaves what comes
//! later live.

use super::*;
use crate::client::ClientBuilder;
use crate::client::offline_resume::{Admission, OfflineBatchCoordinator};
use crate::request::IqError;
use crate::socket::NoiseSocket;
use crate::store::persistence_manager::PersistenceManager;
use crate::test_utils::{MockHttpClient, decrypt_wire_frames, poll_until};
use crate::transport::mock::{
    CapturingMockTransport, CapturingMockTransportFactory, MockTransportFactory,
};
use crate::transport::{Transport, TransportEvent};
use crate::types::events::{Event, EventHandler, EventInterest, EventKind, OfflineSyncPreview};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::time::Duration;
use wacore::handshake::NoiseCipher;
use wacore::net::DisconnectReason;
use wacore::store::in_memory::InMemoryBackend;
use wacore_binary::Node;
use wacore_binary::builder::NodeBuilder;

/// Bounds a wait whose end a regression would leave out.
const HANG: Duration = Duration::from_secs(10);

/// The id of the IQ [`Session::read_so_far`] sends, which no test looks for.
const PROBE: &str = "probe";

/// What the host saw, in order: its calls, and the events of the backlog.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Seen {
    /// The host was asked, with the announced total.
    Asked(Option<i32>),
    /// A raw node the client handled, by its id.
    Node(String),
    Preview(i32),
    Completed(i32),
    Connected,
    Disconnected(DisconnectReason),
}

/// The host: each call waits for the test's verdict.
struct Host {
    seen: Mutex<Vec<Seen>>,
    asked: async_channel::Sender<Option<OfflineSyncPreview>>,
    verdicts: async_channel::Receiver<anyhow::Result<()>>,
    dropped: AtomicUsize,
}

struct Control {
    host: Arc<Host>,
    asked: async_channel::Receiver<Option<OfflineSyncPreview>>,
    verdicts: async_channel::Sender<anyhow::Result<()>>,
}

impl Control {
    fn new() -> Self {
        let (asked_tx, asked) = async_channel::unbounded();
        let (verdicts, verdicts_rx) = async_channel::unbounded();
        Self {
            host: Arc::new(Host {
                seen: Mutex::default(),
                asked: asked_tx,
                verdicts: verdicts_rx,
                dropped: AtomicUsize::new(0),
            }),
            asked,
            verdicts,
        }
    }

    fn seen(&self) -> Vec<Seen> {
        self.host.seen.lock().unwrap().clone()
    }

    async fn asked(&self) -> Option<OfflineSyncPreview> {
        tokio::time::timeout(HANG, self.asked.recv())
            .await
            .expect("the host is asked")
            .expect("the host lives")
    }

    fn answer(&self, verdict: anyhow::Result<()>) {
        self.verdicts.try_send(verdict).expect("the host lives");
    }

    async fn sees(&self, what: &Seen) {
        poll_until("an event of the backlog", || self.seen().contains(what)).await;
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl OfflineAdmissionHook for Host {
    async fn on_offline_backlog(&self, preview: Option<&OfflineSyncPreview>) -> anyhow::Result<()> {
        self.seen
            .lock()
            .unwrap()
            .push(Seen::Asked(preview.map(|preview| preview.total)));
        let mut dropped = scopeguard::guard(false, |answered| {
            if !answered {
                self.dropped.fetch_add(1, Ordering::SeqCst);
            }
        });
        self.asked.send(preview.cloned()).await?;
        let verdict = self.verdicts.recv().await?;
        *dropped = true;
        verdict
    }
}

impl EventHandler for Host {
    fn handle_event(&self, event: Arc<Event>) {
        let seen = match &*event {
            Event::RawNode(node) => match node.get().get_attr("id") {
                Some(id) if id.as_str() != PROBE => Seen::Node(id.as_str().into_owned()),
                _ => return,
            },
            Event::OfflineSyncPreview(preview) => Seen::Preview(preview.total),
            Event::OfflineSyncCompleted(completed) => Seen::Completed(completed.count),
            Event::Connected(_) => Seen::Connected,
            Event::Disconnected(disconnected) => Seen::Disconnected(disconnected.reason.clone()),
            _ => return,
        };
        self.seen.lock().unwrap().push(seen);
    }

    fn interest(&self) -> EventInterest {
        EventInterest::of(&[
            EventKind::RawNode,
            EventKind::OfflineSyncPreview,
            EventKind::OfflineSyncCompleted,
            EventKind::Connected,
            EventKind::Disconnected,
        ])
    }
}

async fn builder() -> ClientBuilder {
    let persistence = PersistenceManager::new(Arc::new(InMemoryBackend::new()))
        .await
        .expect("persistence manager should initialize");
    Client::builder()
        .with_runtime(crate::runtime_impl::TokioRuntime)
        .with_persistence_manager(Arc::new(persistence))
        .with_transport_factory_arc(Arc::new(CapturingMockTransportFactory::new()))
        .with_http_client(MockHttpClient)
}

/// A client with `control`'s host on its bus, and installed where `hooked`.
async fn client(control: &Control, hooked: bool) -> Arc<Client> {
    let mut builder = builder().await;
    if hooked {
        builder = builder.with_offline_admission_hook_arc(control.host.clone());
    }
    let (client, _sync_tasks) = builder
        .build()
        .await
        .expect("test client should build")
        .into_parts();
    while !client.lid_pn_cache.startup_finished_for_tests() {
        tokio::task::yield_now().await;
    }
    client.subscribe_handler(control.host.clone()).detach();
    client
}

/// One connection of a client: its read loop over a transport the test feeds.
struct Session {
    client: Arc<Client>,
    transport: Arc<CapturingMockTransport>,
    events: async_channel::Sender<TransportEvent>,
    reader: tokio::task::JoinHandle<Option<DisconnectReason>>,
    fed: AtomicU32,
    _raw_nodes: crate::RawNodeLease,
}

impl Session {
    async fn connect(client: &Arc<Client>) -> Self {
        let transport = Arc::new(CapturingMockTransport::new());
        let cipher = || NoiseCipher::new(&[0u8; 32]).expect("32-byte key");
        let socket = NoiseSocket::new(
            client.runtime.clone(),
            transport.clone() as Arc<dyn Transport>,
            cipher(),
            cipher(),
        );
        *client.noise_socket.lock().unwrap() = Some(Arc::new(socket));
        let (events, receiver) = async_channel::bounded(2 * HELD_STANZAS);
        *client.transport_events.lock().await = Some(receiver);
        client.set_connected_for_test(true);
        client.set_driver_running_for_test(true, Ordering::Release);
        client.reset_connection_shutdown();
        let reader = tokio::spawn({
            let client = Arc::clone(client);
            async move { client.connection_for_test().read_until_disconnected().await }
        });
        Self {
            client: Arc::clone(client),
            transport,
            events,
            reader,
            fed: AtomicU32::new(0),
            _raw_nodes: client.acquire_raw_node_forwarding(),
        }
    }

    /// A connection that has logged in.
    async fn logged_in(client: &Arc<Client>) -> Self {
        let session = Self::connect(client).await;
        session.feed(&[NodeBuilder::new("success").build()]).await;
        poll_until("the login", || client.is_logged_in()).await;
        session
    }

    /// `nodes` in one transport read.
    async fn feed(&self, nodes: &[Node]) {
        let cipher = NoiseCipher::new(&[0u8; 32]).expect("32-byte key");
        let mut bytes = Vec::new();
        for node in nodes {
            let mut frame = wacore_binary::marshal::marshal(node).expect("marshal");
            cipher
                .encrypt_in_place_with_counter(self.fed.fetch_add(1, Ordering::SeqCst), &mut frame)
                .expect("encrypt");
            bytes.extend(wacore::framing::encode_frame(&frame, None).expect("frame"));
        }
        self.events
            .send(TransportEvent::DataReceived(bytes.into()))
            .await
            .expect("the reader reads");
    }

    /// Everything fed so far has been read: an IQ sent now is answered through
    /// the read loop, which answers IQs whatever waits for the host.
    async fn read_so_far(&self) {
        let before = self.sent("iq", None);
        let iq = tokio::spawn({
            let client = Arc::clone(&self.client);
            async move {
                let iq = NodeBuilder::new("iq").attr("type", "get").attr("id", PROBE);
                client.send_iq_node(iq.build(), Some(HANG)).await
            }
        });
        poll_until("the probe", || self.sent("iq", None) > before).await;
        poll_until("the probe's waiter", || {
            self.client.response_waiters_guard().contains_key(PROBE)
        })
        .await;
        self.feed(&[NodeBuilder::new("iq")
            .attr("from", "s.whatsapp.net")
            .attr("type", "result")
            .attr("id", PROBE)
            .build()])
            .await;
        let answered: Result<_, IqError> = tokio::time::timeout(HANG, iq)
            .await
            .expect("the read loop answers")
            .expect("probe task");
        answered.expect("the probe is answered");
    }

    /// How many `tag` stanzas the client wrote, those with a `child` if given.
    fn sent(&self, tag: &str, child: Option<&str>) -> usize {
        decrypt_wire_frames(&self.transport.sent(), &[0u8; 32])
            .into_iter()
            .filter(|frame| {
                let node = wacore_binary::util::unpack(frame).expect("unpack");
                let node = OwnedNodeRef::new(node.into_owned()).expect("decode");
                node.tag() == tag
                    && child.is_none_or(|child| node.get().get_optional_child(child).is_some())
            })
            .count()
    }

    fn batch_requests(&self) -> usize {
        self.sent("ib", Some("offline_batch"))
    }

    async fn ended(self) -> Option<DisconnectReason> {
        tokio::time::timeout(HANG, self.reader)
            .await
            .expect("the connection ends")
            .expect("the reader")
    }
}

fn preview(total: u32) -> Node {
    let counts = NodeBuilder::new("offline_preview")
        .attr("count", total)
        .attr("message", 3u32)
        .attr("receipt", 2u32)
        .attr("notification", 1u32)
        .attr("call", 4u32)
        .attr("status", 5u32)
        .attr("appdata", 6u32);
    NodeBuilder::new("ib")
        .attr("id", "preview")
        .children([counts.build()])
        .build()
}

fn end_marker(count: u32) -> Node {
    NodeBuilder::new("ib")
        .attr("id", "end")
        .children([NodeBuilder::new("offline").attr("count", count).build()])
        .build()
}

fn receipt(id: &str) -> NodeBuilder {
    NodeBuilder::new("receipt")
        .attr("id", id)
        .attr("from", "15550000001@s.whatsapp.net")
        .attr("t", "1700000000")
}

fn offline_receipt(id: &str) -> Node {
    receipt(id).attr("offline", "1").build()
}

#[tokio::test]
async fn the_backlog_waits_for_the_admission() {
    let control = Control::new();
    let client = client(&control, true).await;
    let session = Session::logged_in(&client).await;
    session
        .feed(&[
            preview(21),
            offline_receipt("offline-1"),
            receipt("live").build(),
            offline_receipt("offline-2"),
        ])
        .await;

    let announced = control.asked().await.expect("a preview");
    assert_eq!(
        (
            announced.total,
            announced.messages,
            announced.receipts,
            announced.notifications,
            announced.calls,
            announced.statuses,
            announced.app_data_changes,
        ),
        (21, 3, 2, 1, 4, 5, 6),
    );

    // The loop read all of it, and answers the client meanwhile.
    session.read_so_far().await;
    assert_eq!(control.seen(), [Seen::Asked(Some(21))]);
    assert_eq!(session.batch_requests(), 0, "no batch is asked for");
    assert_eq!(session.sent("ack", None), 0, "nothing is acknowledged");

    control.answer(Ok(()));
    control.sees(&Seen::Node("offline-2".into())).await;
    poll_until("the first batch request", || session.batch_requests() == 1).await;
    assert_eq!(
        control.seen(),
        [
            Seen::Asked(Some(21)),
            Seen::Node("preview".into()),
            Seen::Preview(21),
            Seen::Node("offline-1".into()),
            Seen::Node("live".into()),
            Seen::Node("offline-2".into()),
        ],
        "in wire order, after the host answered",
    );

    // What follows no longer waits.
    session.feed(&[end_marker(2)]).await;
    control.sees(&Seen::Completed(2)).await;
}

#[tokio::test]
async fn a_refusal_ends_the_connection() {
    let control = Control::new();
    let client = client(&control, true).await;
    let session = Session::logged_in(&client).await;
    session
        .feed(&[preview(2), offline_receipt("offline-1")])
        .await;
    control.asked().await;
    session.read_so_far().await;
    control.answer(Err(anyhow::anyhow!("the store is full")));

    let transport = session.transport.clone();
    assert_eq!(
        session.ended().await,
        Some(DisconnectReason::OfflineAdmissionRefused)
    );
    assert_eq!(
        control.seen(),
        [
            Seen::Asked(Some(2)),
            Seen::Disconnected(DisconnectReason::OfflineAdmissionRefused),
        ],
        "none of the backlog was handled",
    );
    let written = decrypt_wire_frames(&transport.sent(), &[0u8; 32]);
    assert!(
        !written.iter().any(|frame| frame
            .windows(b"offline_batch".len())
            .any(|window| window == b"offline_batch")),
        "no batch was asked for"
    );
    // The run loop redials from here as after any other disconnect.
    assert!(!client.is_socket_connected());
    assert!(!client.expected_session_disconnect(Ordering::Relaxed));
    assert!(client.auto_reconnect_enabled());
    assert!(!client.is_terminal());

    // The next connection asks again, and goes on with what it delivers.
    let session = Session::logged_in(&client).await;
    session.feed(&[preview(1)]).await;
    control.asked().await;
    control.answer(Ok(()));
    poll_until("the first batch request", || session.batch_requests() == 1).await;
}

#[test]
fn a_refusal_is_a_failure_of_the_hosts_own() {
    let reason = DisconnectReason::OfflineAdmissionRefused;
    assert!(!reason.is_clean_shutdown());
    assert_eq!(reason.to_string(), "offline backlog refused by the host");
    assert_eq!(
        serde_json::to_string(&reason).unwrap(),
        "\"offline_admission_refused\""
    );
}

#[tokio::test]
async fn a_connection_without_a_preview_still_asks() {
    // The server had nothing: the end marker comes alone.
    let control = Control::new();
    let hooked = client(&control, true).await;
    let session = Session::logged_in(&hooked).await;
    session.feed(&[end_marker(0)]).await;
    assert!(control.asked().await.is_none());
    session.read_so_far().await;
    assert_eq!(
        control.seen(),
        [Seen::Asked(None)],
        "the drain has not ended"
    );
    control.answer(Ok(()));
    control.sees(&Seen::Completed(0)).await;
    assert_eq!(session.batch_requests(), 0, "nothing was announced");

    // It had something it announced nothing of.
    let control = Control::new();
    let hooked = client(&control, true).await;
    let session = Session::logged_in(&hooked).await;
    session.feed(&[offline_receipt("unannounced")]).await;
    assert!(control.asked().await.is_none());
    session.read_so_far().await;
    assert_eq!(control.seen(), [Seen::Asked(None)], "it waits");
    control.answer(Ok(()));
    control.sees(&Seen::Node("unannounced".into())).await;
}

#[tokio::test]
async fn the_host_is_asked_once_per_connection() {
    let control = Control::new();
    let client = client(&control, true).await;
    for connection in 0..2 {
        let session = Session::logged_in(&client).await;
        session.feed(&[preview(1)]).await;
        control.asked().await;
        control.answer(Ok(()));
        session
            .feed(&[offline_receipt("later"), preview(2), end_marker(1)])
            .await;
        control.sees(&Seen::Preview(2)).await;
        poll_until("the drain's end", || {
            control.seen().contains(&Seen::Completed(1))
        })
        .await;
        let asked = control
            .seen()
            .iter()
            .filter(|seen| matches!(seen, Seen::Asked(_)))
            .count();
        assert_eq!(asked, 1, "connection {connection}");
        control.host.seen.lock().unwrap().clear();
        session
            .events
            .send(TransportEvent::Disconnected(DisconnectReason::StreamEnded))
            .await
            .expect("the reader reads");
        session.ended().await;
        control.host.seen.lock().unwrap().clear();
    }
}

#[tokio::test]
async fn a_connection_not_logged_in_asks_nothing() {
    let control = Control::new();
    let client = client(&control, true).await;
    let session = Session::connect(&client).await;
    session.feed(&[preview(1)]).await;
    control.sees(&Seen::Preview(1)).await;
    assert_eq!(
        control.seen(),
        [Seen::Node("preview".into()), Seen::Preview(1)]
    );
}

#[tokio::test]
async fn a_client_without_the_hook_asks_at_once() {
    let control = Control::new();
    let client = client(&control, false).await;
    let session = Session::logged_in(&client).await;
    session
        .feed(&[preview(1), offline_receipt("offline-1")])
        .await;
    poll_until("the first batch request", || session.batch_requests() == 1).await;
    control.sees(&Seen::Node("offline-1".into())).await;
    assert!(control.asked.is_empty());
}

/// The client completes a drain the server never ends by itself after a minute
/// of the server's silence. The time the host takes is not the server's: the
/// minute starts at its answer, however many the host took.
#[tokio::test(start_paused = true)]
async fn the_drain_limit_starts_after_the_admission() {
    let limit = Client::DEFAULT_OFFLINE_SYNC_TIMEOUT;
    drain_limit_after_an_answer(3 * limit + limit / 2).await;
}

/// The same with a host that answers at once, in the first second of the
/// minute: the minute still starts at the answer.
#[tokio::test(start_paused = true)]
async fn the_drain_limit_starts_after_an_answer_at_once() {
    drain_limit_after_an_answer(Duration::from_millis(500)).await;
}

/// A connection that previews nothing and stalls after the first stanza of
/// its backlog, whose host answers `taken` after it is asked: the drain stays
/// open for a minute after the answer, and then the client ends it. (Without a
/// preview the resume's inactivity watchdog is never armed, so the drain's
/// limit is all that ends it.)
async fn drain_limit_after_an_answer(taken: Duration) {
    let limit = Client::DEFAULT_OFFLINE_SYNC_TIMEOUT;
    // Paused timers due at the same instant fire in either order.
    let margin = Duration::from_secs(1);
    let control = Control::new();
    let client = client(&control, true).await;
    let session = Session::connect(&client).await;
    client.set_logged_in_for_test(true, Ordering::SeqCst);
    let drained = tokio::spawn({
        let client = Arc::clone(&client);
        async move { client.wait_for_offline_delivery_end().await }
    });
    tokio::task::yield_now().await;
    session.feed(&[offline_receipt("offline-1")]).await;
    assert!(control.asked().await.is_none());
    tokio::time::sleep(taken).await;
    assert!(
        !drained.is_finished(),
        "no limit runs while the host decides"
    );

    control.answer(Ok(()));
    tokio::time::sleep(limit - margin).await;
    assert!(
        !drained.is_finished(),
        "the minute runs from the answer, not from a window before it"
    );
    assert_eq!(
        control.seen(),
        [Seen::Asked(None), Seen::Node("offline-1".into())]
    );
    tokio::time::sleep(2 * margin).await;
    assert!(drained.is_finished(), "the minute after the answer ends it");
    drained.await.expect("the wait");
    assert!(
        control
            .seen()
            .iter()
            .any(|seen| matches!(seen, Seen::Completed(_))),
        "the client completes the drain by itself"
    );
}

/// A connection whose drain the client has ended by itself, after a minute in
/// which the server sent nothing of a backlog, asks the host nothing: a
/// backlog it announces later is handled as live, and nothing is held back.
#[tokio::test(start_paused = true)]
async fn a_backlog_after_the_clients_own_end_of_the_drain_is_live() {
    let control = Control::new();
    let client = client(&control, true).await;
    let session = Session::connect(&client).await;
    client.set_logged_in_for_test(true, Ordering::SeqCst);
    let drained = tokio::spawn({
        let client = Arc::clone(&client);
        async move { client.wait_for_offline_delivery_end().await }
    });
    tokio::time::timeout(
        Client::DEFAULT_OFFLINE_SYNC_TIMEOUT + Duration::from_secs(1),
        drained,
    )
    .await
    .expect("the client ends the drain by itself")
    .expect("the wait");
    poll_until("the drain's end", || {
        control
            .seen()
            .iter()
            .any(|seen| matches!(seen, Seen::Completed(_)))
    })
    .await;

    session.feed(&[preview(1), offline_receipt("late")]).await;
    control.sees(&Seen::Node("late".into())).await;
    control.sees(&Seen::Preview(1)).await;
    poll_until("the first batch request", || session.batch_requests() == 1).await;
    assert!(
        !control
            .seen()
            .iter()
            .any(|seen| matches!(seen, Seen::Asked(_))),
        "the host is not asked: {:?}",
        control.seen()
    );
    assert!(control.asked.is_empty());
}

/// The host's ask and the client's own end of a drain are moves of one word,
/// so whichever comes first excludes the other; and a connection's moves never
/// reach another connection's.
#[test]
fn the_ask_and_the_clients_own_end_exclude_each_other() {
    // The client ends the drain first: the host isn't asked.
    let admission = OfflineBatchCoordinator::new();
    assert_eq!(admission.admission(7), Some(Admission::Unasked));
    assert!(admission.close_admission(7, Admission::Unasked));
    assert!(!admission.ask_admission(7), "no host is asked after it");
    assert_eq!(admission.admission(7), Some(Admission::Closed));

    // The host is asked first: no window that began before can end the drain,
    // and none while the call is out.
    let admission = OfflineBatchCoordinator::new();
    assert!(admission.ask_admission(7));
    assert!(!admission.close_admission(7, Admission::Unasked));
    assert!(!admission.close_admission(7, Admission::Asked));
    assert!(!admission.ask_admission(7), "asked once per connection");
    admission.answer_admission(7);
    assert!(!admission.close_admission(7, Admission::Unasked));
    assert_eq!(admission.admission(7), Some(Admission::Answered));
    assert!(admission.close_admission(7, Admission::Answered));
    assert_eq!(admission.admission(7), Some(Admission::Closed));

    // What an older connection left is a newer one's `Unasked`, and the older
    // one's late moves (a gate dropped after its connection) change nothing.
    let admission = OfflineBatchCoordinator::new();
    assert!(admission.ask_admission(7));
    assert_eq!(admission.admission(9), Some(Admission::Unasked));
    assert!(admission.ask_admission(9));
    admission.answer_admission(7);
    assert!(!admission.close_admission(7, Admission::Unasked));
    assert_eq!(admission.admission(7), None);
    assert_eq!(admission.admission(9), Some(Admission::Asked));
}

/// What waits is bounded: past the bound the loop leaves the rest with the
/// transport, and reads on once the host has answered.
#[tokio::test]
async fn what_waits_for_the_host_is_bounded() {
    const BEYOND: usize = 10;
    let control = Control::new();
    let client = client(&control, true).await;
    let session = Session::logged_in(&client).await;
    session.feed(&[preview(1)]).await;
    control.asked().await;
    for index in 1..HELD_STANZAS + BEYOND {
        session
            .feed(&[receipt(&format!("live-{index}")).build()])
            .await;
    }
    poll_until("the loop to stop reading", || {
        session.events.len() == BEYOND
    })
    .await;
    for _ in 0..1_000 {
        tokio::task::yield_now().await;
    }
    assert_eq!(session.events.len(), BEYOND, "the loop reads no more");
    control.answer(Ok(()));
    let last = format!("live-{}", HELD_STANZAS + BEYOND - 1);
    control.sees(&Seen::Node(last)).await;
    let nodes = control
        .seen()
        .iter()
        .filter(|seen| matches!(seen, Seen::Node(_)))
        .count();
    assert_eq!(nodes, HELD_STANZAS + BEYOND, "all of it was handled");
}

#[tokio::test]
async fn what_waits_for_the_host_is_bounded_in_bytes() {
    let control = Control::new();
    let client = client(&control, true).await;
    let session = Session::logged_in(&client).await;
    session.feed(&[preview(1)]).await;
    control.asked().await;
    let large = |id: &str| receipt(id).bytes(vec![0x5a; HELD_BYTES / 2 + 1]).build();
    for id in ["large-1", "large-2", "left-1", "left-2"] {
        session.feed(&[large(id)]).await;
    }
    poll_until("the loop to stop reading", || session.events.len() == 2).await;
    for _ in 0..1_000 {
        tokio::task::yield_now().await;
    }
    assert_eq!(session.events.len(), 2, "the loop reads no more");
    control.answer(Ok(()));
    control.sees(&Seen::Node("left-2".into())).await;
}

/// The bounds are checked between the transport's reads: the read that
/// crosses one is held whole, and the loop reads nothing after it.
#[tokio::test]
async fn the_read_that_crosses_the_bound_is_held_whole() {
    const BEYOND: usize = 10;
    let control = Control::new();
    let client = client(&control, true).await;
    let session = Session::logged_in(&client).await;
    session.feed(&[preview(1)]).await;
    control.asked().await;
    let crossing: Vec<Node> = (1..HELD_STANZAS + BEYOND)
        .map(|index| receipt(&format!("live-{index}")).build())
        .collect();
    session.feed(&crossing).await;
    session.feed(&[receipt("after").build()]).await;
    poll_until("the loop to read the crossing read", || {
        session.events.len() == 1
    })
    .await;
    for _ in 0..1_000 {
        tokio::task::yield_now().await;
    }
    assert_eq!(session.events.len(), 1, "the loop reads no more");
    assert_eq!(
        control.seen(),
        [Seen::Asked(Some(1))],
        "every stanza of the read waits"
    );
    control.answer(Ok(()));
    control.sees(&Seen::Node("after".into())).await;
    let nodes = control
        .seen()
        .iter()
        .filter(|seen| matches!(seen, Seen::Node(_)))
        .count();
    assert_eq!(nodes, HELD_STANZAS + BEYOND + 1, "all of it was handled");
}

/// The connection's end doesn't wait for the host: its call is dropped, and
/// nothing that waited for it is handled.
#[tokio::test]
async fn a_connection_that_ends_drops_the_call() {
    let control = Control::new();
    let client = client(&control, true).await;
    let session = Session::logged_in(&client).await;
    session
        .feed(&[preview(1), offline_receipt("offline-1")])
        .await;
    control.asked().await;
    let generation = client.connection_generation.load(Ordering::Acquire);
    assert_eq!(
        client.offline_batch.admission(generation),
        Some(Admission::Asked)
    );
    session
        .events
        .send(TransportEvent::Disconnected(DisconnectReason::StreamEnded))
        .await
        .expect("the reader reads");
    assert_eq!(session.ended().await, Some(DisconnectReason::StreamEnded));
    assert_eq!(control.host.dropped.load(Ordering::SeqCst), 1);
    assert_eq!(
        client.offline_batch.admission(generation),
        Some(Admission::Answered),
        "a dropped call is an answer: a wait of its connection may end"
    );

    let session = Session::logged_in(&client).await;
    session.feed(&[preview(1)]).await;
    control.asked().await;
    let generation = client.connection_generation.load(Ordering::Acquire);
    let _report = tokio::time::timeout(HANG, client.shutdown())
        .await
        .expect("a shutdown does not wait for the host");
    session.ended().await;
    assert_eq!(control.host.dropped.load(Ordering::SeqCst), 2);
    assert_eq!(
        client.offline_batch.admission(generation),
        Some(Admission::Answered)
    );
    assert!(
        !control
            .seen()
            .iter()
            .any(|seen| matches!(seen, Seen::Node(_) | Seen::Preview(_))),
        "nothing of either backlog was handled"
    );
}

#[tokio::test]
async fn the_last_registered_hook_is_asked() {
    let first = Control::new();
    let last = Control::new();
    let (client, _sync_tasks) = Client::builder()
        .with_runtime(crate::runtime_impl::TokioRuntime)
        .with_persistence_manager(Arc::new(
            PersistenceManager::new(Arc::new(InMemoryBackend::new()))
                .await
                .expect("persistence manager should initialize"),
        ))
        .with_transport_factory(MockTransportFactory::new())
        .with_http_client(MockHttpClient)
        .with_offline_admission_hook_arc(first.host.clone())
        .with_offline_admission_hook_arc(last.host.clone())
        .build()
        .await
        .expect("test client should build")
        .into_parts();
    let session = Session::logged_in(&client).await;
    session.feed(&[preview(1)]).await;
    last.asked().await;
    assert!(first.asked.is_empty());
}
