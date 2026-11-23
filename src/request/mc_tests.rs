//! WF15: an IQ the server answers as it ends the connection is answered.
//!
//! The server can answer a request and end the stream in one flight; for the
//! `remove-companion-device` a logout sends it always does. The read loop
//! resolves the waiter before it reads the frame that ends the stream, and the
//! wait takes an answer it was handed over the connection's end, whichever kind
//! of request waits (a raw IQ, a typed one, a streamed one) and whatever ended
//! the connection. A request nothing answered still ends with it, as
//! `NotConnected`, whether or not the connection's cleanup has dropped its
//! waiter yet (one dropped while the connection lives is the client's own
//! fault, `InternalChannelClosed`). An answer's waiter runs with the waiter
//! map unlocked.

use super::*;
use crate::client::{DeregistrationOutcome, LogoutReport};
use crate::store::commands::DeviceCommand;
use crate::test_utils::{TestEventCollector, answer_iq, create_iq_test_client, decode_sent_iq};
use crate::transport::TransportEvent;
use crate::transport::mock::CapturingMockTransport;
use crate::types::events::Event;
use wacore::handshake::NoiseCipher;
use wacore::iq::devices::RemoveCompanionDeviceSpec;
use wacore::iq::props::PropsSpec;
use wacore::net::DisconnectReason;
use wacore_binary::Jid;
use wacore_binary::builder::NodeBuilder;

/// Bounds a wait whose end a regression would leave out.
const HANG: Duration = Duration::from_secs(10);

/// The three ways a request reaches the shared wait.
#[derive(Debug, Clone, Copy)]
enum Request {
    Raw,
    Typed,
    Streamed,
}

impl Request {
    const ALL: [Self; 3] = [Self::Raw, Self::Typed, Self::Streamed];

    async fn send(self, client: &Client) -> Result<(), IqError> {
        match self {
            Self::Raw => {
                let iq = NodeBuilder::new(IQ_TAG)
                    .attr("type", "get")
                    .attr("xmlns", "w:test")
                    .build();
                client.send_iq_node(iq, None).await.map(drop)
            }
            Self::Typed => {
                let companion = Jid::pn("15550000001").with_device(7);
                client
                    .execute(RemoveCompanionDeviceSpec::new(&companion))
                    .await
            }
            Self::Streamed => client.execute_streaming(PropsSpec::new()).await.map(drop),
        }
    }

    fn spawn(self, client: &Arc<Client>) -> tokio::task::JoinHandle<Result<(), IqError>> {
        let client = Arc::clone(client);
        tokio::spawn(async move { self.send(&client).await })
    }
}

/// What the server answers: both are answers.
#[derive(Debug, Clone, Copy)]
enum Answer {
    Granted,
    Refused,
}

impl Answer {
    fn node(self, id: &str) -> Node {
        let iq = NodeBuilder::new(IQ_TAG)
            .attr("from", "s.whatsapp.net")
            .attr(IQ_ID_ATTR, id);
        match self {
            Self::Granted => iq
                .attr("type", "result")
                .children([NodeBuilder::new("props")
                    .attr("protocol", "1")
                    .attr("hash", "h")
                    .build()]),
            Self::Refused => iq.attr("type", "error").children([NodeBuilder::new("error")
                .attr("code", "403")
                .attr("text", "forbidden")
                .build()]),
        }
        .build()
    }

    fn is(self, result: &Result<(), IqError>) -> bool {
        match self {
            Self::Granted => result.is_ok(),
            Self::Refused => matches!(result, Err(IqError::ServerError { code: 403, .. })),
        }
    }
}

/// What ends the connection right behind the answer.
#[derive(Debug, Clone, Copy)]
enum End {
    DeviceRemoved,
    Unauthorized,
    Restart,
    /// `<xmlstreamend/>`.
    StreamEnded,
    /// The transport's own end, behind the frames it delivered.
    Closed,
}

impl End {
    const ALL: [Self; 5] = [
        Self::DeviceRemoved,
        Self::Unauthorized,
        Self::Restart,
        Self::StreamEnded,
        Self::Closed,
    ];

    fn stanza(self) -> Option<Node> {
        let error = NodeBuilder::new("stream:error");
        Some(match self {
            Self::DeviceRemoved => error
                .children([NodeBuilder::new("conflict")
                    .attr("type", "device_removed")
                    .build()])
                .build(),
            Self::Unauthorized => error.attr("code", "401").build(),
            Self::Restart => error.attr("code", "515").build(),
            Self::StreamEnded => NodeBuilder::new("xmlstreamend").build(),
            Self::Closed => return None,
        })
    }
}

/// The id of the request the client wrote as its frame `index`.
async fn sent_id(transport: &Arc<CapturingMockTransport>, index: usize) -> String {
    decode_sent_iq(transport, index)
        .await
        .attrs()
        .optional_string(IQ_ID_ATTR)
        .expect("the request carries an id")
        .into_owned()
}

/// `nodes` as the bytes of one transport read, under the test socket's key and
/// the read counters of a connection's first frames.
fn flight(nodes: &[Node]) -> bytes::Bytes {
    let cipher = NoiseCipher::new(&[0u8; 32]).expect("32-byte key");
    let mut bytes = Vec::new();
    for (counter, node) in (0u32..).zip(nodes) {
        let mut frame = wacore_binary::marshal::marshal(node).expect("marshal");
        cipher
            .encrypt_in_place_with_counter(counter, &mut frame)
            .expect("encrypt");
        bytes.extend(wacore::framing::encode_frame(&frame, None).expect("frame"));
    }
    bytes.into()
}

/// A client whose read loop runs over a transport the test feeds.
struct Read {
    client: Arc<Client>,
    transport: Arc<CapturingMockTransport>,
    events: async_channel::Sender<TransportEvent>,
    reader: tokio::task::JoinHandle<()>,
}

impl Read {
    async fn new() -> Self {
        let (client, transport) = create_iq_test_client().await;
        let (events, receiver) = async_channel::bounded(4);
        *client.transport_events.lock().await = Some(receiver);
        let reader = tokio::spawn({
            let client = Arc::clone(&client);
            async move {
                client.connection_for_test().read_until_disconnected().await;
            }
        });
        Self {
            client,
            transport,
            events,
            reader,
        }
    }

    /// Delivers `answer`, and in the same read what ends the connection.
    async fn deliver(&self, answer: Node, end: End) {
        let mut nodes = vec![answer];
        nodes.extend(end.stanza());
        let mut events = vec![TransportEvent::DataReceived(flight(&nodes))];
        if matches!(end, End::Closed) {
            events.push(TransportEvent::Disconnected(DisconnectReason::StreamEnded));
        }
        for event in events {
            self.events.send(event).await.expect("the reader reads");
        }
    }

    async fn ended(self) {
        tokio::time::timeout(HANG, self.reader)
            .await
            .expect("the connection ended")
            .expect("the reader");
    }
}

/// The answer is with the waiter and the connection has ended by the time the
/// request is polled again. An unbiased race loses the answer every other time,
/// so each kind runs the race often enough to lose it.
#[tokio::test]
async fn an_answer_delivered_before_the_connection_ended_is_the_answer() {
    const ROUNDS: usize = 32;
    for request in Request::ALL {
        let (client, transport) = create_iq_test_client().await;
        for round in 0..ROUNDS {
            let pending = request.spawn(&client);
            let id = sent_id(&transport, round).await;
            // Nothing yields between the two, so the request sees both at once.
            answer_iq(&client, &id, &Answer::Granted.node(&id)).await;
            client.notify_connection_shutdown();
            let result = pending.await.expect("request task");
            assert!(result.is_ok(), "{request:?}, round {round}: {result:?}");
            client.reset_connection_shutdown();
        }
    }
}

/// The answer and the stanza that ends the stream arrive in one read; the
/// request gets its answer, a refusal included, whatever ended the connection.
#[tokio::test]
async fn an_answer_in_the_flight_that_ends_the_stream_is_the_answer() {
    for request in Request::ALL {
        for answer in [Answer::Granted, Answer::Refused] {
            for end in End::ALL {
                let read = Read::new().await;
                let pending = request.spawn(&read.client);
                let id = sent_id(&read.transport, 0).await;
                read.deliver(answer.node(&id), end).await;
                let result = pending.await.expect("request task");
                assert!(
                    answer.is(&result),
                    "{request:?}, {answer:?} before {end:?}: {result:?}"
                );
                read.ended().await;
            }
        }
    }
}

/// An observer of raw nodes, which makes the read loop decode a streamed answer
/// whole, changes nothing: it sees the answer, and the request gets it.
#[tokio::test]
async fn an_observed_answer_in_the_flight_that_ends_the_stream_is_the_answer() {
    for request in Request::ALL {
        let read = Read::new().await;
        let observer = Arc::new(TestEventCollector::default());
        read.client.subscribe_handler(observer.clone()).detach();
        let _lease = read.client.acquire_raw_node_forwarding();
        let pending = request.spawn(&read.client);
        let id = sent_id(&read.transport, 0).await;
        read.deliver(Answer::Granted.node(&id), End::DeviceRemoved)
            .await;
        let result = pending.await.expect("request task");
        assert!(result.is_ok(), "{request:?}: {result:?}");
        assert!(
            observer
                .events()
                .iter()
                .any(|event| matches!(&**event, Event::RawNode(node) if node.tag() == IQ_TAG)),
            "{request:?}: the observer sees the answer"
        );
        read.ended().await;
    }
}

/// What a logout meets on WhatsApp: the device's removal is answered, and the
/// stream ends with `device_removed` in the same flight.
#[tokio::test]
async fn a_logout_answered_as_the_stream_ends_is_confirmed() {
    let read = Read::new().await;
    let companion = Jid::pn("15550000001").with_device(7);
    read.client
        .persistence_manager
        .process_command(DeviceCommand::SetId(Some(companion)))
        .await;
    let logout = tokio::spawn({
        let client = Arc::clone(&read.client);
        async move { client.logout().await }
    });
    let request = decode_sent_iq(&read.transport, 0).await;
    assert!(
        request
            .get()
            .get_optional_child("remove-companion-device")
            .is_some()
    );
    let id = sent_id(&read.transport, 0).await;
    read.deliver(Answer::Granted.node(&id), End::DeviceRemoved)
        .await;
    let LogoutReport { deregistration, .. } = tokio::time::timeout(HANG, logout)
        .await
        .expect("the logout ends")
        .expect("logout task");
    assert!(
        matches!(deregistration, DeregistrationOutcome::Confirmed),
        "{deregistration:?}"
    );
    read.ended().await;
}

/// How much of a connection's end a request nothing answered sees when it is
/// next polled.
#[derive(Debug, Clone, Copy)]
enum Teardown {
    /// The connection's signal.
    Signal,
    /// The signal, and the connection's cleanup dropping every waiter behind it
    /// (`cleanup_connection_state`'s order), so its exchange has ended too.
    SignalAndCleanup,
}

/// A request nothing answered ends with its connection, at once, as
/// `NotConnected`, whichever of the two the biased wait takes. Every kind and
/// teardown runs before the verdict, which names each that read otherwise.
#[tokio::test]
async fn a_request_unanswered_when_the_connection_ends_is_not_connected() {
    let mut otherwise = Vec::new();
    for request in Request::ALL {
        for teardown in [Teardown::Signal, Teardown::SignalAndCleanup] {
            let (client, transport) = create_iq_test_client().await;
            let pending = request.spawn(&client);
            sent_id(&transport, 0).await;
            client.notify_connection_shutdown();
            if let Teardown::SignalAndCleanup = teardown {
                // Nothing yields between the two, so the request sees both.
                client.response_waiters_guard().clear();
            }
            let result = tokio::time::timeout(HANG, pending)
                .await
                .expect("the request ends with its connection")
                .expect("request task");
            if !matches!(result, Err(IqError::NotConnected)) {
                otherwise.push(format!("{request:?}, {teardown:?}: {result:?}"));
            }
            assert!(client.response_waiters_guard().is_empty());
        }
    }
    assert!(otherwise.is_empty(), "{otherwise:#?}");
}

/// A waiter dropped while its connection lives is no end of the connection but
/// a fault of the client's own, and reads as one.
#[tokio::test]
async fn a_waiter_dropped_while_the_connection_lives_is_internal() {
    let mut otherwise = Vec::new();
    for request in Request::ALL {
        let (client, transport) = create_iq_test_client().await;
        let pending = request.spawn(&client);
        sent_id(&transport, 0).await;
        client.response_waiters_guard().clear();
        let result = tokio::time::timeout(HANG, pending)
            .await
            .expect("the request ends with its waiter")
            .expect("request task");
        if !matches!(result, Err(IqError::InternalChannelClosed)) {
            otherwise.push(format!("{request:?}: {result:?}"));
        }
    }
    assert!(otherwise.is_empty(), "{otherwise:#?}");
}

/// An answer's waiter runs with the waiter map unlocked: a streamed request's
/// sink, which decodes the whole stanza where the answer is read, holds up no
/// other request's registration or answer.
#[tokio::test]
async fn an_answers_waiter_runs_with_the_waiter_map_unlocked() {
    const ID: &str = "lock-probe";
    let (client, _transport) = create_iq_test_client().await;
    let (unlocked, seen) = std::sync::mpsc::channel();
    let waiters = Arc::clone(&client.response_waiters);
    let sink: StreamSink = Box::new(move |_| {
        unlocked
            .send(waiters.try_lock().is_ok())
            .expect("the test listens");
    });
    client
        .response_waiters_guard()
        .try_insert_guarded(ID.to_string(), ResponseWaiter::Stream(sink))
        .expect("a fresh id");
    client
        .process_node(crate::test_utils::node_to_owned_ref(
            &Answer::Refused.node(ID),
        ))
        .await;
    assert!(
        seen.try_recv().expect("the answer reached its waiter"),
        "the waiter ran with the map locked"
    );
}
