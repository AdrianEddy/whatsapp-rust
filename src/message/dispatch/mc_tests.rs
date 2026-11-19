//! WF1: newsletter deliveries ack only after the inbound durability hook has
//! committed them.
//!
//! Stanzas enter where the read loop hands them over, `Client::process_node`
//! (the entry `bench_support::process_stanza` wraps), and run through the real
//! `should_ack` gate, chat lane and newsletter handler. The transport captures
//! what reaches the wire and the client's own frame tap reports it. Every wait
//! is on an event: a hook call, a published batch or a sent frame.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};

use crate::client::Client;
use crate::client::interceptor::{Interception, StanzaInterceptor};
use crate::transport::mock::{CapturingMockTransport, CapturingMockTransportFactory};
use crate::types::durability_hook::{InboundDurabilityHook, InboundMessage};
use wacore::proto_helpers::MessageBuilderExt as _;
use wacore::store::commands::DeviceCommand;
use wacore::types::events::{
    Event, EventHandler, EventInterest, EventKind, MessageBatch, Subscription,
};
use wacore_binary::builder::NodeBuilder;
use wacore_binary::{Jid, JidExt as _, Node, OwnedNodeRef};
use waproto::whatsapp as wa;

const NEWSLETTER: &str = "120363298765432100@newsletter";

/// The local device, which every message ack names as its `from`.
fn own_device() -> Jid {
    Jid::pn_device("15550000001", 3)
}

/// What the hook does with one call, in call order.
enum Step {
    Commit,
    /// Commit once the test releases it, holding the delivery mid-commit.
    CommitWhenReleased,
    Fail,
}

/// Reports each call's message ids, then does what the script says. A call
/// the test did not script fails, so it is reported and visible, never hidden.
struct ScriptedHook {
    steps: Mutex<VecDeque<Step>>,
    calls: async_channel::Sender<Vec<String>>,
    release: async_channel::Receiver<()>,
}

#[async_trait::async_trait]
impl InboundDurabilityHook for ScriptedHook {
    async fn on_messages(
        &self,
        _client: Arc<Client>,
        batch: &[InboundMessage],
    ) -> anyhow::Result<()> {
        let step = self.steps.lock().expect("script lock").pop_front();
        self.calls
            .try_send(batch.iter().map(|item| item.info.id.to_string()).collect())
            .expect("the test holds the call receiver");
        match step {
            Some(Step::Commit) => Ok(()),
            Some(Step::CommitWhenReleased) => {
                self.release
                    .recv()
                    .await
                    .expect("the test releases the held commit");
                Ok(())
            }
            Some(Step::Fail) => Err(anyhow::anyhow!("the store refused the commit")),
            None => Err(anyhow::anyhow!("a hook call the test did not script")),
        }
    }
}

/// The hook, the receiver of its calls and the sender that releases a held
/// commit.
fn scripted<const N: usize>(
    steps: [Step; N],
) -> (
    Arc<dyn InboundDurabilityHook>,
    async_channel::Receiver<Vec<String>>,
    async_channel::Sender<()>,
) {
    let (calls_tx, calls) = async_channel::unbounded();
    let (release, release_rx) = async_channel::unbounded();
    let hook = Arc::new(ScriptedHook {
        steps: Mutex::new(VecDeque::from(steps)),
        calls: calls_tx,
        release: release_rx,
    });
    (hook, calls, release)
}

/// Forwards the dispatched events of one kind to the test.
struct Forward {
    kind: [EventKind; 1],
    events: async_channel::Sender<Arc<Event>>,
}

impl EventHandler for Forward {
    fn handle_event(&self, event: Arc<Event>) {
        let _ = self.events.try_send(event);
    }

    fn interest(&self) -> EventInterest {
        EventInterest::of(&self.kind)
    }
}

/// A connected, logged-in client over a capturing transport, with its
/// published batches and sent frames forwarded as events.
struct Fixture {
    client: Arc<Client>,
    transport: Arc<CapturingMockTransport>,
    batches: async_channel::Receiver<Arc<Event>>,
    frames: async_channel::Receiver<Arc<Event>>,
    _subscriptions: [Subscription; 2],
    _frame_forwarding: crate::SentFrameLease,
}

async fn fixture(hook: Option<Arc<dyn InboundDurabilityHook>>) -> Fixture {
    use crate::store::persistence_manager::PersistenceManager;
    use wacore::handshake::NoiseCipher;

    let persistence = Arc::new(
        PersistenceManager::new(crate::test_utils::create_test_backend().await)
            .await
            .expect("persistence manager"),
    );
    let factory = CapturingMockTransportFactory::new();
    let transport = factory.transport();
    let mut builder = Client::builder()
        .with_runtime_arc(Arc::new(crate::runtime_impl::TokioRuntime))
        .with_persistence_manager(persistence)
        .with_transport_factory_arc(Arc::new(factory))
        .with_http_client_arc(Arc::new(crate::test_utils::MockHttpClient));
    if let Some(hook) = hook {
        builder = builder.with_inbound_durability_hook_arc(hook);
    }
    let (client, _sync_tasks) = builder.build().await.expect("client builds").into_parts();

    // Wired to the client's observers as the real socket is, so every frame
    // that reaches the transport is also an `Event::SentFrame`.
    let socket = crate::socket::NoiseSocket::with_observers(
        client.runtime.clone(),
        transport.clone() as Arc<dyn crate::transport::Transport>,
        NoiseCipher::new(&[0u8; 32]).expect("32-byte key"),
        NoiseCipher::new(&[0u8; 32]).expect("32-byte key"),
        crate::socket::noise_socket::SendObservers::with_stats(client.stats.clone())
            .with_sent_frames(client.sent_frame_tap.clone()),
    );
    *client.noise_socket.lock().expect("socket slot") = Some(Arc::new(socket));
    client.set_connected_for_test(true);
    client.set_driver_running_for_test(true, std::sync::atomic::Ordering::Release);
    client.enter_live_mode_for_tests();
    client
        .persistence_manager
        .process_command(DeviceCommand::SetId(Some(own_device())))
        .await;

    let (batches_tx, batches) = async_channel::unbounded();
    let (frames_tx, frames) = async_channel::unbounded();
    let subscriptions = [
        client.subscribe_handler(Arc::new(Forward {
            kind: [EventKind::Messages],
            events: batches_tx,
        })),
        client.subscribe_handler(Arc::new(Forward {
            kind: [EventKind::SentFrame],
            events: frames_tx,
        })),
    ];
    let frame_forwarding = client.acquire_sent_frame_forwarding();
    Fixture {
        client,
        transport,
        batches,
        frames,
        _subscriptions: subscriptions,
        _frame_forwarding: frame_forwarding,
    }
}

impl Fixture {
    async fn deliver(&self, stanza: Arc<OwnedNodeRef>) {
        self.client.process_node(stanza).await;
    }

    async fn next_batch(&self) -> MessageBatch {
        let event = self.batches.recv().await.expect("the bus stays subscribed");
        let Event::Messages(batch) = &*event else {
            panic!("only message batches are forwarded here");
        };
        batch.clone()
    }

    /// The next frame that reached the transport, as its tag and attributes.
    async fn next_frame(&self) -> (String, BTreeMap<String, String>) {
        let event = self.frames.recv().await.expect("the bus stays subscribed");
        let Event::SentFrame(sent) = &*event else {
            panic!("only sent frames are forwarded here");
        };
        let node = wacore_binary::marshal::unmarshal_packed_ref(&sent.plaintext)
            .expect("a sent frame decodes");
        let attrs = node
            .attrs
            .iter()
            .map(|(key, value)| (key.as_ref().to_owned(), value.to_string()))
            .collect();
        (node.tag.as_ref().to_owned(), attrs)
    }

    /// Nothing reached the transport, nothing is on its way there and nothing
    /// was published. Sound at any instant: an ack holds an outbound-flush
    /// guard from before it is queued until after the transport took its frame.
    fn assert_quiet(&self, when: &str) {
        assert_eq!(
            self.transport.sent_count(),
            0,
            "no frame may reach the wire {when}"
        );
        assert_eq!(
            self.client.outbound_flush.pending(),
            0,
            "no ack may be on its way {when}"
        );
        assert!(self.batches.is_empty(), "nothing may be published {when}");
    }
}

/// A channel post as the server delivers it: plaintext, no `<enc>`.
fn newsletter_post(id: &str, server_id: u32, text: &str) -> Arc<OwnedNodeRef> {
    crate::test_utils::node_to_owned_ref(&newsletter_post_builder(id, server_id, text).build())
}

/// [`newsletter_post`] before it is built, for a test to add attributes.
fn newsletter_post_builder(id: &str, server_id: u32, text: &str) -> NodeBuilder {
    NodeBuilder::new("message")
        .attr("from", NEWSLETTER)
        .attr("id", id)
        .attr("server_id", server_id.to_string())
        .attr("t", "1700000000")
        .attr("type", "text")
        .children([plaintext(text)])
}

/// A post's `<plaintext>` child: the encoded text message.
fn plaintext(text: &str) -> Node {
    NodeBuilder::new("plaintext")
        .bytes(waproto::codec::message_to_vec(&wa::Message::text(text)))
        .build()
}

/// The ack the `should_ack` gate sends for [`newsletter_post`], attribute for
/// attribute: the post-commit ack must be the same stanza.
fn newsletter_ack(id: &str) -> (String, BTreeMap<String, String>) {
    let attrs = [
        ("class", "message".to_owned()),
        ("from", own_device().to_string()),
        ("id", id.to_owned()),
        ("to", NEWSLETTER.to_owned()),
        ("type", "text".to_owned()),
    ];
    (
        "ack".to_owned(),
        attrs
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}

fn ids(batch: &MessageBatch) -> Vec<String> {
    batch.iter().map(|item| item.info.id.to_string()).collect()
}

async fn next_call(calls: &async_channel::Receiver<Vec<String>>) -> Vec<String> {
    calls.recv().await.expect("the hook stays registered")
}

/// With a hook the gate no longer acks a post up front: while the hook is
/// committing, nothing has reached the wire or is on its way there. Once it
/// commits, the post's ack (the gate's own stanza) goes out and the batch is
/// published as committed.
#[tokio::test]
async fn newsletter_ack_waits_for_hook() {
    let (hook, calls, release) = scripted([Step::CommitWhenReleased]);
    let f = fixture(Some(hook)).await;

    f.deliver(newsletter_post("NL-WAIT-1", 101, "first post"))
        .await;
    assert_eq!(next_call(&calls).await, ["NL-WAIT-1"]);
    f.assert_quiet("while the hook commits");

    release.send(()).await.expect("the hook holds the commit");
    let batch = f.next_batch().await;
    assert_eq!(ids(&batch), ["NL-WAIT-1"]);
    assert!(batch.hook_committed, "the hook committed this batch");
    assert_eq!(
        batch.messages[0].message.conversation.as_deref(),
        Some("first post")
    );
    assert_eq!(f.next_frame().await, newsletter_ack("NL-WAIT-1"));
}

/// A hook error withholds the post's ack and its batch. The next post of the
/// channel shares its lane, so its hook call proves the refused post was
/// handled to the end with nothing sent; the redelivery the hook then accepts
/// is acked and published as usual.
#[tokio::test]
async fn newsletter_hook_error_withholds_ack() {
    let (hook, calls, release) = scripted([Step::Fail, Step::CommitWhenReleased, Step::Commit]);
    let f = fixture(Some(hook)).await;

    f.deliver(newsletter_post("NL-FAIL-1", 201, "refused"))
        .await;
    f.deliver(newsletter_post("NL-FAIL-2", 202, "accepted"))
        .await;
    assert_eq!(next_call(&calls).await, ["NL-FAIL-1"]);
    assert_eq!(next_call(&calls).await, ["NL-FAIL-2"]);
    f.assert_quiet("after the hook refused the first post");

    release.send(()).await.expect("the hook holds the commit");
    let batch = f.next_batch().await;
    assert_eq!(ids(&batch), ["NL-FAIL-2"]);
    assert!(batch.hook_committed);
    assert_eq!(f.next_frame().await, newsletter_ack("NL-FAIL-2"));

    // The server sends the refused post again; this time the hook commits it.
    f.deliver(newsletter_post("NL-FAIL-1", 201, "refused"))
        .await;
    assert_eq!(next_call(&calls).await, ["NL-FAIL-1"]);
    let batch = f.next_batch().await;
    assert_eq!(ids(&batch), ["NL-FAIL-1"]);
    assert!(batch.hook_committed);
    assert_eq!(f.next_frame().await, newsletter_ack("NL-FAIL-1"));
    // Each post counts once, when it is published; the refused delivery
    // counts nothing.
    assert_eq!(f.client.stats().messages_received, 2);
}

/// Without a hook nothing changes: the gate has the ack on its way by the time
/// the dispatcher returns, whatever the lane that parses the post has done, and
/// the batch is published as not committed by any hook.
#[tokio::test]
async fn newsletter_without_hook_unchanged() {
    let f = fixture(None).await;

    f.deliver(newsletter_post("NL-PLAIN-1", 301, "post")).await;
    assert!(
        f.transport.sent_count() + f.client.outbound_flush.pending() > 0,
        "the gate queues the ack inside the dispatcher"
    );

    let batch = f.next_batch().await;
    assert_eq!(ids(&batch), ["NL-PLAIN-1"]);
    assert!(!batch.hook_committed, "no hook is registered");
    assert_eq!(
        batch.messages[0].message.conversation.as_deref(),
        Some("post")
    );
    assert_eq!(f.next_frame().await, newsletter_ack("NL-PLAIN-1"));
}

/// A post with nothing to publish keeps the gate's ack under a hook, from the
/// newsletter handler: a redelivery would decode no better.
#[tokio::test]
async fn undecodable_newsletter_acked_with_hook() {
    let (hook, calls, _release) = scripted([]);
    let f = fixture(Some(hook)).await;

    let no_plaintext = NodeBuilder::new("message")
        .attr("from", NEWSLETTER)
        .attr("id", "NL-BAD-1")
        .attr("server_id", "401")
        .attr("t", "1700000000")
        .attr("type", "text")
        .build();
    f.deliver(crate::test_utils::node_to_owned_ref(&no_plaintext))
        .await;
    assert_eq!(f.next_frame().await, newsletter_ack("NL-BAD-1"));
    assert!(calls.is_empty(), "nothing reached the hook");
    assert!(f.batches.is_empty(), "nothing was published");
}

/// An interceptor's claim still answers a post whose ack would have waited for
/// the hook: a claimed stanza keeps the transport ack it is owed
/// (`Interception::Handled`), and the claim takes it past the commit.
#[tokio::test]
async fn claimed_newsletter_acked_with_hook() {
    let (hook, calls, _release) = scripted([]);
    let f = fixture(Some(hook)).await;
    let claim: Arc<dyn StanzaInterceptor> = Arc::new(|node: &OwnedNodeRef| {
        if node.tag() == "message" {
            Interception::Handled
        } else {
            Interception::Pass
        }
    });
    let _claim = f.client.add_stanza_interceptor(claim);

    f.deliver(newsletter_post("NL-CLAIM-1", 501, "claimed"))
        .await;
    assert_eq!(f.next_frame().await, newsletter_ack("NL-CLAIM-1"));
    assert!(calls.is_empty(), "a claimed stanza never reaches the hook");
}

/// A status keeps the gate's ack with a hook registered: the lane's drop paths
/// (an expired status, a missing sender key, a duplicate) send nothing of
/// their own, so the gate's ack is the only answer such a status gets.
#[tokio::test]
async fn status_broadcast_acked_by_gate_with_hook() {
    let (hook, _calls, _release) = scripted([]);
    let f = fixture(Some(hook)).await;

    // Nothing to decrypt: the lane drops it and sends nothing, so whatever
    // reaches the wire for it is the gate's.
    let status = NodeBuilder::new("message")
        .attr("from", "status@broadcast")
        .attr("id", "ST-GATE-1")
        .attr("participant", "100000000000001@lid")
        .attr("t", "1700000000")
        .attr("type", "text")
        .build();
    f.deliver(crate::test_utils::node_to_owned_ref(&status))
        .await;
    assert!(
        f.transport.sent_count() + f.client.outbound_flush.pending() > 0,
        "the gate queues a status's ack inside the dispatcher, hook or not"
    );
    let (tag, attrs) = f.next_frame().await;
    assert_eq!(tag, "ack");
    assert_eq!(attrs["class"], "message");
    assert_eq!(attrs["id"], "ST-GATE-1");
    assert_eq!(attrs["to"], "status@broadcast");
}

/// An offline post during the drain is committed alone, not held for the
/// drain's batch: its ack is on its way before its event is published, and its
/// item says it is a catch-up delivery.
#[tokio::test]
async fn offline_newsletter_committed_alone_during_drain() {
    let (hook, calls, _release) = scripted([Step::Commit]);
    let f = fixture(Some(hook)).await;
    // The batcher accumulates again: it flushes on size, on its timer or at
    // the end of the drain, none of which this test reaches.
    f.client.enter_drain_mode_for_tests();

    let post = newsletter_post_builder("NL-OFF-1", 601, "caught up")
        .attr("offline", "1")
        .build();
    f.deliver(crate::test_utils::node_to_owned_ref(&post)).await;
    assert_eq!(next_call(&calls).await, ["NL-OFF-1"]);
    let batch = f.next_batch().await;
    assert!(
        f.transport.sent_count() + f.client.outbound_flush.pending() > 0,
        "the post's ack is on its way before its event is published"
    );
    assert_eq!(ids(&batch), ["NL-OFF-1"]);
    assert!(batch.hook_committed);
    assert!(
        batch.messages[0].info.is_offline,
        "the item the hook committed tells a catch-up delivery"
    );
    assert_eq!(f.next_frame().await, newsletter_ack("NL-OFF-1"));
}

/// Reports whether Signal maintenance refused inside the hook, then commits.
struct MaintenanceProbe(async_channel::Sender<bool>);

#[async_trait::async_trait]
impl InboundDurabilityHook for MaintenanceProbe {
    async fn on_messages(
        &self,
        client: Arc<Client>,
        _batch: &[InboundMessage],
    ) -> anyhow::Result<()> {
        let refused = client.ensure_signal_maintenance_context().is_err();
        self.0
            .try_send(refused)
            .expect("the test holds the probe receiver");
        Ok(())
    }
}

/// A newsletter's hook runs under the batcher's marker, so Signal maintenance
/// refuses inside it; the marker is gone once the hook's poll returns.
#[tokio::test]
async fn newsletter_hook_refuses_signal_maintenance() {
    let (probe_tx, probe) = async_channel::unbounded();
    let f = fixture(Some(Arc::new(MaintenanceProbe(probe_tx)))).await;

    f.deliver(newsletter_post("NL-MAINT-1", 701, "post")).await;
    assert!(
        probe.recv().await.expect("the hook ran"),
        "Signal maintenance must refuse inside a newsletter's hook"
    );
    assert_eq!(f.next_frame().await, newsletter_ack("NL-MAINT-1"));
    // `#[tokio::test]` runs the lane on this thread, so a marker left set
    // would refuse here too.
    f.client
        .ensure_signal_maintenance_context()
        .expect("the marker is cleared once the hook's poll returns");
}

/// The gate decides from `from` who owes the ack, and the handler follows it.
/// An own-device echo whose `recipient` is a channel (a shape the server isn't
/// known to send) parses to the channel, so the hook commits it and it is
/// published, but the gate owed it nothing, so nothing is sent for it.
#[tokio::test]
async fn newsletter_self_fanout_not_acked_with_hook() {
    let (hook, calls, _release) = scripted([Step::Commit]);
    let f = fixture(Some(hook)).await;

    let echo = NodeBuilder::new("message")
        .attr("from", own_device().to_non_ad_string())
        .attr("id", "NL-ECHO-1")
        .attr("recipient", NEWSLETTER)
        .attr("t", "1700000000")
        .attr("type", "text")
        .children([plaintext("own post")])
        .build();
    f.deliver(crate::test_utils::node_to_owned_ref(&echo)).await;
    assert_eq!(next_call(&calls).await, ["NL-ECHO-1"]);
    let batch = f.next_batch().await;
    assert_eq!(ids(&batch), ["NL-ECHO-1"]);
    assert!(batch.hook_committed);
    assert!(batch.messages[0].info.source.chat.is_newsletter());
    f.assert_quiet("once the echo is published");
}
