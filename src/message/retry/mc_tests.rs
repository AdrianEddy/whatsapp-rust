//! WF5: a message that produced no plaintext is reported through
//! `InboundDurabilityHook::on_undecryptable` before its stanza is answered.
//!
//! Stanzas enter where the read loop hands them over, `Client::process_node`,
//! and run through the real chat lane, classification and decrypt paths. The
//! transport captures what reaches the wire and the client's own frame tap
//! reports it. Every wait is on an event: a hook call, a dispatched event or a
//! sent frame. Absence is asserted where it is provable: while the hook holds
//! the report nothing about the message can have been sent or published, and
//! once a later stanza of the same chat lane reaches the hook (lanes are FIFO)
//! the refused one has been handled to the end, so a retry receipt or an ack
//! (both tracked by the outbound flush scope from the moment they are queued)
//! would be on the wire or on its way. A nack is a detached task, so its
//! absence is asserted once a later stanza's answer, queued after it would
//! have been, has reached the wire.

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use crate::client::Client;
use crate::message::raw_pending::{Occurrence, OwedReport, PendingJournal};
use crate::store::signal_adapter::SignalProtocolStoreAdapter;
use crate::store::traits::Backend;
use crate::transport::mock::{CapturingMockTransport, CapturingMockTransportFactory};
use crate::types::durability_hook::{
    InboundDurabilityHook, InboundMessage, UndecryptableCause, UndecryptableFailure,
    UndecryptableRecovery,
};
use crate::types::events::{DecryptFailMode, EncDecryptFailureReason, UnavailableType};
use crate::types::message::MessageInfo;
use wacore::libsignal::protocol::{
    CiphertextMessage, GenericSignedPreKey as _, IdentityKey, IdentityKeyPair, KeyPair,
    PreKeyBundle, PreKeyRecord, PreKeySignalMessage, PreKeyStore as _, ProtocolAddress,
    SignalMessage, SignedPreKeyStore as _, UsePQRatchet, create_sender_key_distribution_message,
    group_encrypt, message_encrypt, process_prekey_bundle,
};
use wacore::store::commands::DeviceCommand;
use wacore::types::events::{Event, EventHandler, EventInterest, EventKind, Subscription};
use wacore::types::jid::{JidExt as _, make_sender_key_name};
use wacore::types::message::SenderMessageId;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::{Jid, Node};
use waproto::whatsapp as wa;

/// The local device, which every answer names as its `from`.
fn own_device() -> Jid {
    Jid::pn_device("15550000001", 3)
}

/// Old enough that the client skips the request to the primary phone (older
/// than 14 days), so the retry receipt and the ack are the stanza's only
/// frames.
const STANZA_TIME: &str = "1700000000";

/// What the hook does with one `on_undecryptable` call, in call order.
#[derive(Clone, Copy)]
enum Step {
    Commit,
    /// Commit once the test releases it, holding the report mid-commit.
    CommitWhenReleased,
    Fail,
    /// Refuse once the test releases it.
    FailWhenReleased,
}

/// One `on_undecryptable` call as the hook saw it.
#[derive(Clone, Debug)]
struct Call {
    info: MessageInfo,
    cause: UndecryptableCause,
}

impl Call {
    fn id(&self) -> &str {
        self.info.id.as_str()
    }
}

/// Reports each `on_undecryptable` call, then does what the script says; a
/// call the test did not script fails, so it is reported and visible, never
/// hidden. Decrypted messages always commit, and their ids are reported.
struct ScriptedHook {
    steps: Mutex<VecDeque<Step>>,
    calls: async_channel::Sender<Call>,
    committed: async_channel::Sender<Vec<String>>,
    release: async_channel::Receiver<()>,
}

#[async_trait::async_trait]
impl InboundDurabilityHook for ScriptedHook {
    async fn on_messages(
        &self,
        _client: Arc<Client>,
        batch: &[InboundMessage],
    ) -> anyhow::Result<()> {
        self.committed
            .try_send(batch.iter().map(|item| item.info.id.to_string()).collect())
            .expect("the test holds the receiver");
        Ok(())
    }

    async fn on_undecryptable(
        &self,
        _client: Arc<Client>,
        info: &MessageInfo,
        cause: UndecryptableCause,
    ) -> anyhow::Result<()> {
        let step = self.steps.lock().expect("script lock").pop_front();
        self.calls
            .try_send(Call {
                info: info.clone(),
                cause,
            })
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
            Some(Step::FailWhenReleased) => {
                self.release
                    .recv()
                    .await
                    .expect("the test releases the held refusal");
                Err(anyhow::anyhow!("the store refused the commit"))
            }
            None => Err(anyhow::anyhow!("a hook call the test did not script")),
        }
    }
}

/// The hook's receivers: its undecryptable reports, its committed message
/// batches, and the sender that releases a held commit.
struct Script {
    calls: async_channel::Receiver<Call>,
    committed: async_channel::Receiver<Vec<String>>,
    release: async_channel::Sender<()>,
}

impl Script {
    async fn next_call(&self) -> Call {
        self.calls.recv().await.expect("the hook stays registered")
    }

    async fn next_commit(&self) -> Vec<String> {
        self.committed
            .recv()
            .await
            .expect("the hook stays registered")
    }

    async fn release(&self) {
        self.release
            .send(())
            .await
            .expect("the hook holds the commit");
    }
}

fn scripted(steps: &[Step]) -> (Arc<dyn InboundDurabilityHook>, Script) {
    let (calls_tx, calls) = async_channel::unbounded();
    let (committed_tx, committed) = async_channel::unbounded();
    let (release, release_rx) = async_channel::unbounded();
    let hook = Arc::new(ScriptedHook {
        steps: Mutex::new(steps.iter().copied().collect()),
        calls: calls_tx,
        committed: committed_tx,
        release: release_rx,
    });
    (
        hook,
        Script {
            calls,
            committed,
            release,
        },
    )
}

/// Forwards the dispatched events of some kinds to the test.
struct Forward {
    kinds: Vec<EventKind>,
    events: async_channel::Sender<Arc<Event>>,
}

impl EventHandler for Forward {
    fn handle_event(&self, event: Arc<Event>) {
        let _ = self.events.try_send(event);
    }

    fn interest(&self) -> EventInterest {
        EventInterest::of(&self.kinds)
    }
}

/// A frame that reached the transport, as its tag and attributes; a retry
/// receipt's `<retry>` child adds its `count` as `retry.count`.
type Frame = (String, BTreeMap<String, String>);

fn is_retry_receipt((tag, attrs): &Frame) -> bool {
    tag == "receipt" && attrs.get("type").is_some_and(|t| t == "retry")
}

fn is_ack((tag, attrs): &Frame) -> bool {
    tag == "ack"
        && attrs.get("class").is_some_and(|class| class == "message")
        && !attrs.contains_key("error")
}

fn is_nack((tag, attrs): &Frame) -> bool {
    tag == "ack" && attrs.contains_key("error")
}

fn is_delivery_receipt((tag, attrs): &Frame) -> bool {
    tag == "receipt" && attrs.get("type").is_none_or(|t| t != "retry")
}

/// A connected, logged-in client over a capturing transport, with its
/// undecryptable and message events and its sent frames forwarded.
struct Fixture {
    client: Arc<Client>,
    transport: Arc<CapturingMockTransport>,
    undecryptable: async_channel::Receiver<Arc<Event>>,
    messages: async_channel::Receiver<Arc<Event>>,
    frames: async_channel::Receiver<Arc<Event>>,
    /// Frames read from `frames` that a test has not asked for yet.
    backlog: Mutex<VecDeque<Frame>>,
    /// Every frame read from `frames`, in wire order.
    seen: Mutex<Vec<Frame>>,
    _subscriptions: [Subscription; 3],
    _frame_forwarding: crate::SentFrameLease,
}

async fn fixture(hook: Option<Arc<dyn InboundDurabilityHook>>) -> Fixture {
    fixture_on(crate::test_utils::create_test_backend().await, hook).await
}

/// [`fixture`] over `backend`. A second fixture on the same backend stands
/// for the client after a restart: it loads the device, the Signal state and
/// the pending journal the first one made durable.
async fn fixture_on(
    backend: Arc<dyn Backend>,
    hook: Option<Arc<dyn InboundDurabilityHook>>,
) -> Fixture {
    use crate::store::persistence_manager::PersistenceManager;
    use wacore::handshake::NoiseCipher;

    let persistence = Arc::new(
        PersistenceManager::new(backend)
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
    client.set_driver_running_for_test(true, Ordering::Release);
    client.enter_live_mode_for_tests();
    client
        .persistence_manager
        .process_command(DeviceCommand::SetId(Some(own_device())))
        .await;

    let (undecryptable_tx, undecryptable) = async_channel::unbounded();
    let (messages_tx, messages) = async_channel::unbounded();
    let (frames_tx, frames) = async_channel::unbounded();
    let subscriptions = [
        client.subscribe_handler(Arc::new(Forward {
            kinds: vec![EventKind::UndecryptableMessage],
            events: undecryptable_tx,
        })),
        client.subscribe_handler(Arc::new(Forward {
            kinds: vec![EventKind::Messages],
            events: messages_tx,
        })),
        client.subscribe_handler(Arc::new(Forward {
            kinds: vec![EventKind::SentFrame],
            events: frames_tx,
        })),
    ];
    let frame_forwarding = client.acquire_sent_frame_forwarding();
    Fixture {
        client,
        transport,
        undecryptable,
        messages,
        frames,
        backlog: Mutex::new(VecDeque::new()),
        seen: Mutex::new(Vec::new()),
        _subscriptions: subscriptions,
        _frame_forwarding: frame_forwarding,
    }
}

impl Fixture {
    async fn deliver(&self, stanza: &Node) {
        self.client
            .process_node(crate::test_utils::node_to_owned_ref(stanza))
            .await;
    }

    /// The next `UndecryptableMessage` event.
    async fn next_undecryptable(&self) -> crate::types::events::UndecryptableMessage {
        let event = self
            .undecryptable
            .recv()
            .await
            .expect("the bus stays subscribed");
        let Event::UndecryptableMessage(event) = &*event else {
            panic!("only undecryptable events are forwarded here");
        };
        event.clone()
    }

    /// The text of the next published message.
    async fn next_message_text(&self) -> String {
        let event = self
            .messages
            .recv()
            .await
            .expect("the bus stays subscribed");
        let Event::Messages(batch) = &*event else {
            panic!("only message batches are forwarded here");
        };
        batch.messages[0]
            .message
            .conversation
            .clone()
            .expect("a text message")
    }

    async fn read_frame(&self) -> Frame {
        let event = self.frames.recv().await.expect("the bus stays subscribed");
        let Event::SentFrame(sent) = &*event else {
            panic!("only sent frames are forwarded here");
        };
        let node = wacore_binary::marshal::unmarshal_packed_ref(&sent.plaintext)
            .expect("a sent frame decodes");
        let mut attrs: BTreeMap<String, String> = node
            .attrs
            .iter()
            .map(|(key, value)| (key.as_ref().to_owned(), value.to_string()))
            .collect();
        if let Some(count) = node
            .get_optional_child("retry")
            .and_then(|retry| retry.get_attr("count"))
        {
            attrs.insert("retry.count".to_owned(), count.to_string());
        }
        let frame: Frame = (node.tag.as_ref().to_owned(), attrs);
        self.seen.lock().expect("seen lock").push(frame.clone());
        frame
    }

    /// The next frame about message `id`, in wire order; frames about other
    /// messages are kept for their own requests.
    async fn next_frame_for(&self, id: &str) -> Frame {
        {
            let mut backlog = self.backlog.lock().expect("backlog lock");
            if let Some(index) = backlog
                .iter()
                .position(|(_, attrs)| attrs.get("id").is_some_and(|frame_id| frame_id == id))
            {
                return backlog.remove(index).expect("an index the backlog holds");
            }
        }
        loop {
            let frame = self.read_frame().await;
            if frame.1.get("id").is_some_and(|frame_id| frame_id == id) {
                return frame;
            }
            self.backlog.lock().expect("backlog lock").push_back(frame);
        }
    }

    /// The frames about message `id` read so far.
    fn seen_for(&self, id: &str) -> Vec<Frame> {
        self.seen
            .lock()
            .expect("seen lock")
            .iter()
            .filter(|(_, attrs)| attrs.get("id").is_some_and(|frame_id| frame_id == id))
            .cloned()
            .collect()
    }

    /// Nothing reached the wire, nothing tracked is on its way there and
    /// nothing was published. Sound at any instant: a retry receipt and an ack
    /// hold an outbound-flush guard from before they are queued until after
    /// the transport took their frame.
    fn assert_quiet(&self, when: &str) {
        assert_eq!(
            self.transport.sent_count(),
            0,
            "no frame may reach the wire {when}"
        );
        assert_eq!(
            self.client.outbound_flush.pending(),
            0,
            "no answer may be on its way {when}"
        );
        assert!(
            self.undecryptable.is_empty(),
            "no undecryptable event may be published {when}"
        );
        assert!(
            self.messages.is_empty(),
            "no message may be published {when}"
        );
    }

    /// Whether message `info`'s report holds the dispatch-once claim.
    async fn claimed(&self, info: &MessageInfo) -> bool {
        self.client
            .undecryptable_dispatched
            .get(&SenderMessageId::new(
                info.source.chat.clone(),
                info.id.clone(),
                info.source.sender.clone(),
            ))
            .await
            .is_some()
    }
}

fn session_stanza(from: &str, id: &str, encs: &[(&str, Vec<u8>)]) -> Node {
    NodeBuilder::new("message")
        .attr("from", from)
        .attr("id", id)
        .attr("t", STANZA_TIME)
        .attr("type", "text")
        .children(encs.iter().map(|(kind, bytes)| enc(kind, bytes.clone())))
        .build()
}

fn group_stanza(group: &str, participant: &str, id: &str, encs: &[(&str, Vec<u8>)]) -> Node {
    NodeBuilder::new("message")
        .attr("from", group)
        .attr("participant", participant)
        .attr("id", id)
        .attr("t", STANZA_TIME)
        .attr("type", "text")
        .children(encs.iter().map(|(kind, bytes)| enc(kind, bytes.clone())))
        .build()
}

fn enc(kind: &str, bytes: Vec<u8>) -> Node {
    NodeBuilder::new("enc")
        .attr("v", "2")
        .attr("type", kind)
        .bytes(bytes)
        .build()
}

/// An `<unavailable>` stub of the given `type` (none for a plain fan-out).
fn unavailable_stanza(from: &str, id: &str, kind: Option<&str>) -> Node {
    let mut stub = NodeBuilder::new("unavailable");
    if let Some(kind) = kind {
        stub = stub.attr("type", kind);
    }
    NodeBuilder::new("message")
        .attr("from", from)
        .attr("id", id)
        .attr("t", STANZA_TIME)
        .attr("type", "text")
        .children([stub.build()])
        .build()
}

/// A well-formed `msg` for a session this client never had: it parses and
/// fails with `SessionNotFound`.
fn no_session_msg() -> Vec<u8> {
    let mut rng = rand::make_rng::<rand::rngs::StdRng>();
    let ratchet = KeyPair::generate(&mut rng).public_key;
    let sender = IdentityKeyPair::generate(&mut rng);
    let receiver = IdentityKeyPair::generate(&mut rng);
    SignalMessage::new(
        4,
        &[0u8; 32],
        ratchet,
        0,
        0,
        b"unreadable",
        sender.identity_key(),
        receiver.identity_key(),
    )
    .expect("a well-formed SignalMessage")
    .serialized()
    .to_vec()
}

/// A well-formed `pkmsg` naming a signed prekey this client never had: it
/// fails with `InvalidSignedPreKeyId`.
fn unknown_signed_prekey_pkmsg() -> Vec<u8> {
    let mut rng = rand::make_rng::<rand::rngs::StdRng>();
    let sender = IdentityKeyPair::generate(&mut rng);
    let receiver = IdentityKeyPair::generate(&mut rng);
    let inner = SignalMessage::new(
        4,
        &[0u8; 32],
        KeyPair::generate(&mut rng).public_key,
        0,
        0,
        b"unreadable",
        sender.identity_key(),
        receiver.identity_key(),
    )
    .expect("a well-formed SignalMessage");
    PreKeySignalMessage::new(
        4,
        4242,
        Some(4243.into()),
        4242.into(),
        KeyPair::generate(&mut rng).public_key,
        *sender.identity_key(),
        inner,
    )
    .expect("a well-formed PreKeySignalMessage")
    .serialized()
    .to_vec()
}

/// A `skmsg` that parses (version 3, a protobuf, a 64-byte signature) for a
/// chain this client holds no sender key for: `NoSenderKeyState`.
fn no_sender_key_skmsg() -> Vec<u8> {
    let mut bytes = vec![0x33, 0x08, 0x01, 0x10, 0x01, 0x1A, 0x00];
    bytes.extend([0u8; 64]);
    bytes
}

/// Bytes no Signal envelope parses from: a parse failure, nacked.
fn malformed_msg() -> Vec<u8> {
    vec![0xFF, 0x00, 0x03]
}

/// A bot reply (`msmsg`) no `MessageSecretMessage` decodes from: a malformed
/// payload, nacked with 487.
fn malformed_msmsg() -> Vec<u8> {
    vec![0xFF]
}

/// A stanza whose only `<enc>` is of a type this client has no path for,
/// marked `decrypt-fail="hide"` when `hide`.
fn future_enc_stanza(from: &str, id: &str, hide: bool) -> Node {
    let mut enc = NodeBuilder::new("enc")
        .attr("v", "2")
        .attr("type", "future");
    if hide {
        enc = enc.attr("decrypt-fail", "hide");
    }
    NodeBuilder::new("message")
        .attr("from", from)
        .attr("id", id)
        .attr("t", STANZA_TIME)
        .attr("type", "text")
        .children([enc.bytes(vec![1, 2, 3]).build()])
        .build()
}

/// Built as a host's tests build one (the type is `#[non_exhaustive]`).
fn cause(failure: EncDecryptFailureReason, recovery: UndecryptableRecovery) -> UndecryptableCause {
    UndecryptableCause::builder()
        .failure(UndecryptableFailure::Enc(failure))
        .recovery(recovery)
        .decrypt_fail_mode(DecryptFailMode::Show)
        .build()
}

/// A peer that opens a real Signal session to the client under test. Its
/// stores are a second client's, so the session it keeps is the library's own.
struct Peer {
    jid: Jid,
    /// The peer's address as the client under test sees it.
    address: ProtocolAddress,
    /// The client under test's address as the peer sees it.
    target: ProtocolAddress,
    stores: SignalProtocolStoreAdapter,
    _client: Arc<Client>,
}

impl Peer {
    /// Opens the peer's side of a session from a bundle of `client`'s keys
    /// with a fresh one-time prekey `prekey_id`.
    async fn new(client: &Arc<Client>, jid: &str, prekey_id: u32) -> Self {
        let mut rng = rand::make_rng::<rand::rngs::StdRng>();
        let snapshot = client.persistence_manager.get_device_snapshot();
        let own = snapshot.pn.clone().expect("the fixture sets the own JID");
        let mut adapter = client.signal_adapter();
        let signed = adapter
            .signed_pre_key_store
            .get_signed_pre_key(1.into())
            .await
            .expect("the client's signed prekey");
        let prekey = KeyPair::generate(&mut rng);
        adapter
            .pre_key_store
            .save_pre_key(
                prekey_id.into(),
                &PreKeyRecord::new(prekey_id.into(), &prekey),
            )
            .await
            .expect("the one-time prekey is stored");
        let bundle = PreKeyBundle::new(
            snapshot.core.registration_id,
            u32::from(own.device).into(),
            Some((prekey_id.into(), prekey.public_key)),
            1.into(),
            signed.public_key().expect("signed prekey public key"),
            signed.signature().expect("signed prekey signature"),
            IdentityKey::new(snapshot.core.identity_key.public_key),
        )
        .expect("a valid bundle");

        let peer_client = crate::test_utils::create_test_client().await;
        let mut stores = peer_client.signal_adapter();
        let target = own.to_non_ad().to_protocol_address();
        process_prekey_bundle(
            &target,
            &mut stores.session_store,
            &mut stores.identity_store,
            &bundle,
            &mut rng,
            UsePQRatchet::No,
        )
        .await
        .expect("the peer accepts the bundle");
        let jid: Jid = jid.parse().expect("peer JID");
        Self {
            address: jid.to_protocol_address(),
            jid,
            target,
            stores,
            _client: peer_client,
        }
    }

    /// `plaintext` encrypted as the stanza's next `<enc>`: a `pkmsg` until
    /// the peer hears back, which it never does here.
    async fn encrypt(&mut self, plaintext: &[u8]) -> (&'static str, Vec<u8>) {
        let message = message_encrypt(
            plaintext,
            &self.target,
            &mut self.stores.session_store,
            &mut self.stores.identity_store,
        )
        .await
        .expect("the peer encrypts");
        match message {
            CiphertextMessage::PreKeySignalMessage(message) => {
                ("pkmsg", message.serialized().to_vec())
            }
            CiphertextMessage::SignalMessage(message) => ("msg", message.serialized().to_vec()),
            _ => panic!("a session ciphertext"),
        }
    }

    /// A text message, encoded and padded as a sender does.
    async fn encrypt_text(&mut self, text: &str) -> (&'static str, Vec<u8>) {
        let mut message = wa::Message::default();
        message.conversation = Some(text.to_owned());
        self.encrypt(&wacore::messages::MessageUtils::encode_and_pad(&message))
            .await
    }

    /// A group stanza's two `<enc>`s as a sender builds them: the session
    /// message handing the client the peer's sender key for `group`, then
    /// `plaintext` encrypted with that key (`skmsg`).
    async fn group_encs(&mut self, group: &Jid, plaintext: &[u8]) -> [(&'static str, Vec<u8>); 2] {
        let mut rng = rand::make_rng::<rand::rngs::StdRng>();
        let name = make_sender_key_name(group, &self.address);
        let distribution = create_sender_key_distribution_message(
            &name,
            &mut self.stores.sender_key_store,
            &mut rng,
        )
        .await
        .expect("the peer creates its sender key");
        let mut skdm = wa::message::SenderKeyDistributionMessage::default();
        skdm.group_id = Some(group.to_string());
        skdm.axolotl_sender_key_distribution_message = Some(distribution.serialized().to_vec());
        let mut message = wa::Message::default();
        message.sender_key_distribution_message = buffa::MessageField::some(skdm);
        let carrier = self
            .encrypt(&wacore::messages::MessageUtils::encode_and_pad(&message))
            .await;
        let skmsg = group_encrypt(
            &mut self.stores.sender_key_store,
            &name,
            plaintext,
            &mut rng,
        )
        .await
        .expect("the peer encrypts for the group")
        .serialized()
        .to_vec();
        [carrier, ("skmsg", skmsg)]
    }
}

/// A plaintext the sender padded wrongly: its last byte claims five bytes of
/// padding in a one-byte plaintext, so it decrypts and cannot be unpadded.
const UNUSABLE_PLAINTEXT: &[u8] = &[0x05];

/// Delivers `stanza` with the hook holding its report, checks nothing about
/// the message is sent or published until the hook commits, then checks the
/// event, and the retry receipt before the ack.
async fn assert_reported_before_retry_and_ack(
    f: &Fixture,
    script: &Script,
    stanza: &Node,
    id: &str,
    expected: UndecryptableCause,
) {
    f.deliver(stanza).await;
    let call = script.next_call().await;
    assert_eq!(call.id(), id);
    assert_eq!(call.cause, expected, "{id}: the hook is told what failed");
    f.assert_quiet("while the hook commits the report");

    script.release().await;
    let event = f.next_undecryptable().await;
    assert_eq!(event.info.id, id);
    assert!(!event.is_unavailable);
    let retry = f.next_frame_for(id).await;
    assert!(
        is_retry_receipt(&retry),
        "{id}: the retry receipt first: {retry:?}"
    );
    assert_eq!(retry.1["retry.count"], "1", "{id}: the first retry");
    let ack = f.next_frame_for(id).await;
    assert!(is_ack(&ack), "{id}: then the ack: {ack:?}");
}

/// The hook commits the report before anything answers the stanza: the
/// `UndecryptableMessage` event, the retry receipt and then the ack follow it,
/// for a `msg` without a session, a `pkmsg` naming an unknown prekey, a group
/// `skmsg` without a sender key, and a group stanza whose `skmsg` is skipped
/// after its `pkmsg` failed (reported once, for the `pkmsg`). An `<unavailable>`
/// stub's ack follows the commit too.
#[tokio::test]
async fn undecryptable_hook_runs_before_ack_and_retry_receipt() {
    let held = [Step::CommitWhenReleased];

    let (hook, script) = scripted(&held);
    let f = fixture(Some(hook)).await;
    assert_reported_before_retry_and_ack(
        &f,
        &script,
        &session_stanza(
            "15550002002@s.whatsapp.net",
            "WF5-MSG-1",
            &[("msg", no_session_msg())],
        ),
        "WF5-MSG-1",
        cause(
            EncDecryptFailureReason::NoSession,
            UndecryptableRecovery::RetryReceipt,
        ),
    )
    .await;

    let (hook, script) = scripted(&held);
    let f = fixture(Some(hook)).await;
    assert_reported_before_retry_and_ack(
        &f,
        &script,
        &session_stanza(
            "15550002003@s.whatsapp.net",
            "WF5-PKMSG-1",
            &[("pkmsg", unknown_signed_prekey_pkmsg())],
        ),
        "WF5-PKMSG-1",
        cause(
            EncDecryptFailureReason::UnknownPreKey,
            UndecryptableRecovery::RetryReceipt,
        ),
    )
    .await;

    let (hook, script) = scripted(&held);
    let f = fixture(Some(hook)).await;
    assert_reported_before_retry_and_ack(
        &f,
        &script,
        &group_stanza(
            "120363000000000501@g.us",
            "15550002004@s.whatsapp.net",
            "WF5-SKMSG-1",
            &[("skmsg", no_sender_key_skmsg())],
        ),
        "WF5-SKMSG-1",
        cause(
            EncDecryptFailureReason::NoSenderKey,
            UndecryptableRecovery::RetryReceipt,
        ),
    )
    .await;

    // The skmsg is skipped because the pkmsg that would carry its sender key
    // failed: one report, the pkmsg's. A later stanza of the same group lane
    // reaches the hook next, so the skipped skmsg reported nothing more.
    let (hook, script) = scripted(&[Step::CommitWhenReleased, Step::Commit]);
    let f = fixture(Some(hook)).await;
    let group = "120363000000000502@g.us";
    let participant = "15550002005@s.whatsapp.net";
    assert_reported_before_retry_and_ack(
        &f,
        &script,
        &group_stanza(
            group,
            participant,
            "WF5-SKIP-1",
            &[
                ("pkmsg", unknown_signed_prekey_pkmsg()),
                ("skmsg", no_sender_key_skmsg()),
            ],
        ),
        "WF5-SKIP-1",
        cause(
            EncDecryptFailureReason::UnknownPreKey,
            UndecryptableRecovery::RetryReceipt,
        ),
    )
    .await;
    f.deliver(&group_stanza(
        group,
        participant,
        "WF5-SKIP-2",
        &[("skmsg", no_sender_key_skmsg())],
    ))
    .await;
    assert_eq!(
        script.next_call().await.id(),
        "WF5-SKIP-2",
        "the skipped skmsg was not reported again"
    );

    // A plain `<unavailable>` fan-out asks the phone (skipped here: the
    // message is too old), a view-once one nothing; both ack after the commit.
    for (kind, id, recovery) in [
        (None, "WF5-UNAV-1", UndecryptableRecovery::PlaceholderResend),
        (
            Some("view_once"),
            "WF5-UNAV-2",
            UndecryptableRecovery::NoRequest,
        ),
    ] {
        let (hook, script) = scripted(&held);
        let f = fixture(Some(hook)).await;
        f.deliver(&unavailable_stanza("15550002006@s.whatsapp.net", id, kind))
            .await;
        let call = script.next_call().await;
        assert_eq!(call.id(), id);
        let unavailable = if kind.is_some() {
            UnavailableType::ViewOnce
        } else {
            UnavailableType::Unknown
        };
        assert_eq!(
            call.cause,
            UndecryptableCause {
                failure: UndecryptableFailure::Unavailable(unavailable),
                recovery,
                decrypt_fail_mode: DecryptFailMode::Show,
            }
        );
        f.assert_quiet("while the hook commits the stub's report");
        script.release().await;
        let event = f.next_undecryptable().await;
        assert!(event.is_unavailable);
        assert_eq!(event.unavailable_type, unavailable);
        let ack = f.next_frame_for(id).await;
        assert!(is_ack(&ack), "{id}: the stub is acked: {ack:?}");
    }
}

/// A refused report withholds everything that answers the stanza: no event,
/// no retry receipt, no ack, no request to the phone. The next stanza of the
/// chat lane reaching the hook proves the refused one was handled to the end.
/// The redelivery is reported again and answered, its retry still the first.
#[tokio::test]
async fn undecryptable_hook_error_withholds_ack() {
    let (hook, script) = scripted(&[Step::Fail, Step::CommitWhenReleased, Step::Commit]);
    let f = fixture(Some(hook)).await;
    let sender = "15550002010@s.whatsapp.net";
    let refused = session_stanza(sender, "WF5-REFUSE-1", &[("msg", no_session_msg())]);
    f.deliver(&refused).await;
    f.deliver(&session_stanza(
        sender,
        "WF5-REFUSE-2",
        &[("msg", no_session_msg())],
    ))
    .await;
    let first = script.next_call().await;
    assert_eq!(first.id(), "WF5-REFUSE-1");
    assert_eq!(script.next_call().await.id(), "WF5-REFUSE-2");
    f.assert_quiet("after the hook refused the first report");
    assert!(
        !f.claimed(&first.info).await,
        "a refused report leaves no dispatch claim"
    );

    script.release().await;
    assert_eq!(f.next_undecryptable().await.info.id, "WF5-REFUSE-2");
    assert!(is_retry_receipt(&f.next_frame_for("WF5-REFUSE-2").await));
    assert!(is_ack(&f.next_frame_for("WF5-REFUSE-2").await));

    // The server delivers the refused stanza again; this time the hook commits.
    f.deliver(&refused).await;
    let again = script.next_call().await;
    assert_eq!(again.id(), "WF5-REFUSE-1");
    assert_eq!(again.cause, first.cause);
    assert_eq!(f.next_undecryptable().await.info.id, "WF5-REFUSE-1");
    let retry = f.next_frame_for("WF5-REFUSE-1").await;
    assert!(is_retry_receipt(&retry));
    assert_eq!(
        retry.1["retry.count"], "1",
        "the refused delivery spent no retry"
    );
    assert!(is_ack(&f.next_frame_for("WF5-REFUSE-1").await));

    // An `<unavailable>` stub: neither the request to the phone nor the ack.
    let (hook, script) = scripted(&[Step::Fail, Step::CommitWhenReleased, Step::Commit]);
    let f = fixture(Some(hook)).await;
    let from = "15550002011@s.whatsapp.net";
    let stub = unavailable_stanza(from, "WF5-STUB-1", None);
    f.deliver(&stub).await;
    f.deliver(&unavailable_stanza(from, "WF5-STUB-2", None))
        .await;
    assert_eq!(script.next_call().await.id(), "WF5-STUB-1");
    assert_eq!(script.next_call().await.id(), "WF5-STUB-2");
    f.assert_quiet("after the hook refused the stub's report");
    script.release().await;
    assert_eq!(f.next_undecryptable().await.info.id, "WF5-STUB-2");
    assert!(is_ack(&f.next_frame_for("WF5-STUB-2").await));
    f.deliver(&stub).await;
    assert_eq!(script.next_call().await.id(), "WF5-STUB-1");
    assert_eq!(f.next_undecryptable().await.info.id, "WF5-STUB-1");
    assert!(is_ack(&f.next_frame_for("WF5-STUB-1").await));

    // A refusal settles the stanza for this delivery: the branch that reports
    // a skipped skmsg does not report it again, whether the pkmsg's report
    // was to be answered with a retry receipt or a nack, so the stanzas'
    // reports reach the hook once each, in lane order.
    let (hook, script) = scripted(&[Step::Fail, Step::Fail, Step::Commit]);
    let f = fixture(Some(hook)).await;
    let group = "120363000000000503@g.us";
    let participant = "15550002012@s.whatsapp.net";
    for (id, pkmsg) in [
        ("WF5-SETTLED-1", unknown_signed_prekey_pkmsg()),
        ("WF5-SETTLED-2", malformed_msg()),
    ] {
        f.deliver(&group_stanza(
            group,
            participant,
            id,
            &[("pkmsg", pkmsg), ("skmsg", no_sender_key_skmsg())],
        ))
        .await;
    }
    f.deliver(&group_stanza(
        group,
        participant,
        "WF5-SETTLED-3",
        &[("skmsg", no_sender_key_skmsg())],
    ))
    .await;
    for id in ["WF5-SETTLED-1", "WF5-SETTLED-2", "WF5-SETTLED-3"] {
        assert_eq!(
            script.next_call().await.id(),
            id,
            "a refused stanza is not reported again"
        );
    }
    assert_eq!(f.next_undecryptable().await.info.id, "WF5-SETTLED-3");
    assert!(is_retry_receipt(&f.next_frame_for("WF5-SETTLED-3").await));
    for id in ["WF5-SETTLED-1", "WF5-SETTLED-2"] {
        assert!(f.seen_for(id).is_empty(), "{id} got no answer");
    }
}

/// A `pkmsg` that decrypts into an unusable plaintext is nacked once the hook
/// committed its report; a refused report sends no nack. Its redelivery
/// decrypts as a duplicate, so the client reports it again from the report
/// the journal owes, with the same cause, before answering the duplicate.
#[tokio::test]
async fn plaintext_failure_hook_error_sends_no_nack() {
    let (hook, script) = scripted(&[Step::Fail, Step::Commit, Step::Commit, Step::Commit]);
    let f = fixture(Some(hook)).await;
    let mut peer = Peer::new(&f.client, "15550002020@s.whatsapp.net", 9001).await;
    let from = peer.jid.to_string();
    let (kind, bytes) = peer.encrypt(UNUSABLE_PLAINTEXT).await;
    let unusable = session_stanza(&from, "WF5-PLAIN-1", &[(kind, bytes)]);
    f.deliver(&unusable).await;
    let refused = script.next_call().await;
    assert_eq!(refused.id(), "WF5-PLAIN-1");
    assert_eq!(
        refused.cause,
        cause(
            EncDecryptFailureReason::PlaintextUnusable,
            UndecryptableRecovery::NoRequest
        )
    );

    // A later stanza of the peer's lane: its report and its nack come after
    // the refused one was handled, and its nack after any the refused one
    // could have queued.
    f.deliver(&session_stanza(
        &from,
        "WF5-PLAIN-2",
        &[("msg", malformed_msg())],
    ))
    .await;
    assert_eq!(script.next_call().await.id(), "WF5-PLAIN-2");
    assert!(is_nack(&f.next_frame_for("WF5-PLAIN-2").await));
    assert_eq!(f.next_undecryptable().await.info.id, "WF5-PLAIN-2");
    assert!(
        f.seen_for("WF5-PLAIN-1").is_empty(),
        "the refused report sent nothing"
    );
    assert!(f.undecryptable.is_empty(), "nor published anything");

    // The redelivery is reported again from the owed report, then answered as
    // the duplicate it is.
    f.deliver(&unusable).await;
    let again = script.next_call().await;
    assert_eq!(again.id(), "WF5-PLAIN-1");
    assert_eq!(again.cause, refused.cause);
    assert_eq!(f.next_undecryptable().await.info.id, "WF5-PLAIN-1");
    let answer = f.next_frame_for("WF5-PLAIN-1").await;
    assert!(
        is_delivery_receipt(&answer),
        "the duplicate is answered: {answer:?}"
    );
    assert!(
        !f.seen_for("WF5-PLAIN-1").iter().any(is_nack),
        "no nack ever went out for the refused delivery"
    );

    // Without a refusal the unusable plaintext is nacked after the commit,
    // and the report it owed while the hook ran is settled before that.
    let mut other = Peer::new(&f.client, "15550002021@s.whatsapp.net", 9002).await;
    let (kind, bytes) = other.encrypt(UNUSABLE_PLAINTEXT).await;
    f.deliver(&session_stanza(
        &other.jid.to_string(),
        "WF5-PLAIN-3",
        &[(kind, bytes)],
    ))
    .await;
    let committed = script.next_call().await;
    assert_eq!(committed.id(), "WF5-PLAIN-3");
    assert_eq!(f.next_undecryptable().await.info.id, "WF5-PLAIN-3");
    let nack = f.next_frame_for("WF5-PLAIN-3").await;
    assert!(is_nack(&nack), "{nack:?}");
    assert_eq!(nack.1["error"], "491", "InvalidProtobuf");
    assert_eq!(
        owed(&f, &committed.info).await,
        None,
        "a committed report owes nothing"
    );
}

/// A plaintext failure after a successful prefix while the rest of the stanza
/// waits for an identity recovery is reported with no nack, the stanza left
/// for redelivery. A refused report leaves it unanswered too, and its
/// redelivery reports it again from the report the journal owes, saying that
/// nothing more is asked for it (that delivery is answered), then processes
/// the rest.
#[tokio::test]
async fn recovery_deferred_failure_hook_error_keeps_stanza_unacked() {
    use crate::store::signal_adapter::strict_identity_fixture::Rejection;

    let (hook, script) = scripted(&[Step::Fail, Step::Commit, Step::Commit]);
    let f = fixture(Some(hook)).await;
    let mut peer = Peer::new(&f.client, "15550002030@s.whatsapp.net", 9001).await;
    let from = peer.jid.to_string();
    let (kind, bytes) = peer.encrypt_text("hello").await;
    f.deliver(&session_stanza(&from, "WF5-DEFER-0", &[(kind, bytes)]))
        .await;
    assert_eq!(script.next_commit().await, ["WF5-DEFER-0"]);
    assert_eq!(f.next_message_text().await, "hello");
    assert!(is_delivery_receipt(&f.next_frame_for("WF5-DEFER-0").await));

    // One stanza: an unusable plaintext, then a payload whose identity check
    // is refused once, which defers the rest of the stanza to its redelivery.
    let unusable = peer.encrypt(UNUSABLE_PLAINTEXT).await;
    let suffix = peer.encrypt_text("after the recovery").await;
    let stanza = session_stanza(&from, "WF5-DEFER-1", &[unusable, suffix]);
    let rejection = Rejection::after_checks(peer.address.clone(), 1);
    f.deliver(&stanza).await;
    let refused = script.next_call().await;
    assert_eq!(refused.id(), "WF5-DEFER-1");
    assert_eq!(
        refused.cause,
        cause(
            EncDecryptFailureReason::PlaintextUnusable,
            UndecryptableRecovery::Redelivery
        )
    );

    f.deliver(&session_stanza(
        &from,
        "WF5-DEFER-2",
        &[("msg", malformed_msg())],
    ))
    .await;
    assert_eq!(script.next_call().await.id(), "WF5-DEFER-2");
    assert!(is_nack(&f.next_frame_for("WF5-DEFER-2").await));
    assert!(
        rejection.happened(),
        "the second payload's identity was refused"
    );
    assert!(
        f.seen_for("WF5-DEFER-1").is_empty(),
        "the deferred stanza stays unanswered"
    );
    assert_eq!(f.next_undecryptable().await.info.id, "WF5-DEFER-2");
    assert!(
        f.undecryptable.is_empty(),
        "the refused report published nothing"
    );
    assert!(f.messages.is_empty());

    // The redelivery reports the unusable payload from the owed report first,
    // then decrypts the payload the recovery deferred. The report no longer
    // waits for a redelivery: this one is processed and answered.
    f.deliver(&stanza).await;
    let again = script.next_call().await;
    assert_eq!(again.id(), "WF5-DEFER-1");
    assert_eq!(
        again.cause,
        cause(
            EncDecryptFailureReason::PlaintextUnusable,
            UndecryptableRecovery::NoRequest
        )
    );
    assert_eq!(f.next_undecryptable().await.info.id, "WF5-DEFER-1");
    assert_eq!(script.next_commit().await, ["WF5-DEFER-1"]);
    assert_eq!(f.next_message_text().await, "after the recovery");
    let answer = f.next_frame_for("WF5-DEFER-1").await;
    assert!(is_delivery_receipt(&answer), "{answer:?}");
    assert!(!f.seen_for("WF5-DEFER-1").iter().any(is_nack));
    drop(rejection);
}

/// A group `skmsg` that decrypts into an unusable plaintext is reported as
/// the session path reports one: the hook commits before the 491 nack. A
/// refused report sends no nack, and the redelivery, whose `skmsg` decrypts as
/// a duplicate, reports it again from the report the journal owes before the
/// duplicate is answered.
#[tokio::test]
async fn group_plaintext_failure_reported_before_nack() {
    let group: Jid = "120363000000000510@g.us".parse().expect("group JID");
    let unusable = cause(
        EncDecryptFailureReason::PlaintextUnusable,
        UndecryptableRecovery::NoRequest,
    );

    let (hook, script) = scripted(&[Step::CommitWhenReleased]);
    let f = fixture(Some(hook)).await;
    let mut peer = Peer::new(&f.client, "15550002110@s.whatsapp.net", 9001).await;
    let encs = peer.group_encs(&group, UNUSABLE_PLAINTEXT).await;
    f.deliver(&group_stanza(
        &group.to_string(),
        &peer.jid.to_string(),
        "WF5-GPLAIN-1",
        &encs,
    ))
    .await;
    let call = script.next_call().await;
    assert_eq!(call.id(), "WF5-GPLAIN-1");
    assert_eq!(call.cause, unusable, "the hook is told what failed");
    f.assert_quiet("while the hook commits the report");
    script.release().await;
    assert_eq!(f.next_undecryptable().await.info.id, "WF5-GPLAIN-1");
    let nack = f.next_frame_for("WF5-GPLAIN-1").await;
    assert!(is_nack(&nack), "{nack:?}");
    assert_eq!(nack.1["error"], "491", "InvalidProtobuf");

    let (hook, script) = scripted(&[Step::Fail, Step::Commit, Step::Commit]);
    let f = fixture(Some(hook)).await;
    let mut peer = Peer::new(&f.client, "15550002111@s.whatsapp.net", 9001).await;
    let encs = peer.group_encs(&group, UNUSABLE_PLAINTEXT).await;
    let (chat, participant) = (group.to_string(), peer.jid.to_string());
    let stanza = group_stanza(&chat, &participant, "WF5-GPLAIN-2", &encs);
    f.deliver(&stanza).await;
    let refused = script.next_call().await;
    assert_eq!(refused.id(), "WF5-GPLAIN-2");
    assert_eq!(refused.cause, unusable);

    // A later stanza of the group's lane: its report and its nack come after
    // the refused one was handled, its nack after any the refused one could
    // have queued.
    f.deliver(&group_stanza(
        &chat,
        &participant,
        "WF5-GPLAIN-3",
        &[("pkmsg", malformed_msg())],
    ))
    .await;
    assert_eq!(script.next_call().await.id(), "WF5-GPLAIN-3");
    assert!(is_nack(&f.next_frame_for("WF5-GPLAIN-3").await));
    assert_eq!(f.next_undecryptable().await.info.id, "WF5-GPLAIN-3");
    assert!(
        f.seen_for("WF5-GPLAIN-2").is_empty(),
        "the refused report sent nothing"
    );
    assert!(f.undecryptable.is_empty(), "nor published anything");

    f.deliver(&stanza).await;
    let again = script.next_call().await;
    assert_eq!(again.id(), "WF5-GPLAIN-2");
    assert_eq!(again.cause, refused.cause);
    assert_eq!(f.next_undecryptable().await.info.id, "WF5-GPLAIN-2");
    let answer = f.next_frame_for("WF5-GPLAIN-2").await;
    assert!(
        is_delivery_receipt(&answer),
        "the duplicate is answered: {answer:?}"
    );
    assert!(
        !f.seen_for("WF5-GPLAIN-2").iter().any(is_nack),
        "no nack ever went out for the refused delivery"
    );
}

/// A stanza none of whose `<enc>`s this client can decrypt (an unsupported
/// type here) is reported before its ack, with the first such `<enc>`'s
/// reason and the stanza's decrypt-fail mode. A refused report leaves it
/// unacked, and its redelivery, classified the same way, is reported again.
#[tokio::test]
async fn unusable_enc_reported_before_ack() {
    let from = "15550002100@s.whatsapp.net";

    let (hook, script) = scripted(&[Step::CommitWhenReleased]);
    let f = fixture(Some(hook)).await;
    f.deliver(&future_enc_stanza(from, "WF5-FUTURE-1", true))
        .await;
    let call = script.next_call().await;
    assert_eq!(call.id(), "WF5-FUTURE-1");
    assert_eq!(
        call.cause,
        UndecryptableCause {
            failure: UndecryptableFailure::Enc(EncDecryptFailureReason::UnsupportedEncType),
            recovery: UndecryptableRecovery::NoRequest,
            decrypt_fail_mode: DecryptFailMode::Hide,
        }
    );
    f.assert_quiet("while the hook commits the report");
    script.release().await;
    let event = f.next_undecryptable().await;
    assert_eq!(event.info.id, "WF5-FUTURE-1");
    assert!(!event.is_unavailable);
    assert_eq!(event.decrypt_fail_mode, DecryptFailMode::Hide);
    let ack = f.next_frame_for("WF5-FUTURE-1").await;
    assert!(
        is_ack(&ack),
        "the stanza is acked after the commit: {ack:?}"
    );

    let (hook, script) = scripted(&[Step::Fail, Step::CommitWhenReleased, Step::Commit]);
    let f = fixture(Some(hook)).await;
    let refused = future_enc_stanza(from, "WF5-FUTURE-2", false);
    f.deliver(&refused).await;
    f.deliver(&future_enc_stanza(from, "WF5-FUTURE-3", false))
        .await;
    assert_eq!(script.next_call().await.id(), "WF5-FUTURE-2");
    assert_eq!(script.next_call().await.id(), "WF5-FUTURE-3");
    f.assert_quiet("after the hook refused the first report");
    script.release().await;
    assert_eq!(f.next_undecryptable().await.info.id, "WF5-FUTURE-3");
    assert!(is_ack(&f.next_frame_for("WF5-FUTURE-3").await));

    f.deliver(&refused).await;
    assert_eq!(script.next_call().await.id(), "WF5-FUTURE-2");
    assert_eq!(f.next_undecryptable().await.info.id, "WF5-FUTURE-2");
    assert!(is_ack(&f.next_frame_for("WF5-FUTURE-2").await));
}

/// A bot reply (`msmsg`) that can't be opened is reported before its nack,
/// as any `<enc>` that produced no plaintext. A refused report sends no nack,
/// and the redelivery opens the payload again and reports it again.
#[tokio::test]
async fn bot_payload_failure_reported_before_nack() {
    let from = "15550002080@s.whatsapp.net";
    let malformed = cause(
        EncDecryptFailureReason::MalformedCiphertext,
        UndecryptableRecovery::NoRequest,
    );

    let (hook, script) = scripted(&[Step::CommitWhenReleased]);
    let f = fixture(Some(hook)).await;
    f.deliver(&session_stanza(
        from,
        "WF5-BOT-1",
        &[("msmsg", malformed_msmsg())],
    ))
    .await;
    let call = script.next_call().await;
    assert_eq!(call.id(), "WF5-BOT-1");
    assert_eq!(call.cause, malformed, "the hook is told what failed");
    f.assert_quiet("while the hook commits the report");
    script.release().await;
    assert_eq!(f.next_undecryptable().await.info.id, "WF5-BOT-1");
    let nack = f.next_frame_for("WF5-BOT-1").await;
    assert!(is_nack(&nack), "{nack:?}");
    assert_eq!(nack.1["error"], "487", "ParsingError");

    let (hook, script) = scripted(&[Step::Fail, Step::Commit, Step::Commit]);
    let f = fixture(Some(hook)).await;
    let refused = session_stanza(from, "WF5-BOT-2", &[("msmsg", malformed_msmsg())]);
    f.deliver(&refused).await;
    let first = script.next_call().await;
    assert_eq!(first.id(), "WF5-BOT-2");
    assert_eq!(first.cause, malformed);

    // A later stanza of the lane, nacked after any nack the refused one
    // could have queued.
    f.deliver(&session_stanza(
        from,
        "WF5-BOT-3",
        &[("msg", malformed_msg())],
    ))
    .await;
    assert_eq!(script.next_call().await.id(), "WF5-BOT-3");
    assert!(is_nack(&f.next_frame_for("WF5-BOT-3").await));
    assert_eq!(f.next_undecryptable().await.info.id, "WF5-BOT-3");
    assert!(
        f.seen_for("WF5-BOT-2").is_empty(),
        "the refused report sent nothing"
    );
    assert!(f.undecryptable.is_empty(), "nor published anything");

    f.deliver(&refused).await;
    let again = script.next_call().await;
    assert_eq!(again.id(), "WF5-BOT-2");
    assert_eq!(again.cause, first.cause);
    assert_eq!(f.next_undecryptable().await.info.id, "WF5-BOT-2");
    let nack = f.next_frame_for("WF5-BOT-2").await;
    assert!(is_nack(&nack), "{nack:?}");
    assert_eq!(nack.1["error"], "487");
}

/// A refused report settles the whole stanza for this delivery: a bot payload
/// beside the refused `<enc>` is neither reported nor nacked (its own failure
/// would nack the stanza, and the server would drop the refused report with
/// it). The lane's next stanza is the next to reach the hook, and its nack,
/// queued after any the refused stanza could have queued, reaches the wire
/// with nothing sent for the refused one.
#[tokio::test]
async fn refused_report_withholds_bot_payload_answer() {
    let (hook, script) = scripted(&[Step::Fail, Step::Commit, Step::Commit]);
    let f = fixture(Some(hook)).await;
    let sender = "15550002090@s.whatsapp.net";
    let refused = session_stanza(
        sender,
        "WF5-WITHHELD-1",
        &[("msg", no_session_msg()), ("msmsg", malformed_msmsg())],
    );
    f.deliver(&refused).await;
    let first = script.next_call().await;
    assert_eq!(first.id(), "WF5-WITHHELD-1");
    assert_eq!(
        first.cause,
        cause(
            EncDecryptFailureReason::NoSession,
            UndecryptableRecovery::RetryReceipt
        )
    );

    f.deliver(&session_stanza(
        sender,
        "WF5-WITHHELD-2",
        &[("msg", malformed_msg())],
    ))
    .await;
    assert_eq!(
        script.next_call().await.id(),
        "WF5-WITHHELD-2",
        "the refused stanza's bot payload reported nothing"
    );
    assert!(is_nack(&f.next_frame_for("WF5-WITHHELD-2").await));
    assert_eq!(f.next_undecryptable().await.info.id, "WF5-WITHHELD-2");
    assert!(
        f.seen_for("WF5-WITHHELD-1").is_empty(),
        "the refused stanza got no answer"
    );
    assert!(f.undecryptable.is_empty(), "and published nothing");

    // The redelivery is reported again; once committed, it is answered.
    f.deliver(&refused).await;
    let again = script.next_call().await;
    assert_eq!(again.id(), "WF5-WITHHELD-1");
    assert_eq!(again.cause, first.cause);
    assert_eq!(f.next_undecryptable().await.info.id, "WF5-WITHHELD-1");
}

/// A delivery cancelled after its `<enc>` decrypted, before the plaintext was
/// checked, reported nothing and left the plaintext with the client. When the
/// stanza comes back the replay finds the plaintext unusable and reports it
/// before the redelivery is answered. A refused report leaves the redelivery
/// unanswered and is made before the next one, which is answered as the
/// duplicate it is.
#[tokio::test]
async fn cancelled_plaintext_reported_on_replay() {
    let (hook, script) = scripted(&[Step::Fail, Step::Commit, Step::Commit]);
    let f = fixture(Some(hook)).await;
    let mut peer = Peer::new(&f.client, "15550002120@s.whatsapp.net", 9001).await;
    let from = peer.jid.to_string();
    let (kind, bytes) = peer.encrypt(UNUSABLE_PLAINTEXT).await;
    let stanza = session_stanza(&from, "WF5-REPLAY-1", &[(kind, bytes)]);

    // The first delivery stops once its plaintext is staged and is cancelled
    // there. It enters at the decrypt phase, where a test can cancel it; the
    // chat lane runs that same phase.
    let retention = &f.client.inbound_commit_batch.live_retention;
    retention.pause_stage.store(true, Ordering::Release);
    let classified = f
        .client
        .classify_incoming_message(&crate::test_utils::node_to_owned_ref(&stanza))
        .await
        .expect("a session payload to decrypt");
    let info = Arc::clone(&classified.info);
    let generation = f.client.connection_generation.load(Ordering::Acquire);
    let first =
        tokio::spawn(Arc::clone(&f.client).process_classified_message(classified, generation));
    retention.stage_ready.notified().await;
    first.abort();
    assert!(
        first
            .await
            .expect_err("the first delivery is cancelled")
            .is_cancelled()
    );
    retention.pause_stage.store(false, Ordering::Release);
    assert!(
        retention.has_raw_for_message(&info),
        "the decrypted plaintext is kept"
    );
    assert!(script.calls.is_empty(), "nothing was reported");
    f.assert_quiet("after the cancelled delivery");

    // The redelivery replays the kept plaintext: reported, refused, and the
    // redelivery left unanswered. A later stanza of the lane follows it: its
    // report comes after the replay's, and its nack after any answer the
    // redelivery could have queued.
    f.deliver(&stanza).await;
    f.deliver(&session_stanza(
        &from,
        "WF5-REPLAY-2",
        &[("msg", malformed_msg())],
    ))
    .await;
    let refused = script.next_call().await;
    assert_eq!(refused.id(), "WF5-REPLAY-1", "the replay reported first");
    assert_eq!(
        refused.cause,
        cause(
            EncDecryptFailureReason::PlaintextUnusable,
            UndecryptableRecovery::NoRequest
        )
    );
    assert_eq!(script.next_call().await.id(), "WF5-REPLAY-2");
    assert!(is_nack(&f.next_frame_for("WF5-REPLAY-2").await));
    assert_eq!(f.next_undecryptable().await.info.id, "WF5-REPLAY-2");
    assert!(
        f.seen_for("WF5-REPLAY-1").is_empty(),
        "the refused report left the redelivery unanswered"
    );
    assert!(f.undecryptable.is_empty(), "and published nothing");

    // The next delivery makes the owed report first, then is answered as the
    // duplicate it is.
    f.deliver(&stanza).await;
    let again = script.next_call().await;
    assert_eq!(again.id(), "WF5-REPLAY-1");
    assert_eq!(again.cause, refused.cause);
    assert_eq!(f.next_undecryptable().await.info.id, "WF5-REPLAY-1");
    let answer = f.next_frame_for("WF5-REPLAY-1").await;
    assert!(
        is_delivery_receipt(&answer),
        "the duplicate is answered: {answer:?}"
    );
}

/// The pending-journal row of `info`'s message, decoded: a direct or status
/// message's row is keyed by its sender as the arrival spells it.
async fn journal_row(f: &Fixture, info: &MessageInfo) -> Option<PendingJournal> {
    f.client
        .persistence_manager
        .backend()
        .get_pending_inbound(
            &info.source.chat.to_string(),
            &info.source.sender.to_string(),
            &info.id,
        )
        .await
        .expect("the pending row reads")
        .map(|bytes| PendingJournal::decode(bytes.into()).expect("the pending row decodes"))
}

/// The undecryptable report `info`'s message owes in the pending journal.
async fn owed(f: &Fixture, info: &MessageInfo) -> Option<OwedReport> {
    journal_row(f, info).await.and_then(|journal| journal.owed)
}

/// What an unusable plaintext's refused report of a stanza without
/// `decrypt-fail="hide"` owes.
const OWED_SHOWN: Option<OwedReport> = Some(OwedReport {
    decrypt_fail_mode: DecryptFailMode::Show,
});

/// Ends `f`'s client after making what a running client makes durable on its
/// own: the Signal cache's ratchet advances (the coalesced flush) and the
/// device. A client built next on the same backend stands for a restart.
async fn end_client(f: Fixture) {
    f.client
        .flush_signal_cache()
        .await
        .expect("the Signal state is flushed");
    f.client
        .persistence_manager
        .flush()
        .await
        .expect("the device is saved");
}

/// A refused report of an unusable plaintext is owed in the message's
/// pending-journal row before the hook is called, and the refusal keeps it,
/// so it outlives the client: a second client on the same store, holding the
/// first one's ratchet advance, makes the report when the stanza comes back,
/// with the same failure and before anything answers the stanza, though its
/// copy decrypts as a duplicate. The report is settled once committed.
#[tokio::test]
async fn owed_report_survives_client_restart() {
    let unusable = cause(
        EncDecryptFailureReason::PlaintextUnusable,
        UndecryptableRecovery::NoRequest,
    );
    let backend = crate::test_utils::create_test_backend().await;
    let (hook, script) = scripted(&[Step::FailWhenReleased, Step::Commit]);
    let f = fixture_on(Arc::clone(&backend), Some(hook)).await;
    let mut peer = Peer::new(&f.client, "15550002130@s.whatsapp.net", 9001).await;
    let from = peer.jid.to_string();
    let stanza = session_stanza(
        &from,
        "WF5-RESTART-1",
        &[peer.encrypt(UNUSABLE_PLAINTEXT).await],
    );
    f.deliver(&stanza).await;
    let refused = script.next_call().await;
    assert_eq!(refused.id(), "WF5-RESTART-1");
    assert_eq!(refused.cause, unusable);
    assert_eq!(
        owed(&f, &refused.info).await,
        OWED_SHOWN,
        "the report is owed before the hook answers"
    );
    f.assert_quiet("while the hook holds the report");
    script.release().await;

    // A later stanza of the peer's lane: its nack comes after anything the
    // refused one could have sent.
    f.deliver(&session_stanza(
        &from,
        "WF5-RESTART-2",
        &[("msg", malformed_msg())],
    ))
    .await;
    assert_eq!(script.next_call().await.id(), "WF5-RESTART-2");
    assert!(is_nack(&f.next_frame_for("WF5-RESTART-2").await));
    assert!(
        f.seen_for("WF5-RESTART-1").is_empty(),
        "the refused report sent nothing"
    );
    assert_eq!(
        owed(&f, &refused.info).await,
        OWED_SHOWN,
        "the refusal keeps it owed"
    );
    end_client(f).await;

    let (hook, script) = scripted(&[Step::CommitWhenReleased]);
    let f = fixture_on(backend, Some(hook)).await;
    f.deliver(&stanza).await;
    let again = script.next_call().await;
    assert_eq!(again.id(), "WF5-RESTART-1");
    assert_eq!(again.cause, unusable, "the same failure is reported");
    f.assert_quiet("while the hook commits the owed report");
    script.release().await;
    assert_eq!(f.next_undecryptable().await.info.id, "WF5-RESTART-1");
    let answer = f.next_frame_for("WF5-RESTART-1").await;
    assert!(
        is_delivery_receipt(&answer),
        "the duplicate is answered: {answer:?}"
    );
    assert_eq!(owed(&f, &again.info).await, None, "the report is settled");
    assert!(f.messages.is_empty(), "the duplicate published nothing");
}

/// [`owed_report_survives_client_restart`] with a decodable sibling in the
/// stanza: the sibling is committed and published while the stanza stays
/// unanswered, and the commit's cleanup of the message's row keeps the owed
/// report. After the restart only the report is made, then the duplicate is
/// answered; the committed sibling is not published again.
#[tokio::test]
async fn owed_report_beside_committed_sibling_survives_restart() {
    let backend = crate::test_utils::create_test_backend().await;
    let (hook, script) = scripted(&[Step::Fail, Step::Commit]);
    let f = fixture_on(Arc::clone(&backend), Some(hook)).await;
    let mut peer = Peer::new(&f.client, "15550002131@s.whatsapp.net", 9001).await;
    let from = peer.jid.to_string();
    let unusable = peer.encrypt(UNUSABLE_PLAINTEXT).await;
    let sibling = peer.encrypt_text("beside the unusable payload").await;
    let stanza = session_stanza(&from, "WF5-SIBLING-1", &[unusable, sibling]);
    f.deliver(&stanza).await;
    let refused = script.next_call().await;
    assert_eq!(refused.id(), "WF5-SIBLING-1");
    assert_eq!(script.next_commit().await, ["WF5-SIBLING-1"]);
    assert_eq!(f.next_message_text().await, "beside the unusable payload");

    f.deliver(&session_stanza(
        &from,
        "WF5-SIBLING-2",
        &[("msg", malformed_msg())],
    ))
    .await;
    assert_eq!(script.next_call().await.id(), "WF5-SIBLING-2");
    assert!(is_nack(&f.next_frame_for("WF5-SIBLING-2").await));
    assert!(
        f.seen_for("WF5-SIBLING-1").is_empty(),
        "the refused stanza stays unanswered"
    );
    let row = journal_row(&f, &refused.info)
        .await
        .expect("the message's row stays");
    assert_eq!(
        row.owed, OWED_SHOWN,
        "the committed sibling's cleanup kept the owed report"
    );
    assert!(
        row.occurrences.is_empty(),
        "and only it: the committed occurrence is gone"
    );
    end_client(f).await;

    let (hook, script) = scripted(&[Step::CommitWhenReleased]);
    let f = fixture_on(backend, Some(hook)).await;
    f.deliver(&stanza).await;
    let again = script.next_call().await;
    assert_eq!(again.id(), "WF5-SIBLING-1");
    assert_eq!(again.cause, refused.cause);
    f.assert_quiet("while the hook commits the owed report");
    script.release().await;
    assert_eq!(f.next_undecryptable().await.info.id, "WF5-SIBLING-1");
    let answer = f.next_frame_for("WF5-SIBLING-1").await;
    assert!(
        is_delivery_receipt(&answer),
        "the duplicate is answered: {answer:?}"
    );
    assert!(
        journal_row(&f, &again.info).await.is_none(),
        "the settled report took its row with it"
    );
    assert!(
        f.messages.is_empty(),
        "the committed sibling is not published again"
    );
}

/// A `status@broadcast` stanza is acked when it arrives, so no redelivery
/// would settle a report owed to it: a refused report of its unusable
/// plaintext (the `skmsg` of a status) owes nothing, neither while the hook
/// holds it nor after the hook refused it.
#[tokio::test]
async fn refused_status_report_owes_nothing() {
    let status: Jid = "status@broadcast".parse().expect("status JID");
    let (hook, script) = scripted(&[Step::FailWhenReleased, Step::Commit]);
    let f = fixture(Some(hook)).await;
    let mut peer = Peer::new(&f.client, "15550002140@s.whatsapp.net", 9001).await;
    let participant = peer.jid.to_string();
    let encs = peer.group_encs(&status, UNUSABLE_PLAINTEXT).await;
    f.deliver(&group_stanza(
        &status.to_string(),
        &participant,
        "WF5-STATUS-1",
        &encs,
    ))
    .await;
    let refused = script.next_call().await;
    assert_eq!(refused.id(), "WF5-STATUS-1");
    assert_eq!(
        refused.cause,
        cause(
            EncDecryptFailureReason::PlaintextUnusable,
            UndecryptableRecovery::NoRequest
        )
    );
    assert_eq!(
        owed(&f, &refused.info).await,
        None,
        "nothing is owed while the hook holds the report"
    );
    script.release().await;

    // The status lane's next stanza reaches the hook once the refused one was
    // handled to the end.
    f.deliver(&group_stanza(
        &status.to_string(),
        &participant,
        "WF5-STATUS-2",
        &[("pkmsg", malformed_msg())],
    ))
    .await;
    assert_eq!(script.next_call().await.id(), "WF5-STATUS-2");
    assert_eq!(
        owed(&f, &refused.info).await,
        None,
        "nor after the hook refused it"
    );
}

/// A duplicate whose message still owes an undecryptable report (refused on
/// another copy of the stanza, which a second lane holds across a reconnect)
/// is no duplicate to ack: the stanza is left unanswered, the report owed,
/// for the next delivery to make before it decrypts. Called where the
/// duplicate paths call it, since the arrival path settles an owed report
/// before it decrypts.
#[tokio::test]
async fn duplicate_owing_a_report_is_not_acked() {
    let (hook, _script) = scripted(&[]);
    let f = fixture(Some(hook)).await;
    let sender: Jid = "15550002150@s.whatsapp.net".parse().expect("sender JID");
    let info = Arc::new(MessageInfo {
        id: "WF5-OWING-DUP-1".into(),
        source: crate::types::message::MessageSource {
            chat: sender.clone(),
            sender,
            ..Default::default()
        },
        ..Default::default()
    });
    f.client
        .owe_undecryptable_report(&info, OWED_SHOWN.expect("an owed report"))
        .await
        .expect("the report is owed");
    assert!(
        !f.client.ack_or_replay_to_hook(&info).await,
        "nothing was replayed"
    );
    f.assert_quiet("after the duplicate");
    assert_eq!(owed(&f, &info).await, OWED_SHOWN, "the report stays owed");
}

/// The journal's owed report: a journal that owes nothing keeps the V4
/// encoding, so its rows stay what older builds read; one that owes a report
/// is V5 and keeps the report's decrypt-fail mode, also with no occurrence,
/// through a decode, an unchanged re-encode (its backing reused), a merge (the
/// batch's row write) and the settlement. The row holding the report alone,
/// which the batch's cleanup writes without a fallible encode, has exactly
/// the bytes `encode` writes for that journal.
#[test]
fn owed_report_journal_encoding() {
    let hide = OwedReport {
        decrypt_fail_mode: DecryptFailMode::Hide,
    };
    let occurrence = |text: &'static [u8]| Occurrence {
        producer: None,
        index: Some(0),
        original: bytes::Bytes::from_static(text),
        projection: bytes::Bytes::from_static(text),
    };

    let mut plain = PendingJournal::default();
    plain
        .merge(occurrence(b"sibling"))
        .expect("an occurrence joins");
    let plain = plain.encode().expect("a journal encodes");
    assert!(plain.starts_with(b"\0WRPD\x04"), "nothing owed: V4");
    let mut owing = PendingJournal::decode(plain).expect("V4 decodes");
    assert_eq!(owing.owed, None);
    owing.owed = Some(hide);
    let owing = owing.encode().expect("an owed report encodes");
    assert!(owing.starts_with(b"\0WRPD\x05"), "a report owed: V5");
    let decoded = PendingJournal::decode(owing).expect("V5 decodes");
    assert_eq!(decoded.owed, Some(hide));
    assert_eq!(decoded.occurrences.len(), 1);

    let alone = PendingJournal::owing_bytes(hide);
    assert_eq!(
        alone.len(),
        6 + 16 + 1 + 4,
        "version, generation, report, count"
    );
    assert!(alone.starts_with(b"\0WRPD\x05"));
    assert_eq!(alone[22], 1, "the report's decrypt-fail mode: hide");
    assert_eq!(alone[23..], [0; 4], "no occurrence");
    let mut decoded = PendingJournal::decode(alone.clone()).expect("it decodes");
    assert_eq!(decoded.owed, Some(hide));
    assert!(decoded.occurrences.is_empty());
    assert_eq!(
        decoded.encode().expect("re-encodes").as_ptr(),
        alone.as_ptr(),
        "unchanged, its backing is reused"
    );
    // A mode changed and changed back makes `encode` write the row afresh
    // under the same generation: the very bytes `owing_bytes` wrote.
    let mut show = PendingJournal::decode(alone.clone()).expect("decodes");
    show.owed = Some(OwedReport {
        decrypt_fail_mode: DecryptFailMode::Show,
    });
    let show = show.encode().expect("an owed report alone encodes");
    assert_ne!(show, alone, "the mode's byte is rewritten");
    let mut back = PendingJournal::decode(show).expect("decodes");
    back.owed = Some(hide);
    assert_eq!(
        back.encode().expect("an owed report alone encodes"),
        alone,
        "`owing_bytes` writes what `encode` writes"
    );
    decoded
        .merge(occurrence(b"sibling"))
        .expect("a sibling joins the row");
    let mut merged = PendingJournal::decode(decoded.encode().expect("encodes")).expect("decodes");
    assert_eq!(merged.owed, Some(hide), "a row write keeps the owed report");
    assert_eq!(merged.occurrences.len(), 1);
    merged.owed = None;
    let settled = merged.encode().expect("a settled journal encodes");
    assert!(settled.starts_with(b"\0WRPD\x04"), "settled: V4 again");
    assert_eq!(PendingJournal::decode(settled).expect("decodes").owed, None);

    // Only an owed report stands alone, its mode byte is checked, and a
    // truncated row is refused.
    let mut empty = alone.to_vec();
    empty[5] = 4;
    empty.remove(22);
    assert!(
        PendingJournal::decode(empty.into()).is_err(),
        "V4, nothing in it"
    );
    let mut mode = alone.to_vec();
    mode[22] = 2;
    assert!(PendingJournal::decode(mode.into()).is_err(), "no such mode");
    for end in 1..alone.len() {
        assert!(PendingJournal::decode(alone.slice(..end)).is_err());
    }
}

/// The dispatch-once claim is taken only after the hook returned `Ok`: a
/// refused report leaves none, so the next delivery reaches the hook again,
/// and while that call commits there is still no claim, no event and no nack.
#[tokio::test]
async fn dedup_claim_after_hook_ok() {
    let (hook, script) = scripted(&[Step::Fail, Step::CommitWhenReleased, Step::Commit]);
    let f = fixture(Some(hook)).await;
    let sender = "15550002040@s.whatsapp.net";
    let stanza = session_stanza(sender, "WF5-CLAIM-1", &[("msg", malformed_msg())]);
    f.deliver(&stanza).await;
    let refused = script.next_call().await;
    assert_eq!(refused.id(), "WF5-CLAIM-1");
    assert_eq!(
        refused.cause,
        cause(
            EncDecryptFailureReason::MalformedCiphertext,
            UndecryptableRecovery::NoRequest
        )
    );

    f.deliver(&stanza).await;
    let held = script.next_call().await;
    assert_eq!(held.id(), "WF5-CLAIM-1", "the refused report is made again");
    assert!(
        !f.claimed(&held.info).await,
        "no claim while the hook commits"
    );
    assert!(f.undecryptable.is_empty());

    script.release().await;
    assert_eq!(f.next_undecryptable().await.info.id, "WF5-CLAIM-1");
    assert!(
        f.claimed(&held.info).await,
        "claimed once the hook committed"
    );
    let nack = f.next_frame_for("WF5-CLAIM-1").await;
    assert!(is_nack(&nack), "{nack:?}");
    assert_eq!(nack.1["error"], "487", "ParsingError");

    // A later stanza of the lane, nacked after any nack the refused delivery
    // could have queued.
    f.deliver(&session_stanza(
        sender,
        "WF5-CLAIM-2",
        &[("msg", malformed_msg())],
    ))
    .await;
    assert_eq!(script.next_call().await.id(), "WF5-CLAIM-2");
    assert!(is_nack(&f.next_frame_for("WF5-CLAIM-2").await));
    assert_eq!(
        f.seen_for("WF5-CLAIM-1").len(),
        1,
        "only the committed delivery was nacked"
    );
}

/// Dedup is unchanged: one event per message, and with a hook one commit per
/// message within the window, while every delivery is still answered. A
/// redelivery after a committed report doesn't reach the hook (the next
/// stanza of the lane does).
#[tokio::test]
async fn undecryptable_dedup_unchanged() {
    let (hook, script) = scripted(&[Step::Commit, Step::Commit]);
    let f = fixture(Some(hook)).await;
    let sender = "15550002050@s.whatsapp.net";
    let stanza = session_stanza(sender, "WF5-DEDUP-1", &[("msg", malformed_msg())]);
    f.deliver(&stanza).await;
    assert_eq!(script.next_call().await.id(), "WF5-DEDUP-1");
    assert_eq!(f.next_undecryptable().await.info.id, "WF5-DEDUP-1");
    assert!(is_nack(&f.next_frame_for("WF5-DEDUP-1").await));

    f.deliver(&stanza).await;
    assert!(
        is_nack(&f.next_frame_for("WF5-DEDUP-1").await),
        "the redelivery is still answered"
    );
    f.deliver(&session_stanza(
        sender,
        "WF5-DEDUP-2",
        &[("msg", malformed_msg())],
    ))
    .await;
    assert_eq!(
        script.next_call().await.id(),
        "WF5-DEDUP-2",
        "the committed message did not reach the hook again"
    );
    assert_eq!(f.next_undecryptable().await.info.id, "WF5-DEDUP-2");
    assert!(
        f.undecryptable.is_empty(),
        "one event for the redelivered message"
    );

    // Without a hook: one event, every delivery answered.
    let f = fixture(None).await;
    let stanza = session_stanza(sender, "WF5-DEDUP-3", &[("msg", malformed_msg())]);
    f.deliver(&stanza).await;
    assert_eq!(f.next_undecryptable().await.info.id, "WF5-DEDUP-3");
    assert!(is_nack(&f.next_frame_for("WF5-DEDUP-3").await));
    f.deliver(&stanza).await;
    assert!(is_nack(&f.next_frame_for("WF5-DEDUP-3").await));
    f.deliver(&session_stanza(
        sender,
        "WF5-DEDUP-4",
        &[("msg", malformed_msg())],
    ))
    .await;
    assert_eq!(f.next_undecryptable().await.info.id, "WF5-DEDUP-4");
    assert!(f.undecryptable.is_empty());
}

/// The `MessageInfo` of message `id` from the 1:1 `sender`, for reports made
/// directly through `dispatch_undecryptable_event`.
fn direct_info(sender: &str, id: &str) -> Arc<MessageInfo> {
    Arc::new(MessageInfo {
        id: id.into(),
        source: crate::types::message::MessageSource {
            sender: sender.parse().expect("sender JID"),
            chat: sender.parse().expect("chat JID"),
            ..Default::default()
        },
        ..Default::default()
    })
}

/// Concurrent reports of one message (in production, the previous
/// connection's copy still in the hook and the redelivery on the new
/// connection) make one hook call at a time. Copies that wait behind a call
/// that commits are answered from its claim without a call of their own, and
/// one event follows; a copy that waits behind a refusal makes its own report.
#[tokio::test]
async fn concurrent_reports_share_one_hook_call() {
    let sender = "15550002055@s.whatsapp.net";
    let no_session = || {
        cause(
            EncDecryptFailureReason::NoSession,
            UndecryptableRecovery::RetryReceipt,
        )
    };

    // Sixteen copies behind one held commit: one call, one claim, one event.
    let (hook, script) = scripted(&[Step::CommitWhenReleased]);
    let f = fixture(Some(hook)).await;
    let info = direct_info(sender, "WF5-DEDUP-5");
    let (reports, ()) = futures::join!(
        futures::future::join_all((0..16).map(|_| {
            f.client
                .dispatch_undecryptable_event(Arc::clone(&info), no_session())
        })),
        async {
            assert_eq!(script.next_call().await.id(), "WF5-DEDUP-5");
            assert!(
                script.calls.is_empty(),
                "the other copies wait for the call in flight"
            );
            script.release().await;
        },
    );
    assert_eq!(
        reports.iter().filter(|report| **report == Ok(true)).count(),
        1,
        "{reports:?}"
    );
    assert!(reports.iter().all(Result::is_ok), "{reports:?}");
    assert!(script.calls.is_empty(), "one hook call for the message");
    assert_eq!(f.next_undecryptable().await.info.id, "WF5-DEDUP-5");
    assert!(f.undecryptable.is_empty());

    // A copy waiting behind a refusal makes its own report, which commits.
    let (hook, script) = scripted(&[Step::FailWhenReleased, Step::Commit]);
    let f = fixture(Some(hook)).await;
    let info = direct_info(sender, "WF5-DEDUP-6");
    let (refused, committed, ()) = futures::join!(
        f.client
            .dispatch_undecryptable_event(Arc::clone(&info), no_session()),
        f.client
            .dispatch_undecryptable_event(Arc::clone(&info), no_session()),
        async {
            assert_eq!(script.next_call().await.id(), "WF5-DEDUP-6");
            assert!(
                script.calls.is_empty(),
                "the second copy waits for the call in flight"
            );
            script.release().await;
        },
    );
    assert_eq!(refused, Err(super::HookRefused));
    assert_eq!(committed, Ok(true), "the waiter made its own report");
    assert_eq!(script.next_call().await.id(), "WF5-DEDUP-6");
    assert!(script.calls.is_empty(), "two calls, one per copy");
    assert_eq!(f.next_undecryptable().await.info.id, "WF5-DEDUP-6");
    assert!(f.undecryptable.is_empty());
}

/// Reports whether Signal maintenance refused inside the hook, then commits.
struct MaintenanceProbe(async_channel::Sender<bool>);

#[async_trait::async_trait]
impl InboundDurabilityHook for MaintenanceProbe {
    async fn on_messages(
        &self,
        _client: Arc<Client>,
        _batch: &[InboundMessage],
    ) -> anyhow::Result<()> {
        Ok(())
    }

    async fn on_undecryptable(
        &self,
        client: Arc<Client>,
        _info: &MessageInfo,
        _cause: UndecryptableCause,
    ) -> anyhow::Result<()> {
        let refused = client.ensure_signal_maintenance_context().is_err();
        self.0
            .try_send(refused)
            .expect("the test holds the probe receiver");
        Ok(())
    }
}

/// The report runs under the inbound hooks' marker, so Signal maintenance
/// refuses inside it; the marker is gone once the hook's poll returns.
#[tokio::test]
async fn undecryptable_hook_refuses_signal_maintenance() {
    let (probe_tx, probe) = async_channel::unbounded();
    let f = fixture(Some(Arc::new(MaintenanceProbe(probe_tx)))).await;
    f.deliver(&session_stanza(
        "15550002060@s.whatsapp.net",
        "WF5-MAINT-1",
        &[("msg", malformed_msg())],
    ))
    .await;
    assert!(
        probe.recv().await.expect("the hook ran"),
        "Signal maintenance must refuse inside on_undecryptable"
    );
    assert!(is_nack(&f.next_frame_for("WF5-MAINT-1").await));
    // `#[tokio::test]` runs the lane on this thread, so a marker left set
    // would refuse here too.
    f.client
        .ensure_signal_maintenance_context()
        .expect("the marker is cleared once the hook's poll returns");
}

/// Commits decrypted messages and leaves `on_undecryptable` to its default.
struct MessagesOnly;

#[async_trait::async_trait]
impl InboundDurabilityHook for MessagesOnly {
    async fn on_messages(
        &self,
        _client: Arc<Client>,
        _batch: &[InboundMessage],
    ) -> anyhow::Result<()> {
        Ok(())
    }
}

/// A hook that doesn't implement `on_undecryptable` answers undecryptable
/// stanzas as a client without a hook does: the event, the retry receipt,
/// the ack.
#[tokio::test]
async fn undecryptable_default_hook_answers_as_without_hook() {
    let f = fixture(Some(Arc::new(MessagesOnly))).await;
    f.deliver(&session_stanza(
        "15550002070@s.whatsapp.net",
        "WF5-DEFAULT-1",
        &[("msg", no_session_msg())],
    ))
    .await;
    assert_eq!(f.next_undecryptable().await.info.id, "WF5-DEFAULT-1");
    assert!(is_retry_receipt(&f.next_frame_for("WF5-DEFAULT-1").await));
    assert!(is_ack(&f.next_frame_for("WF5-DEFAULT-1").await));
}
