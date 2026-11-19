//! WF2: a message the primary phone recovers (a PDO placeholder resend) is
//! committed through the inbound durability hook before it is claimed and
//! published; a refusal publishes nothing, claims nothing and fails the phone's
//! reply, whose redelivery retries the commit, without asking the phone again.
//! The recovery is the consumer projection an ordinary delivery gets: its
//! secret captured and in its context, a secret-encrypted add-on resolved.
//!
//! The client is connected over a capturing transport with an encrypting
//! session to its own phone, so the requests to the phone are real stanzas.
//! A request goes out through `send_pdo_placeholder_resend_request`, the phone's
//! reply comes in through `handle_pdo_response`, the entry the decrypted reply
//! reaches (a redelivery of the reply enters there again, as its replay does),
//! and a sender's own resend through `handle_decrypted_plaintext`. What the
//! refusal does to the reply's own stanza, its ack and its replay, is tested
//! end to end in `message::tests` (`pdo_refused_recovery_fails_its_reply`).
//! Every wait is on an event: a hook call, a published batch, a sent frame or
//! the outbound flush scope going idle.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};

use crate::client::Client;
use crate::transport::mock::CapturingMockTransport;
use crate::types::durability_hook::{InboundDurabilityHook, InboundMessage};
use crate::types::message::MessageInfo;
use wacore::messages::MessageUtils;
use wacore::proto_helpers::MessageBuilderExt as _;
use wacore::store::commands::DeviceCommand;
use wacore::types::events::{
    Event, EventHandler, EventInterest, EventKind, MessageBatch, Subscription,
};
use wacore::types::message::{ChatMessageId, MessageSource};
use wacore_binary::Jid;
use waproto::whatsapp as wa;

/// The local device, a companion of the account the phone (device 0) is the
/// primary of.
fn own_device() -> Jid {
    Jid::pn_device("15550000001", 3)
}

/// The primary phone, which every request goes to and every reply comes from.
fn phone() -> Jid {
    own_device().to_non_ad()
}

/// What the hook does with one call, in call order.
enum Step {
    Commit,
    /// Commit once the test releases it, holding the recovery mid-commit.
    CommitWhenReleased,
    Fail,
}

/// Reports each call's items, then does what the script says. A call the test
/// did not script fails, so it is reported and visible, never hidden.
struct ScriptedHook {
    steps: Mutex<VecDeque<Step>>,
    calls: async_channel::Sender<Vec<InboundMessage>>,
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
            .try_send(batch.to_vec())
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
    async_channel::Receiver<Vec<InboundMessage>>,
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

/// A connected client with a session to its phone, its published batches and
/// sent frames forwarded as events.
struct Fixture {
    client: Arc<Client>,
    transport: Arc<CapturingMockTransport>,
    batches: async_channel::Receiver<Arc<Event>>,
    frames: async_channel::Receiver<Arc<Event>>,
    _subscriptions: [Subscription; 2],
    _frame_forwarding: crate::SentFrameLease,
}

async fn fixture(hook: Option<Arc<dyn InboundDurabilityHook>>) -> Fixture {
    let (client, transport) = crate::test_utils::create_iq_test_client().await;
    client
        .persistence_manager
        .process_command(DeviceCommand::SetId(Some(own_device())))
        .await;
    client
        .persistence_manager
        .process_command(DeviceCommand::SetAccount(Some(
            wa::ADVSignedDeviceIdentity::default(),
        )))
        .await;
    crate::test_utils::seed_peer_session(&client, &phone()).await;
    if let Some(hook) = hook {
        assert!(
            client.inbound_durability_hook.set(hook).is_ok(),
            "the fixture registers the only hook"
        );
    }

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

    /// The next frame must be a request to the phone: its stanza id, which the
    /// phone's reply names as its `stanza_id`.
    async fn next_request(&self) -> String {
        let (tag, attrs) = self.next_frame().await;
        assert_eq!(tag, "message", "a request to the phone is a message");
        assert_eq!(
            attrs["category"], "peer",
            "a request to the phone is a peer message"
        );
        assert_eq!(
            attrs["to"],
            phone().to_string(),
            "requests go to the primary phone"
        );
        attrs["id"].clone()
    }

    /// Ask the phone for `info`'s content, as a decrypt failure does: the
    /// request's id.
    async fn ask_phone(&self, info: &Arc<MessageInfo>) -> String {
        self.client
            .send_pdo_placeholder_resend_request(info)
            .await
            .expect("the request goes out");
        self.next_request().await
    }

    /// The phone answers `request_id` with `text` as `info`'s content: whether
    /// the reply may go on to its own commit (`false`: the hook refused the
    /// recovery).
    async fn phone_replies(&self, request_id: &str, info: &MessageInfo, text: &str) -> bool {
        self.client
            .handle_pdo_response(&phone_reply(request_id, info, text), &phone_reply_info())
            .await
    }

    /// The request for `info` the client holds open, if any.
    async fn pending_request(&self, info: &MessageInfo) -> Option<String> {
        self.client
            .pdo_pending_requests
            .get(&ChatMessageId::new(
                info.source.chat.clone(),
                info.id.clone(),
            ))
            .await
            .map(|(_, memo)| memo.request_id.clone())
    }

    /// Wait until every send spawned on the outbound flush scope has finished.
    async fn outbound_idle(&self) {
        assert!(
            matches!(
                self.client
                    .outbound_flush
                    .flush(&*self.client.runtime, std::time::Duration::from_secs(30))
                    .await,
                crate::flush_scope::DrainOutcome::Completed
            ),
            "the spawned sends finish"
        );
    }
}

/// A direct message from a contact that this device failed to decrypt: the
/// `info` its request is made with, and that its recovery is published under.
fn undecryptable(id: &str) -> Arc<MessageInfo> {
    let contact = Jid::pn("15550000002");
    Arc::new(MessageInfo {
        id: id.into(),
        source: MessageSource {
            chat: contact.clone(),
            sender: contact,
            ..Default::default()
        },
        ..Default::default()
    })
}

/// The `MessageInfo` of the decrypted stanza that carried the phone's reply.
fn phone_reply_info() -> MessageInfo {
    MessageInfo {
        id: "PHONE-REPLY".into(),
        source: MessageSource {
            chat: phone(),
            sender: phone(),
            is_from_me: true,
            ..Default::default()
        },
        ..Default::default()
    }
}

/// The phone's answer to `request_id`: `info`'s message, with `text` as its
/// content, as the phone stores it.
fn phone_reply(
    request_id: &str,
    info: &MessageInfo,
    text: &str,
) -> wa::message::PeerDataOperationRequestResponseMessage {
    phone_reply_with(request_id, info, wa::Message::text(text), None)
}

/// The phone's answer to `request_id` with `message` as `info`'s content, and
/// `secret` as the message's secret on the reply's `WebMessageInfo`, beside
/// the message, where the phone's stored copies can keep it.
// The test encodes the reply's `WebMessageInfo` as the phone does; waproto's
// pinned codec wrappers have no encoder for it.
#[allow(clippy::disallowed_methods)]
fn phone_reply_with(
    request_id: &str,
    info: &MessageInfo,
    message: wa::Message,
    secret: Option<&[u8; 32]>,
) -> wa::message::PeerDataOperationRequestResponseMessage {
    use buffa::Message as _;
    use wa::message::peer_data_operation_request_response_message as response;

    let mut key = wa::MessageKey::default();
    key.remote_jid = Some(info.source.chat.to_string());
    key.from_me = Some(info.source.is_from_me);
    key.id = Some(info.id.to_string());
    let mut web = wa::WebMessageInfo::default();
    web.key = buffa::MessageField::some(key);
    web.message = buffa::MessageField::some(message);
    web.message_secret = secret.map(|secret| secret.to_vec());
    let mut resend =
        response::peer_data_operation_result::PlaceholderMessageResendResponse::default();
    resend.web_message_info_bytes = Some(web.encode_to_vec());
    let mut result = response::PeerDataOperationResult::default();
    result.placeholder_message_resend_response = buffa::MessageField::some(resend);
    let mut reply = wa::message::PeerDataOperationRequestResponseMessage::default();
    reply.stanza_id = Some(request_id.into());
    reply.peer_data_operation_result = vec![result];
    reply
}

async fn next_call(calls: &async_channel::Receiver<Vec<InboundMessage>>) -> Vec<InboundMessage> {
    calls.recv().await.expect("the hook stays registered")
}

fn text_of(item: &InboundMessage) -> Option<&str> {
    item.message.conversation.as_deref()
}

/// The secret in the item's `messageContextInfo`, where consumers read it.
fn secret_of(item: &InboundMessage) -> Option<&[u8]> {
    item.message
        .message_context_info
        .as_option()
        .and_then(|context| context.message_secret.as_deref())
}

/// A poll creation, with `secret` in its context as its author sends it: the
/// key its votes and other add-ons are encrypted with.
fn poll_creation(question: &str, secret: Option<&[u8; 32]>) -> wa::Message {
    let mut poll = wa::message::PollCreationMessage::default();
    poll.name = Some(question.into());
    let mut message = wa::Message::default();
    message.poll_creation_message_v3 = buffa::MessageField::some(poll);
    if let Some(secret) = secret {
        let mut context = wa::MessageContextInfo::default();
        context.message_secret = Some(secret.to_vec());
        message.message_context_info = buffa::MessageField::some(context);
    }
    message
}

/// `info`'s sender reacting with `text` to its own message `parent_id` in an
/// `encReactionMessage`, encrypted with that message's `secret`.
fn encrypted_reaction(
    info: &MessageInfo,
    parent_id: &str,
    secret: &[u8; 32],
    text: &str,
) -> wa::Message {
    let author = info.source.sender.to_non_ad_string();
    let (payload, iv) = wacore::reaction::encrypt_reaction_with_secret(
        text,
        1_700_000_000_000,
        secret,
        parent_id,
        &author,
        &author,
    )
    .expect("the reaction encrypts");
    let mut target = wa::MessageKey::default();
    target.remote_jid = Some(info.source.chat.to_string());
    target.from_me = Some(false);
    target.id = Some(parent_id.into());
    let mut envelope = wa::message::EncReactionMessage::default();
    envelope.target_message_key = buffa::MessageField::some(target);
    envelope.enc_payload = Some(payload);
    envelope.enc_iv = Some(iv.to_vec());
    let mut message = wa::Message::default();
    message.enc_reaction_message = buffa::MessageField::some(envelope);
    message
}

/// While the hook commits the recovery, nothing is published and nothing is
/// claimed. Once it commits, the very items it committed are published as
/// committed, the claim is taken, and the phone is not asked again.
#[tokio::test]
async fn pdo_recovery_commits_before_dispatch() {
    let (hook, calls, release) = scripted([Step::CommitWhenReleased]);
    let f = fixture(Some(hook)).await;
    let info = undecryptable("PDO-COMMIT-1");
    let request_id = f.ask_phone(&info).await;

    let reply = phone_reply(&request_id, &info, "recovered");
    let client = Arc::clone(&f.client);
    let replied = tokio::spawn(async move {
        let carrier = phone_reply_info();
        client.handle_pdo_response(&reply, &carrier).await
    });
    let committed = next_call(&calls).await;
    assert_eq!(committed.len(), 1, "the recovery is committed alone");
    assert_eq!(committed[0].info.id, info.id);
    assert_eq!(committed[0].info.source.sender, info.source.sender);
    assert_eq!(text_of(&committed[0]), Some("recovered"));
    assert_eq!(
        committed[0].info.unavailable_request_id.as_deref(),
        Some(request_id.as_str()),
        "the hook sees which request the recovery answers"
    );
    assert!(
        f.batches.is_empty(),
        "nothing is published while the hook commits"
    );
    assert!(
        !f.client.message_already_dispatched(&info).await,
        "nothing is claimed while the hook commits"
    );

    release.send(()).await.expect("the hook holds the commit");
    assert!(
        replied.await.expect("the reply is handled"),
        "a committed recovery lets its reply go on to its own commit"
    );
    let batch = f.next_batch().await;
    assert_eq!(batch.messages.len(), 1);
    assert!(batch.hook_committed, "the hook committed this batch");
    assert!(
        Arc::ptr_eq(&batch.messages[0].message, &committed[0].message),
        "the event carries the items the hook committed"
    );
    assert_eq!(
        batch.messages[0].info.unavailable_request_id.as_deref(),
        Some(request_id.as_str())
    );
    assert!(f.client.message_already_dispatched(&info).await);
    assert_eq!(
        f.client.outbound_flush.pending(),
        0,
        "nothing is being sent"
    );
    assert_eq!(
        f.transport.sent_count(),
        1,
        "the phone was asked once: a committed recovery is not asked for again"
    );
}

/// A hook error publishes nothing and leaves no claim, so nothing suppresses a
/// later copy. It fails the phone's reply rather than asking the phone again:
/// the request stays pending, and the reply's redelivery retries the commit
/// under the `MessageInfo` of the stanza that failed to decrypt, then publishes
/// the recovery.
#[tokio::test]
async fn pdo_hook_error_releases_claim_and_retries() {
    let (hook, calls, _release) = scripted([Step::Fail, Step::Commit]);
    let f = fixture(Some(hook)).await;
    // Caught up offline: an `info` rebuilt from the reply would say live.
    let info = Arc::new(MessageInfo {
        is_offline: true,
        ..(*undecryptable("PDO-REFUSED-1")).clone()
    });
    let request_id = f.ask_phone(&info).await;

    assert!(
        !f.phone_replies(&request_id, &info, "recovered").await,
        "the refusal fails the reply that carries the recovery"
    );
    let call = next_call(&calls).await;
    assert_eq!(text_of(&call[0]), Some("recovered"));
    assert!(f.batches.is_empty(), "a refused recovery is not published");
    assert!(
        !f.client.message_already_dispatched(&info).await,
        "a refused recovery leaves no claim"
    );
    assert_eq!(
        f.pending_request(&info).await.as_deref(),
        Some(request_id.as_str()),
        "the request stays pending for the reply's redelivery"
    );
    assert_eq!(
        f.client.outbound_flush.pending(),
        0,
        "nothing is being sent"
    );
    assert_eq!(f.transport.sent_count(), 1, "the phone is not asked again");

    // The server redelivers the reply: the recovery's commit is retried.
    assert!(f.phone_replies(&request_id, &info, "recovered").await);
    let call = next_call(&calls).await;
    assert_eq!(
        call[0].info.unavailable_request_id.as_deref(),
        Some(request_id.as_str())
    );
    assert!(
        call[0].info.is_offline,
        "the retry keeps the MessageInfo of the stanza that failed to decrypt"
    );
    let batch = f.next_batch().await;
    assert!(batch.hook_committed);
    assert_eq!(text_of(&batch.messages[0]), Some("recovered"));
    assert!(Arc::ptr_eq(&batch.messages[0].info, &call[0].info));
    assert!(f.client.message_already_dispatched(&info).await);
    assert_eq!(
        f.pending_request(&info).await,
        None,
        "the committed recovery answered its request"
    );
    assert_eq!(
        f.transport.sent_count(),
        1,
        "the phone was asked once in all"
    );
}

/// A hook that keeps refusing costs the phone nothing: every redelivery of the
/// reply retries the commit and is refused again, and the phone is never asked
/// again, so the refusals are paced by the reply's redeliveries alone.
#[tokio::test]
async fn pdo_hook_refusing_repeatedly_asks_phone_nothing() {
    let (hook, calls, _release) = scripted([Step::Fail, Step::Fail, Step::Fail]);
    let f = fixture(Some(hook)).await;
    let info = undecryptable("PDO-REFUSED-AGAIN-1");
    let request_id = f.ask_phone(&info).await;

    for delivery in 1..=3 {
        assert!(
            !f.phone_replies(&request_id, &info, "recovered").await,
            "delivery {delivery} of the reply is refused"
        );
        assert_eq!(
            next_call(&calls).await[0]
                .info
                .unavailable_request_id
                .as_deref(),
            Some(request_id.as_str()),
            "delivery {delivery} retries the recovery's commit"
        );
        assert_eq!(
            f.pending_request(&info).await.as_deref(),
            Some(request_id.as_str()),
            "the request stays pending after delivery {delivery}"
        );
    }
    assert!(calls.is_empty(), "one hook call per delivery");
    assert!(f.batches.is_empty(), "nothing refused is published");
    assert!(!f.client.message_already_dispatched(&info).await);
    f.outbound_idle().await;
    assert_eq!(
        f.transport.sent_count(),
        1,
        "the phone was asked once: refusals send it nothing"
    );
}

/// Without a hook nothing changes: the recovery is published as committed by
/// no hook, and claimed.
#[tokio::test]
async fn pdo_recovery_without_hook_unchanged() {
    let f = fixture(None).await;
    let info = undecryptable("PDO-PLAIN-1");
    let request_id = f.ask_phone(&info).await;

    f.phone_replies(&request_id, &info, "recovered").await;
    let batch = f.next_batch().await;
    assert!(!batch.hook_committed, "no hook is registered");
    assert_eq!(text_of(&batch.messages[0]), Some("recovered"));
    assert_eq!(
        batch.messages[0].info.unavailable_request_id.as_deref(),
        Some(request_id.as_str())
    );
    assert!(f.client.message_already_dispatched(&info).await);
}

/// The sender's own resend of a recovery the hook committed is a duplicate:
/// it reaches neither the hook nor the bus again.
#[tokio::test]
async fn pdo_committed_recovery_not_recommitted() {
    let (hook, calls, _release) = scripted([Step::Commit]);
    let f = fixture(Some(hook)).await;
    let info = undecryptable("PDO-THEN-RESEND-1");
    let request_id = f.ask_phone(&info).await;
    f.phone_replies(&request_id, &info, "recovered").await;
    assert_eq!(text_of(&next_call(&calls).await[0]), Some("recovered"));
    assert!(f.next_batch().await.hook_committed);

    f.client
        .handle_decrypted_plaintext(
            "msg",
            MessageUtils::encode_and_pad(&wa::Message::text("recovered")),
            2,
            0,
            Default::default(),
            &info,
        )
        .await
        .expect("the resend is handled");
    assert!(
        calls.is_empty(),
        "the hook already holds this payload from the recovery"
    );
    assert!(f.batches.is_empty(), "the resend is not published again");
}

/// The phone's reply for a message its sender has already resent, committed
/// and published is a duplicate: it reaches neither the hook nor the bus.
#[tokio::test]
async fn pdo_recovery_of_published_message_not_recommitted() {
    let (hook, calls, _release) = scripted([Step::Commit]);
    let f = fixture(Some(hook)).await;
    let info = undecryptable("RESEND-THEN-PDO-1");
    let request_id = f.ask_phone(&info).await;
    f.client
        .handle_decrypted_plaintext(
            "msg",
            MessageUtils::encode_and_pad(&wa::Message::text("delivered")),
            2,
            0,
            Default::default(),
            &info,
        )
        .await
        .expect("the resend is handled");
    assert_eq!(text_of(&next_call(&calls).await[0]), Some("delivered"));
    assert!(f.next_batch().await.hook_committed);
    // The resend's own answers (its ack and receipt) are sent by then.
    f.outbound_idle().await;
    let sent = f.transport.sent_count();

    f.phone_replies(&request_id, &info, "delivered").await;
    assert!(calls.is_empty(), "the hook already holds this payload");
    assert!(f.batches.is_empty(), "the recovery is not published again");
    f.outbound_idle().await;
    assert_eq!(
        f.transport.sent_count(),
        sent,
        "a duplicate recovery asks the phone for nothing"
    );
}

/// Only a payload the hook committed spares a recovery the hook. A live claim
/// of the same payload that no commit preceded (what a producer claiming
/// before or without the hook would leave; none here does) doesn't: the
/// recovery is committed, and admission then suppresses its publication as a
/// duplicate of that claim.
#[tokio::test]
async fn pdo_recovery_of_payload_claimed_without_commit_is_committed() {
    let (hook, calls, _release) = scripted([Step::Commit]);
    let f = fixture(Some(hook)).await;
    let info = undecryptable("CLAIMED-THEN-PDO-1");
    let request_id = f.ask_phone(&info).await;
    f.client
        .mark_message_dispatched(&info, &wa::Message::text("claimed"))
        .await;

    assert!(f.phone_replies(&request_id, &info, "claimed").await);
    // The hook runs inline in the reply's handling, so its call is in by now.
    let call = calls
        .try_recv()
        .expect("the recovery is committed: the hook never committed the claimed payload");
    assert_eq!(text_of(&call[0]), Some("claimed"));
    assert_eq!(
        call[0].info.unavailable_request_id.as_deref(),
        Some(request_id.as_str())
    );
    assert!(
        f.batches.is_empty(),
        "admission suppresses the recovery's event: the claim stands for a published copy"
    );
    assert_eq!(
        f.client.stats().messages_suppressed_duplicate,
        1,
        "the recovery's publication is a suppressed duplicate"
    );
}

/// A copy the offline drain holds in its batch while the phone's recovery of
/// the same payload commits is the consumer's already when the batch commits:
/// it reaches neither the hook nor the bus, and is counted once as a
/// suppressed duplicate.
#[tokio::test]
async fn pdo_recovery_committed_while_copy_waits_in_drain() {
    let (hook, calls, _release) = scripted([Step::Commit]);
    let f = fixture(Some(hook)).await;
    let info = undecryptable("QUEUED-THEN-PDO-1");
    let request_id = f.ask_phone(&info).await;
    // The batcher accumulates again: the copy below waits for the drain's
    // flush, which this test runs itself.
    f.client.enter_drain_mode_for_tests();
    f.client
        .handle_decrypted_plaintext(
            "msg",
            MessageUtils::encode_and_pad(&wa::Message::text("caught up")),
            2,
            0,
            Default::default(),
            &info,
        )
        .await
        .expect("the copy is handled");
    assert!(calls.is_empty(), "the copy waits in the drain's batch");

    f.phone_replies(&request_id, &info, "caught up").await;
    let call = next_call(&calls).await;
    assert_eq!(
        call[0].info.unavailable_request_id.as_deref(),
        Some(request_id.as_str()),
        "the recovery commits first"
    );
    assert!(f.next_batch().await.hook_committed);
    assert_eq!(
        f.client.stats().messages_suppressed_duplicate,
        0,
        "the recovery is the first copy published, and the waiting one is not suppressed yet"
    );

    assert!(
        f.client
            .flush_inbound_commits_under_permit(true, None, None)
            .await,
        "the drain's batch commits"
    );
    assert!(
        calls.is_empty(),
        "the hook already holds the waiting copy's payload"
    );
    assert!(f.batches.is_empty(), "the waiting copy is not published");
    assert_eq!(
        f.client.stats().messages_suppressed_duplicate,
        1,
        "the waiting copy is a suppression like any other, counted once"
    );
}

/// A recovered message's secret is captured as an ordinary delivery's is, so
/// the votes and add-ons that name the message can be decrypted, and the
/// hook's item carries it in `messageContextInfo`: both when the phone sends
/// it there and when it sends it only beside the message, on the reply's
/// `WebMessageInfo`. A refused recovery has it too, and the redelivery that
/// commits it captures the same secret again.
#[tokio::test]
async fn pdo_recovery_captures_its_message_secret() {
    let (hook, calls, _release) = scripted([Step::Commit, Step::Fail, Step::Commit]);
    let f = fixture(Some(hook)).await;
    for (id, secret, beside) in [
        ("PDO-POLL-IN-CONTEXT-1", [0x31; 32], false),
        ("PDO-POLL-BESIDE-1", [0x32; 32], true),
    ] {
        let info = undecryptable(id);
        let request_id = f.ask_phone(&info).await;
        let poll = poll_creation("Lunch?", (!beside).then_some(&secret));
        let reply = phone_reply_with(&request_id, &info, poll, beside.then_some(&secret));
        if beside {
            assert!(
                !f.client
                    .handle_pdo_response(&reply, &phone_reply_info())
                    .await,
                "{id}: the hook refuses the reply's first delivery"
            );
            assert_eq!(
                secret_of(&next_call(&calls).await[0]),
                Some(&secret[..]),
                "{id}: the refused item carries the secret too"
            );
        }
        assert!(
            f.client
                .handle_pdo_response(&reply, &phone_reply_info())
                .await
        );

        let committed = next_call(&calls).await;
        assert!(
            committed[0]
                .message
                .poll_creation_message_v3
                .as_option()
                .is_some(),
            "{id}: the hook commits the recovered poll"
        );
        assert_eq!(
            secret_of(&committed[0]),
            Some(&secret[..]),
            "{id}: the hook's item carries the secret in its context"
        );
        let batch = f.next_batch().await;
        assert!(
            Arc::ptr_eq(&batch.messages[0].message, &committed[0].message),
            "{id}: the event carries the item the hook committed"
        );
        f.client.msg_secret_buffer.wait_flushed().await;
        let contact = info.source.sender.to_non_ad_string();
        let stored = f
            .client
            .persistence_manager
            .backend()
            .get_msg_secret(&contact, &contact, id)
            .await
            .expect("the store answers");
        assert_eq!(
            stored.as_deref(),
            Some(&secret[..]),
            "{id}: the secret is stored for the add-ons that name the poll"
        );
    }
}

/// A recovered secret-encrypted add-on reaches the hook resolved, as an
/// ordinary delivery of it does, and is claimed as that resolved payload: the
/// sender's resend of the same envelope, which the arrival probe resolves too,
/// repeats it and reaches neither the hook nor the bus.
#[tokio::test]
async fn pdo_recovery_materializes_secret_encrypted_message() {
    let (hook, calls, _release) = scripted([Step::Commit]);
    let f = fixture(Some(hook)).await;
    let info = undecryptable("PDO-ENC-REACTION-1");
    let parent_id = "PDO-REACTION-PARENT-1";
    let secret = [0x5A; 32];
    f.client
        .persistence_manager
        .backend()
        .put_msg_secrets(vec![wacore::store::traits::MsgSecretEntry::new(
            &info.source.chat,
            &info.source.sender,
            parent_id,
            secret,
            0,
            0,
        )])
        .await
        .expect("the parent's secret is stored");
    let reaction = encrypted_reaction(&info, parent_id, &secret, "\u{1f44d}");
    let request_id = f.ask_phone(&info).await;

    let reply = phone_reply_with(&request_id, &info, reaction.clone(), None);
    assert!(
        f.client
            .handle_pdo_response(&reply, &phone_reply_info())
            .await
    );
    let committed = next_call(&calls).await;
    assert!(
        !crate::features::message_edit::carries_secret_encrypted(&committed[0].message),
        "the hook commits the resolved add-on, not its envelope"
    );
    let resolved = committed[0]
        .message
        .reaction_message
        .as_option()
        .expect("the envelope resolves to a reaction");
    assert_eq!(resolved.text.as_deref(), Some("\u{1f44d}"));
    assert_eq!(
        resolved.key.as_option().and_then(|key| key.id.as_deref()),
        Some(parent_id),
        "the reaction names its parent"
    );
    let batch = f.next_batch().await;
    assert!(batch.hook_committed);
    assert!(Arc::ptr_eq(
        &batch.messages[0].message,
        &committed[0].message
    ));
    assert!(
        f.client.message_already_dispatched(&info).await,
        "the resolved recovery is claimed"
    );

    f.client
        .handle_decrypted_plaintext(
            "msg",
            MessageUtils::encode_and_pad(&reaction),
            2,
            0,
            Default::default(),
            &info,
        )
        .await
        .expect("the resend is handled");
    assert!(
        calls.is_empty(),
        "the hook already holds the resolved payload from the recovery"
    );
    assert!(f.batches.is_empty(), "the resend is not published again");
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

/// A recovery's hook runs under the batcher's marker, so Signal maintenance
/// refuses inside it; the marker is gone once the hook's poll returns.
#[tokio::test]
async fn pdo_recovery_hook_refuses_signal_maintenance() {
    let (probe_tx, probe) = async_channel::unbounded();
    let f = fixture(Some(Arc::new(MaintenanceProbe(probe_tx)))).await;
    let info = undecryptable("PDO-MAINT-1");
    let request_id = f.ask_phone(&info).await;

    f.phone_replies(&request_id, &info, "recovered").await;
    assert!(
        probe.recv().await.expect("the hook ran"),
        "Signal maintenance must refuse inside a recovery's hook"
    );
    assert!(f.next_batch().await.hook_committed);
    // `#[tokio::test]` runs the reply on this thread, so a marker left set
    // would refuse here too.
    f.client
        .ensure_signal_maintenance_context()
        .expect("the marker is cleared once the hook's poll returns");
}
