//! Select capture by origin; no single hook covers all incoming content.
//!
//! | Origin | Commit gate before ACK/receipt |
//! | --- | --- |
//! | Encrypted live/offline direct and group messages | [`InboundDurabilityHook`] |
//! | Undecryptable stanzas | [`InboundDurabilityHook::on_undecryptable`], before the event, the retry receipt and the ACK |
//! | Newsletter/channel messages | [`InboundDurabilityHook`], each as a batch of one |
//! | PDO recovery | [`InboundDurabilityHook`], each as a batch of one, before its event |
//! | Group `w:gp2` notifications | [`crate::GroupNotificationDurabilityHook`] |
//! | Admitted history chunks | [`HistorySyncCaptureHook`], registered separately |
//! | History notifications with restart recovery | [`crate::HistorySyncDurabilityHook`] |
//! | App-state patches, snapshots and recoveries | [`crate::AppStateDurabilityHook`], before the cursor moves |
//! | Callbacks/event subscriptions | Observers, not durable capture |
//!
//! A connection's offline backlog as a whole is admitted first, before any of
//! it is asked for or handled: [`crate::OfflineAdmissionHook`].
//!
//! Each hook defines its own idempotence, cancellation and replay limits.
//! Withholding an ACK/receipt does not promise indefinite retention or redelivery.

use crate::client::Client;
use anyhow::Result;
use std::sync::Arc;
pub use wacore::types::events::InboundMessage;
use wacore::types::events::{DecryptFailMode, EncDecryptFailureReason, UnavailableType};
use wacore::types::message::MessageInfo;
use waproto::whatsapp as wa;

/// Hook invoked for every decrypted inbound user message, and every newsletter
/// message, before it is acknowledged to the server, for every message the
/// primary phone recovers before it is published, and for every message that
/// produced no plaintext before it is answered
/// ([`on_undecryptable`](Self::on_undecryptable)), turning the consumer from
/// at-most-once into at-least-once delivery.
///
/// The transport ack tells the server to drop the message from its offline
/// queue. By default the SDK acks as soon as a message is decrypted, so a crash
/// (or a failed DB write) before the consumer persists the message loses it for
/// good. When a hook is registered, the ack is deferred until the hook returns
/// `Ok`: the decrypted messages are buffered durably first, the hook runs, and
/// only on success are their acks sent and the buffer cleared. On `Err` (or a
/// crash) the messages stay unacked and the server redelivers them on the next
/// connect, where the hook runs again from the buffered copies.
///
/// This is at-least-once, not exactly-once: a crash after the consumer commits
/// but before the ack lands replays the message, so the hook MUST be idempotent.
/// A failed batch is redelivered whole, so a partially-applied batch commit
/// must also be safe to re-run. Deduplicate by the message source AND id —
/// `(info.source.chat, info.source.sender, info.id)` — not `info.id` alone:
/// stanza ids are only unique within a `(chat, sender)`, so two chats can
/// reuse the same id.
///
/// The builder checks the `ProtocolStore` bounded pending-inbound exact/group-alias reads and
/// conditional replacement/deletion operations, and rejects unsupported backends with
/// [`ClientBuilderError::UnsupportedDurabilityBackend`](crate::ClientBuilderError::UnsupportedDurabilityBackend).
/// Custom batched overrides must preserve those operations' semantics; the
/// construction probe does not certify an arbitrary batch implementation.
///
/// History capture is configured independently through [`HistorySyncCaptureHook`].
/// Registering this hook alone does not change history receipt ordering.
/// [`crate::HistorySyncDurabilityHook`] additionally retains notifications for replay.
///
/// The hook is awaited inside the receive pipeline, so a slow hook backpressures
/// inbound processing (the same trade-off as whatsmeow's synchronous ack). Do
/// not perform blocking client operations for a sender present in the batch
/// (e.g. a synchronous reply) — that can deadlock against the per-sender Signal
/// lock held while a 1:1 message is processed; persist and return, and spawn
/// any reply.
/// Device metadata lookups for users outside the batch can complete here.
/// If a lookup requires Signal cleanup or identity recovery, it returns an
/// error instead of waiting for the hook's own processing permit (a
/// newsletter's call, which holds none, is refused the same way). Run that
/// maintenance from a separate control task and retry the durable batch.
///
/// Scope and known limitations:
/// - Covers end-to-end encrypted messages (1:1 and group), newsletter /
///   broadcast channel messages, messages the primary phone recovers, and,
///   through [`on_undecryptable`](Self::on_undecryptable), messages that
///   produced no plaintext.
/// - A message the primary phone recovers (a PDO placeholder resend, the
///   answer to a message this device could not decrypt;
///   `info.unavailable_request_id` names the request when the reply carries
///   one) is committed alone, as a batch of one, before it is claimed and
///   published. Its `info` is that of the stanza that failed to decrypt while
///   that stanza's request is pending
///   ([`CacheConfig::pdo_pending_requests`](crate::CacheConfig::pdo_pending_requests)),
///   or is rebuilt from the reply when no request here matches it. Its
///   `message` is the consumer projection an ordinary delivery gets: its
///   `messageSecret` in `messageContextInfo` (also when the phone sent it
///   beside the message, on the reply's `WebMessageInfo`) and captured, and a
///   secret-encrypted add-on resolved when its parent's secret is known. It has
///   no ack and no pending-inbound row of its own: it rides inside the phone's
///   reply, whose own delivery this hook then commits as an ordinary message.
///   That reply is the only copy, so `Err` fails the reply with it: nothing is
///   published, no dispatch-cache claim is left, the reply is neither
///   committed nor acked, and the request it answered stays pending for
///   another window. The server redelivers the reply on the next connect and
///   the recovery comes to this hook again from it, as any refused message
///   does; the phone is not asked again. Until then the reply's plaintext is
///   owned by this Client only, as described below for a failed buffer write,
///   so a refused recovery survives reconnects but not the end of the Client
///   or process, after which a redelivery the Signal session already
///   decrypted is acked as a duplicate: only a new request to the phone
///   ([`Client::retry_pdo_placeholder_resend_request`]) or the sender's own
///   resend then brings the message back. Within the dispatch cache's
///   retention window
///   ([`CacheConfig::dispatched_messages`](crate::CacheConfig::dispatched_messages)),
///   a recovery of a payload this hook already committed under the same
///   message identity (the sender's own resend, say) is not passed to it again,
///   and a copy that arrives after a recovery was committed, or waits in the
///   offline drain's batch while it commits, is acked as a duplicate, reaching
///   neither the hook nor the bus; one that arrives after the window is
///   committed and published again. A copy whose own commit is already running
///   when the recovery commits is committed too, and published once. The
///   idempotence above absorbs both. The recovery's event says
///   `hook_committed`.
/// - A newsletter message (`info.source.chat.is_newsletter()`;
///   `InboundMessage::newsletter_ref` addresses it) is plaintext and is
///   committed alone, as a batch of one, live or offline. The ack it is owed
///   (`<ack class="message">`) follows `Ok`; as for any item, `Err` withholds
///   both the ack and the event. It skips the pending-inbound buffer, so after
///   an `Err` its redelivery is parsed again from the stanza. As without a
///   hook, it also skips the dispatch cache, so a redelivery after a lost ack
///   reaches this hook and `Event::Messages` again; the idempotence above is
///   what deduplicates it. Its event says `hook_committed`, so a hook that
///   returns `Ok` without storing the item leaves that event as its only copy.
///   The commit runs in its chat lane before any processing permit, so it can
///   overlap a drain batch's commit, and shutdown and teardown don't wait for
///   it, as they don't for a live encrypted commit: the ack of an `Ok` that
///   lands after its connection closed goes out on the next connection, or is
///   dropped for the server to redeliver.
/// - Live plaintext backing is admitted before Signal decryption under a
///   4 MiB budget and 400 reservations. Admission accounts for both the carrier
///   and consumer projection plus metadata; the maximum ciphertext size is
///   therefore smaller than 4 MiB. Capacity refusal leaves Signal untouched
///   and sends no positive ACK. A later server redelivery can retry after
///   capacity is released; an oversized stanza remains refused under this bound.
/// - If a durable buffer write fails, plaintext remains owned by this Client
///   across cancellation and reconnect, and redelivery retries storage without
///   repeating Signal decryption. This resident copy cannot survive process
///   termination. Crash recovery requires the pending row to have been stored
///   durably before the process exits.
///   Resident retry projections use encoded backing; decoded graphs belong to
///   active processing, callbacks or consumers and are outside this backing
///   budget. Consumer-held messages are not a bounded Client cache.
/// - On a redelivery replay the `info` is re-parsed from the stanza, so a few
///   fields derived during the first dispatch (the ephemeral timer, encrypted
///   comment threading) may be absent. The stored `message` is the consumer
///   projection, including the resolved payload of secret messages.
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait InboundDurabilityHook: wacore::sync_marker::MaybeSendSync {
    /// Durably commit the whole batch, all-or-nothing, in slice order (e.g. one
    /// multi-row INSERT transaction). Return `Ok(())` only after the commit is
    /// durable; the SDK then acks every message in the batch. Return `Err` to
    /// suppress all their acks and have the server redeliver them.
    ///
    /// Live messages, newsletter messages and recoveries from the primary
    /// phone arrive as batches of one. During
    /// the offline drain the SDK accumulates encrypted messages and commits
    /// them per batch (WA Web's MessageProcessorCache granularity), so one
    /// round-trip covers the lot.
    /// [`Event::Messages`](wacore::types::events::Event::Messages) then
    /// carries the exact same items: what this method committed is what event
    /// consumers observe. Publication precedes conditional pending-row cleanup
    /// so a partial cleanup cannot discard part of this committed event. ACK
    /// waits for the complete cleanup; an error or cancellation can therefore
    /// leave rows to retry after the event has already been published. The
    /// existing dispatch cache suppresses repeated events of encrypted messages
    /// within its retention window, including reconnects of the same Client. A
    /// process restart still requires the idempotent durable consumer described
    /// above.
    async fn on_messages(&self, client: Arc<Client>, batch: &[InboundMessage]) -> Result<()>;

    /// Durably commit the report of one message that produced no plaintext,
    /// before the client answers its stanza. Return `Ok(())` only after the
    /// commit is durable; the SDK then dispatches
    /// [`Event::UndecryptableMessage`](wacore::types::events::Event::UndecryptableMessage)
    /// and does what [`UndecryptableCause::recovery`] says: the retry receipt
    /// and then the ACK, a request to the primary phone and then the ACK, an
    /// ACK or a nack, or nothing until the server delivers the stanza again.
    /// Return `Err` to withhold all of it, the event included: the stanza is
    /// neither acked nor nacked, so the server delivers it again and this
    /// method is called again for it.
    ///
    /// It is called for every message that produced no plaintext: where an
    /// `<enc>` of the stanza fails to decrypt (a Signal session or sender-key
    /// message, or a bot reply's `msmsg`), where its plaintext proves
    /// unusable (also one kept from a delivery cancelled before its plaintext
    /// was checked, reported when the redelivery replays it), where no
    /// `<enc>` of the stanza is one this client can decrypt (an unsupported
    /// type or a malformed node), and for an `<unavailable>` stub the server
    /// sends in place of ciphertext. A stanza whose message attributes don't
    /// parse has no `info` to report and is nacked as before. Within the
    /// [`CacheConfig::undecryptable_dispatched`](crate::CacheConfig::undecryptable_dispatched)
    /// window a message is reported until a call returns `Ok`: a later delivery
    /// of a message this method accepted is answered without another call or
    /// event (as is a further failed `<enc>` of the same stanza), while one it
    /// refused is reported again. A copy that arrives while a call for the
    /// same message still runs (a redelivery on a new connection while the
    /// previous connection's copy is in this method) waits for that call and
    /// then follows it: answered without a call after `Ok`, reported in a
    /// call of its own after `Err`. Commit a placeholder for
    /// `(info.source.chat, info.source.sender, info.id)` that the real message
    /// replaces when a retry, the primary phone or the sender's own resend
    /// brings it, and be idempotent: after the window, after a restart, or
    /// when the commit landed and the answer did not, the same message is
    /// reported again.
    ///
    /// When the `<enc>` had decrypted and only its plaintext was unusable, its
    /// redelivery cannot fail the same way again (the ratchet has moved on and
    /// it decrypts as a duplicate). Before this call the client therefore
    /// records the report in the message's pending-inbound row, as a
    /// decrypted message is buffered before its hook runs, and clears it after
    /// `Ok`. After an `Err` it stays owed, across reconnects, the end of this
    /// Client and a restart: when the stanza comes back, before any of it is
    /// processed, this method is called with that delivery's `info`, the same
    /// `failure` and `decrypt_fail_mode`, and
    /// [`UndecryptableRecovery::NoRequest`] (nothing asks for the message
    /// again; the stanza is then processed and answered as its content says).
    /// The row expires with the other pending-inbound rows. A
    /// `status@broadcast` stanza owes nothing: it was acked when it arrived and
    /// is not delivered again.
    ///
    /// The rules of [`on_messages`](Self::on_messages) apply: this runs in the
    /// receive pipeline, possibly while the client holds the sender's Signal
    /// session lock and a processing permit, so never call the client for this
    /// sender from inside it, and Signal maintenance it reaches refuses. A
    /// `status@broadcast` stanza is acked when it arrives, without waiting for
    /// this call, as for `on_messages`, so an `Err` withholds what follows the
    /// report (the event, the retry receipt, the request to the phone or the
    /// nack), not the ack. The default commits nothing and returns `Ok(())`,
    /// which answers the stanza as a client without a hook does.
    async fn on_undecryptable(
        &self,
        _client: Arc<Client>,
        _info: &MessageInfo,
        _cause: UndecryptableCause,
    ) -> Result<()> {
        Ok(())
    }
}

/// What [`InboundDurabilityHook::on_undecryptable`] is told about a message
/// that produced no plaintext: what failed, and what the client does once the
/// hook returns `Ok`. A host's tests build one with
/// [`UndecryptableCause::builder`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, bon::Builder)]
#[non_exhaustive]
pub struct UndecryptableCause {
    /// What produced no plaintext.
    pub failure: UndecryptableFailure,
    /// What the client does after `Ok`.
    pub recovery: UndecryptableRecovery,
    /// The sender's `decrypt-fail` attribute: `Hide` marks a message whose
    /// failure the sender asks not to show (an add-on, a fan-out copy), as the
    /// event's own field does.
    pub decrypt_fail_mode: DecryptFailMode,
}

/// What produced no plaintext for an
/// [`InboundDurabilityHook::on_undecryptable`] report. Later versions may add
/// kinds: match it with a wildcard arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UndecryptableFailure {
    /// The server sent an `<unavailable>` stub of this kind in place of the
    /// ciphertext (a fan-out this device was not encrypted for).
    Unavailable(UnavailableType),
    /// An `<enc>` of the stanza produced no plaintext, for the reason the
    /// client gives it in
    /// [`Event::EncDecryptFailed`](wacore::types::events::Event::EncDecryptFailed).
    Enc(EncDecryptFailureReason),
}

/// What the client does once [`InboundDurabilityHook::on_undecryptable`]
/// returns `Ok`. Later versions may add kinds: match it with a wildcard arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UndecryptableRecovery {
    /// A retry receipt asks the sender to encrypt the message again, then the
    /// stanza is acked. The first retry also asks the primary phone for the
    /// message; at the client's retry cap only the phone is asked, and a
    /// [`DecryptFailureAdmission`](crate::DecryptFailureAdmission) policy can
    /// have the stanza acked without a retry.
    RetryReceipt,
    /// The primary phone is asked for the message (a placeholder resend), then
    /// the stanza is acked.
    PlaceholderResend,
    /// The stanza is left unanswered, so the server delivers it again and the
    /// client processes it again then.
    Redelivery,
    /// The stanza is acked or nacked and nothing asks for the message again:
    /// only the sender resending it on its own brings it back.
    NoRequest,
}

impl UndecryptableCause {
    /// A failed `<enc>`.
    pub(crate) const fn enc(
        reason: EncDecryptFailureReason,
        recovery: UndecryptableRecovery,
        decrypt_fail_mode: DecryptFailMode,
    ) -> Self {
        Self {
            failure: UndecryptableFailure::Enc(reason),
            recovery,
            decrypt_fail_mode,
        }
    }
}

/// Optional capture of history-sync bytes before attempting their receipt.
///
/// Register with [`crate::ClientBuilder::with_history_sync_capture_hook`] or
/// [`crate::bot::BotBuilder::with_history_sync_capture_hook`]. This hook does not
/// enable message durability or require pending-inbound storage. Consumers
/// migrating from `InboundDurabilityHook::on_history_sync` must implement this
/// trait and register it separately, even when one object implements both hooks.
///
/// ```
/// use std::sync::Arc;
/// use whatsapp_rust::{ClientBuilder, HistorySyncCaptureHook};
///
/// fn capture_history(builder: ClientBuilder, capture: Arc<dyn HistorySyncCaptureHook>) -> ClientBuilder {
///     builder.with_history_sync_capture_hook_arc(capture)
/// }
/// ```
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait HistorySyncCaptureHook: wacore::sync_marker::MaybeSendSync {
    /// Durably capture one history-sync chunk before its `hist_sync` receipt
    /// is sent. `compressed` is the chunk exactly as the phone uploaded it
    /// (zlib-compressed `HistorySync`), whether it arrived inline or as a
    /// downloaded blob.
    ///
    /// Return `Ok(())` only after the capture is durable. The SDK awaits this
    /// method before attempting the receipt. Download failures, hook errors,
    /// and cancellation before this method returns leave the chunk without a
    /// `hist_sync` receipt. The SDK does not retry the hook or persist a replay
    /// buffer for history chunks; withholding a receipt does not itself
    /// guarantee that the phone will redeliver the chunk.
    ///
    /// Duplicate notifications can invoke this hook again, including after a
    /// successful capture whose receipt failed to send. Make capture idempotent
    /// by `message_id`. Downloaded bytes are decrypted but still compressed;
    /// capture runs before decompression and protobuf validation.
    ///
    /// History tasks can call this hook concurrently. A slow hook holds a history
    /// worker slot. Shutdown does not join these detached tasks or cancel an
    /// already-running hook; use [`Client::shutdown_signal`] if the capture needs
    /// to observe shutdown, and make partial writes safe against cancellation.
    ///
    /// Chunks the SDK does not process (history sync skipped, or rejected by the
    /// admission policy) are acknowledged without calling the hook. Without a
    /// capture hook the receipt is attempted before download, including when only
    /// an [`InboundDurabilityHook`] is registered. There is no default capture.
    async fn on_history_sync(
        &self,
        client: Arc<Client>,
        message_id: &str,
        sync_type: Option<wa::message::HistorySyncType>,
        compressed: &[u8],
    ) -> Result<()>;
}
