use crate::HistorySyncMetadata;
use anyhow::Result;

/// Identity of one self-sent history notification, scoped to the Client account.
/// Stanza IDs alone are not unique: deduplicate on all three fields, and keep
/// each account's records separate. Device components are preserved verbatim.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HistorySyncKey {
    pub chat: String,
    pub sender: String,
    pub id: String,
}

impl HistorySyncKey {
    pub fn new(chat: impl Into<String>, sender: impl Into<String>, id: impl Into<String>) -> Self {
        Self {
            chat: chat.into(),
            sender: sender.into(),
            id: id.into(),
        }
    }
}

/// Opt-in durable notification recovery, independent of [`crate::HistorySyncCaptureHook`].
///
/// The SDK first stores the decrypted protocol-message carrier in its bounded
/// pending-inbound journal, then awaits `on_notification` and admission to the
/// bounded history work queue before acknowledging the message carrier. Queue
/// saturation or capture failure keeps the journal for server redelivery without
/// repeating Signal decryption. Downloads run on the history worker, sharing its
/// two-task limit with explicit replay; the `hist_sync` receipt additionally
/// waits for `on_compressed_chunk` and successful parsing.
///
/// After the carrier ACK, the host owns recovery if the worker fails or the
/// process stops. Keep the notification and schedule retries through
/// [`crate::Client::replay_history_sync_notification`] until the chunk is durable;
/// do not depend on server redelivery or the SDK journal surviving its cleanup.
/// The worker tells the host when it gives a chunk up ([`Self::on_chunk_failed`],
/// with why), so a host can retry while the connection lasts rather than at its
/// next start. One key has one download and parse at a time: a carrier
/// redelivered, or a replay, while the worker or a replay already holds the key
/// joins that work instead of starting its own.
///
/// Implementations must commit before returning `Ok`, be idempotent, and reject
/// an existing key with different bytes. Callbacks can repeat after failure,
/// cancellation, reconnect or a lost receipt. Store metadata together with the
/// bytes; fields are untrusted sender claims, not validated file properties.
/// Notifications contain media keys and possibly inline history: protect them
/// as account data, and do not log their contents.
///
/// Only self-sent notifications are captured. Skip/admission rejection still
/// intentionally acknowledges without calling either hook. Registration enables
/// the same bounded inbound journal/admission used by [`crate::InboundDurabilityHook`]
/// for encrypted messages, even without that hook; unsupported backends fail
/// construction. No live-message consumer hook is installed implicitly.
///
/// `on_notification` backpressures the receive commit pipeline; chunk callbacks
/// run on the history worker or a host replay. Do not call blocking client
/// operations from a hook. Failed pending writes remain in
/// bounded resident retention for this Client; surviving process termination
/// requires either the journal or the host notification write to have committed.
/// Durability strength depends on the selected backend/storage configuration.
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait HistorySyncDurabilityHook: wacore::sync_marker::MaybeSendSync {
    /// Retain the complete encoded `HistorySyncNotification`, including inline
    /// payload, before attempting download, processing, or a positive receipt.
    async fn on_notification(
        &self,
        key: &HistorySyncKey,
        metadata: &HistorySyncMetadata<'_>,
        notification: &[u8],
    ) -> Result<()>;

    /// Retain the decrypted, zlib-compressed chunk before its receipt. Parsing
    /// follows this callback; malformed chunks remain unacknowledged.
    async fn on_compressed_chunk(
        &self,
        key: &HistorySyncKey,
        metadata: &HistorySyncMetadata<'_>,
        compressed: &[u8],
    ) -> Result<()>;

    /// The history worker gave up on `key`'s chunk, for `failure`: its task for
    /// the key ended without the chunk captured and parsed. Called once for each
    /// such task, whatever ended it but a stop of the client (a shutdown or a
    /// permanent stop calls nothing: the host replays the notifications it kept
    /// when it starts again). The carrier was acknowledged already, so nothing
    /// but the host's replay brings the chunk back; the failure says when that
    /// is worth it. A host replay's own failure is its result, as the same
    /// [`HistoryChunkFailure`] in the error's chain, not a call here. Runs on the
    /// history worker; don't await client work from it that waits on the
    /// worker. The default does nothing.
    async fn on_chunk_failed(
        &self,
        _key: &HistorySyncKey,
        _metadata: &HistorySyncMetadata<'_>,
        _failure: HistoryChunkFailure,
    ) {
    }
}

/// Why the history worker gave up on a durable chunk
/// ([`HistorySyncDurabilityHook::on_chunk_failed`]), or why a host replay
/// failed (in its error's chain): what a later try can expect.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HistoryChunkFailure {
    /// The blob wasn't downloaded for a reason a later try can get past: no
    /// connection to download over, a network or transport failure, a media
    /// route that couldn't be had, a server error, memory the download
    /// couldn't have at the time.
    #[error("the history chunk's download failed")]
    Network,
    /// The blob can't be had as the notification references it: the media
    /// server refused the reference (401, 403, 404 or 410, after a refresh of
    /// the route), the body the media hosts served fails its MAC, a hash or
    /// its decryption, the reference makes no request, or the client's
    /// download policy refuses the blob. Trying again meets the same refusal
    /// or the same bytes; such a blob takes the primary phone's upload again.
    #[error("the history chunk's blob can't be had as referenced")]
    Refused,
    /// The host's own hook didn't keep the chunk (its `on_compressed_chunk`, or
    /// a [`HistorySyncCaptureHook`](crate::HistorySyncCaptureHook)'s error).
    #[error("the host didn't keep the history chunk")]
    Capture,
    /// The chunk doesn't parse (it doesn't inflate or decode, or its parse
    /// stopped with no result), or a replay's notification doesn't decode:
    /// trying again meets the same bytes.
    #[error("the history chunk or its notification is malformed")]
    Malformed,
}
