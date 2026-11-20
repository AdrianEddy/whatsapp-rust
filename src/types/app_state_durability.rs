use anyhow::Result;
pub use wacore::appstate_sync::{AppStateBatch, AppStateBatchKind};

/// A durable gate for app-state mutations, before the collection's cursor moves.
///
/// Awaited once for every patch the client applies that carries at least one
/// mutation, and for every snapshot and snapshot recovery, an empty one
/// included: what the app-state sync fetches from the server (including the
/// sync the client runs after each patch it sends), and a collection the
/// primary phone sends back to recover one whose snapshot could not be
/// validated. It runs after the client's own durable effects of the same
/// mutations (the status-privacy audience and the `pnForLidChat` LID mappings)
/// and before the client commits any of the batch's rows: its mutation MACs,
/// the version and the ltHash. (A collection starting over without a baseline
/// has already dropped the stale MAC rows a reset left behind, and a rebuild
/// its version too, before its first batch is offered.) Only after `Ok(())`
/// does the cursor move, and only then are the mutations dispatched as events
/// (`ArchiveUpdate`, `PinUpdate`, `MuteUpdate` and the rest).
///
/// [`AppStateBatch::collection`] is the wire name (`regular`, `regular_low`,
/// `regular_high`, `critical_block`, `critical_unblock_low`). Its `mutations`
/// are the decoded mutations the commit covers, in the order the collection
/// applies them, SET and REMOVE alike, including actions the client has no
/// event for. Its `kind` says what an index the batch lacks means: a
/// [`AppStateBatchKind::Patch`] changes the collection and leaves every other
/// index as it was, while a snapshot or a recovery is the whole collection,
/// its records one per index and app-state key (an index the collection holds
/// under two keys, after a key rotation, comes twice), so an index the host
/// holds and the batch lacks no longer exists; an empty batch is a snapshot or
/// a recovery of an empty collection. Its `version` is the collection's once the batch commits: a
/// host that replaces a collection from a whole-collection batch drops only
/// what it last wrote at or below it, since a batch from a retired connection
/// can arrive after a newer one (see below). Its `full_sync` is the value
/// these mutations' events carry in `from_full_sync`: `true` on every batch of
/// a rebuild from a snapshot (a collection without a baseline, or a full-sync
/// request), the patches after the snapshot included, and for a recovery;
/// `false` for live patches and for what a conflicting patch send absorbs, a
/// snapshot included.
///
/// `Err` leaves the collection's rows as the hook found them and dispatches
/// nothing, and the collection's next sync fetches the same mutations again.
/// A sync the client runs in the background or after a patch it sends is
/// retried with backoff, waiting out reconnects; one a caller awaits
/// (`resync_app_state`) reports the failure to that caller instead. Patches and
/// collections of the same sync committed before the refused one stay
/// committed and are dispatched. A refused recovery is not offered again by
/// itself: the collection's next sync fails as before and asks the primary
/// phone again.
///
/// Implementations must commit before returning `Ok` and be idempotent: a
/// crash between the host's commit and the cursor's, a sync retried after a
/// later failure, a rebuild or a repeated recovery all offer the same
/// mutations again. Last-writer-wins on `SyncActionValue::timestamp` makes a
/// replay a no-op. A future dropped before it completes is an indeterminate
/// commit, which that replay settles.
///
/// The hook is awaited inside the sync, with the collection reserved, so a
/// slow hook holds up that collection and the sync work queued behind it. Do
/// not await a client operation that writes app state (a chat action such as
/// archiving, any patch send, an app-state resync) from inside the hook: it
/// waits for that reservation; spawn it instead. Calls for different
/// collections can run at the same time, and after a reconnect a call from the
/// old connection can still be running when the new connection syncs the same
/// collection, so each call must commit on its own. Once such a call returns,
/// the old connection's sync stops without writing the collection's rows or
/// dispatching the batch, and the collection's next sync offers its mutations
/// again.
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait AppStateDurabilityHook: wacore::sync_marker::MaybeSendSync {
    /// Commit `batch` before returning `Ok(())`.
    ///
    /// Return an error when the host cannot establish a durable commit; the
    /// sync of that collection fails with it.
    async fn on_mutations(&self, batch: AppStateBatch<'_>) -> Result<()>;
}
