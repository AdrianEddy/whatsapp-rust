//! WF13: the conditional pending-inbound batch methods, each one immediate
//! transaction whose rows are compared and written as the single-row methods
//! do, and the single-row replacement's bound checked before any transaction.

use super::*;

async fn open_store() -> SqliteStore {
    use portable_atomic::AtomicU64;
    use std::sync::atomic::Ordering;
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let db_name = format!(
        "file:memdb_wf13_{}_{}?mode=memory&cache=shared",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    SqliteStore::open(&db_name)
        .await
        .expect("Failed to create test store")
}

const CHAT: &str = "chat";
const SENDER: &str = "sender";

fn key(id: &str) -> PendingInboundKey<'_> {
    PendingInboundKey {
        chat: CHAT,
        sender: SENDER,
        id,
    }
}

fn lease() -> PendingInboundLease {
    PendingInboundLease::new(Arc::new(()))
}

fn put(bytes: &'static [u8]) -> PendingInboundPayload {
    PendingInboundPayload::new(Bytes::from_static(bytes), lease())
}

fn cas<'a>(
    id: &'a str,
    expected: PendingInboundRevision,
    bytes: &'static [u8],
) -> PendingInboundCas<'a> {
    PendingInboundCas {
        key: key(id),
        expected,
        replacement: put(bytes),
    }
}

async fn stored(store: &SqliteStore, id: &str) -> Option<Vec<u8>> {
    store.get_pending_inbound(CHAT, SENDER, id).await.unwrap()
}

/// Each row is answered for itself: applied when its expected revision is the
/// stored one (absence included), already applied when it holds the
/// replacement, a conflict otherwise, which leaves that row alone and the
/// others applied.
#[tokio::test]
async fn pending_batch_cas_answers_each_row() {
    let store = open_store().await;
    let missing = PendingInboundRevision::missing();
    let stale = PendingInboundRevision::for_bytes(b"stale");
    let revision = PendingInboundRevision::for_bytes;
    for (id, bytes) in [("A", b"a0"), ("B", b"b0"), ("D", b"d1")] {
        store
            .store_pending_inbound(CHAT, SENDER, id, bytes)
            .await
            .unwrap();
    }

    let replaced = store
        .replace_pending_inbound_batch_if(
            vec![
                cas("A", revision(b"a0"), b"a1"),
                cas("B", stale, b"b1"),
                cas("C", missing, b"c1"),
                cas("D", stale, b"d1"),
            ],
            16,
        )
        .await
        .unwrap();
    assert_eq!(
        replaced,
        [
            PendingInboundMutation::Applied,
            PendingInboundMutation::Conflict,
            PendingInboundMutation::Applied,
            PendingInboundMutation::Applied,
        ]
    );
    assert_eq!(stored(&store, "A").await.as_deref(), Some(&b"a1"[..]));
    assert_eq!(stored(&store, "B").await.as_deref(), Some(&b"b0"[..]));
    assert_eq!(stored(&store, "C").await.as_deref(), Some(&b"c1"[..]));
    assert_eq!(stored(&store, "D").await.as_deref(), Some(&b"d1"[..]));

    let deleted = store
        .delete_pending_inbound_batch_if(
            &[
                (key("A"), revision(b"a1")),
                (key("B"), stale),
                (key("E"), missing),
            ],
            16,
            lease(),
        )
        .await
        .unwrap();
    assert_eq!(
        deleted,
        [
            PendingInboundMutation::Applied,
            PendingInboundMutation::Conflict,
            PendingInboundMutation::Applied,
        ]
    );
    assert_eq!(stored(&store, "A").await, None);
    assert_eq!(stored(&store, "B").await.as_deref(), Some(&b"b0"[..]));

    assert!(
        store
            .replace_pending_inbound_batch_if(Vec::new(), 16)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .delete_pending_inbound_batch_if(&[], 16, lease())
            .await
            .unwrap()
            .is_empty()
    );
}

/// A batch is one transaction: when a row's statement fails (here a trigger
/// aborts it), the rows the batch wrote before it are rolled back with it.
#[tokio::test]
async fn pending_batch_is_one_transaction() {
    let store = open_store().await;
    let missing = PendingInboundRevision::missing();
    for (id, bytes) in [("B", b"b0"), ("poison-delete", b"p0")] {
        store
            .store_pending_inbound(CHAT, SENDER, id, bytes)
            .await
            .unwrap();
    }
    store
        .write_blocking(|conn| {
            diesel::sql_query(
                "CREATE TRIGGER wf13_poison_insert BEFORE INSERT ON pending_inbound_messages \
                 WHEN NEW.id = 'poison-insert' BEGIN SELECT RAISE(ABORT, 'poisoned row'); END",
            )
            .execute(conn)
            .map_err(|e| StoreError::Database(Box::new(e)))?;
            diesel::sql_query(
                "CREATE TRIGGER wf13_poison_delete BEFORE DELETE ON pending_inbound_messages \
                 WHEN OLD.id = 'poison-delete' BEGIN SELECT RAISE(ABORT, 'poisoned row'); END",
            )
            .execute(conn)
            .map_err(|e| StoreError::Database(Box::new(e)))?;
            Ok(())
        })
        .await
        .unwrap();

    let replaced = store
        .replace_pending_inbound_batch_if(
            vec![
                cas("A", missing, b"a1"),
                cas("poison-insert", missing, b"p1"),
            ],
            16,
        )
        .await;
    assert!(replaced.is_err());
    assert_eq!(
        stored(&store, "A").await,
        None,
        "the row written before the failed one was rolled back"
    );

    let deleted = store
        .delete_pending_inbound_batch_if(
            &[
                (key("B"), PendingInboundRevision::for_bytes(b"b0")),
                (
                    key("poison-delete"),
                    PendingInboundRevision::for_bytes(b"p0"),
                ),
            ],
            16,
            lease(),
        )
        .await;
    assert!(deleted.is_err());
    assert_eq!(
        stored(&store, "B").await.as_deref(),
        Some(&b"b0"[..]),
        "the row deleted before the failed one was restored"
    );
}

/// A row that can't be compared (here an oversized replacement) fails the
/// call, after the batch's other rows were applied, as a caller mutating them
/// one by one would have found them.
#[tokio::test]
async fn pending_batch_row_that_cannot_be_compared_fails_the_call() {
    let store = open_store().await;
    let missing = PendingInboundRevision::missing();
    let replaced = store
        .replace_pending_inbound_batch_if(
            vec![
                cas("A", missing, b"a1"),
                cas("X", missing, b"seventeen bytes!!"),
                cas("C", missing, b"c1"),
            ],
            16,
        )
        .await;
    assert!(replaced.is_err());
    assert_eq!(stored(&store, "A").await.as_deref(), Some(&b"a1"[..]));
    assert_eq!(stored(&store, "X").await, None);
    assert_eq!(stored(&store, "C").await.as_deref(), Some(&b"c1"[..]));
}

/// A single-row replacement over the bound is refused before the write queue:
/// `Validation`, with no write transaction and so no commit barrier, whose
/// failure would tell the caller to treat the call as committed. The fitting
/// replacement after it reaches the barrier.
#[tokio::test]
async fn oversized_single_replacement_refused_before_the_write_queue() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let mut store = open_store().await;
    let barriers = Arc::new(AtomicUsize::new(0));
    store.commit_barrier = Some({
        let barriers = barriers.clone();
        Arc::new(move || {
            let barriers = barriers.clone();
            Box::pin(async move {
                barriers.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        })
    });
    let missing = PendingInboundRevision::missing();

    let refused = store
        .replace_pending_inbound_if(key("X"), missing, put(b"seventeen bytes!!"), 16)
        .await;
    assert!(
        matches!(refused, Err(StoreError::Validation(_))),
        "{refused:?}"
    );
    assert_eq!(barriers.load(Ordering::SeqCst), 0, "no write transaction");

    assert_eq!(
        store
            .replace_pending_inbound_if(key("X"), missing, put(b"sixteen bytes!!!"), 16)
            .await
            .unwrap(),
        PendingInboundMutation::Applied
    );
    assert_eq!(barriers.load(Ordering::SeqCst), 1);
    assert_eq!(
        stored(&store, "X").await.as_deref(),
        Some(&b"sixteen bytes!!!"[..])
    );
}
