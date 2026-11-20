//! WF13: a commit batch writes its pending-inbound journal with one batched
//! conditional replacement before the hook and removes it with one batched
//! conditional delete after, never one call per message. The client runs over
//! [`ProbeBackend`], which logs every store call it forwards to an
//! [`InMemoryBackend`] the test also reads directly; that backend implements
//! the single-row methods only, so the batched calls run the trait's defaults.

use super::*;
use crate::message::tests::{delivery_receipts_for, seed_test_pn};
use crate::store::release::tests::ProbeBackend;
use crate::types::durability_hook::InboundDurabilityHook;
use crate::types::message::{MessageInfo, MessageSource};
use std::sync::Mutex;
use wacore::store::in_memory::InMemoryBackend;
use wacore::store::traits::ProtocolStore;
use wacore::types::events::DecryptFailMode;
use waproto::whatsapp as wa;

/// A one-to-one chat: the probe forwards no group lookup, and none is needed.
const CHAT: &str = "200@s.whatsapp.net";
const REPLACE_BATCH: &str = "replace_pending_inbound_batch_if";
const DELETE_BATCH: &str = "delete_pending_inbound_batch_if";
const HOOK: &str = "on_messages";

fn item(id: &str) -> InboundMessage {
    let mut message = wa::Message::default();
    message.conversation = Some(format!("text {id}"));
    InboundMessage::builder()
        .message(Arc::new(message))
        .info(Arc::new(MessageInfo {
            id: id.into(),
            source: MessageSource {
                chat: CHAT.parse().unwrap(),
                sender: CHAT.parse().unwrap(),
                ..Default::default()
            },
            ..Default::default()
        }))
        .build()
}

fn key(id: &str) -> PendingInboundKey<'_> {
    PendingInboundKey {
        chat: CHAT,
        sender: CHAT,
        id,
    }
}

fn lease() -> PendingInboundLease {
    PendingInboundLease::new(Arc::new(()))
}

fn put(bytes: &'static [u8]) -> PendingInboundPayload {
    PendingInboundPayload::new(bytes::Bytes::from_static(bytes), lease())
}

/// Logs each batch it commits into the probe's call log, so the log orders
/// the journal writes around it, and records which of the batch's messages
/// already had a journal row when it was called.
struct Hook {
    store: Arc<InMemoryBackend>,
    calls: Arc<Mutex<Vec<String>>>,
    batches: Mutex<Vec<Vec<(String, bool)>>>,
}

#[async_trait::async_trait]
impl InboundDurabilityHook for Hook {
    async fn on_messages(
        &self,
        _client: Arc<Client>,
        batch: &[InboundMessage],
    ) -> anyhow::Result<()> {
        let mut seen = Vec::with_capacity(batch.len());
        for message in batch {
            let row = self
                .store
                .get_pending_inbound(CHAT, CHAT, &message.info.id)
                .await?;
            seen.push((message.info.id.to_string(), row.is_some()));
        }
        self.calls.lock().unwrap().push(HOOK.to_owned());
        self.batches.lock().unwrap().push(seen);
        Ok(())
    }
}

struct Harness {
    client: Arc<Client>,
    store: Arc<InMemoryBackend>,
    calls: Arc<Mutex<Vec<String>>>,
    hook: Arc<Hook>,
}

impl Harness {
    /// A client over a logging probe, with the hook registered and the
    /// batcher in drain mode.
    async fn new(configure: impl FnOnce(&mut ProbeBackend)) -> Self {
        let (mut probe, _) = ProbeBackend::new();
        let store = Arc::new(InMemoryBackend::new());
        let calls = Arc::new(Mutex::new(Vec::new()));
        probe.backend = store.clone();
        probe.calls = Some(calls.clone());
        configure(&mut probe);
        let client = crate::test_utils::create_test_client_with_backend(Arc::new(probe)).await;
        let hook = Arc::new(Hook {
            store: store.clone(),
            calls: calls.clone(),
            batches: Mutex::new(Vec::new()),
        });
        client
            .inbound_durability_hook
            .set(hook.clone())
            .ok()
            .unwrap();
        client.inbound_commit_batch.reset();
        calls.lock().unwrap().clear();
        Self {
            client,
            store,
            calls,
            hook,
        }
    }

    async fn drain(&self, ids: &[&str]) {
        for id in ids {
            self.client.commit_or_batch_inbound(item(id), false).await;
        }
    }

    /// The journal row writes the client made, and the hook's calls between
    /// them.
    fn journal_writes(&self) -> Vec<String> {
        const WRITES: [&str; 9] = [
            HOOK,
            REPLACE_BATCH,
            DELETE_BATCH,
            "replace_pending_inbound_if",
            "delete_pending_inbound_if",
            "store_pending_inbound",
            "store_pending_inbound_batch",
            "delete_pending_inbound",
            "delete_pending_inbound_batch",
        ];
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|call| WRITES.contains(&call.as_str()))
            .cloned()
            .collect()
    }

    fn hook_batches(&self) -> Vec<Vec<(String, bool)>> {
        self.hook.batches.lock().unwrap().clone()
    }

    async fn row(&self, id: &str) -> Option<Vec<u8>> {
        self.store
            .get_pending_inbound(CHAT, CHAT, id)
            .await
            .unwrap()
    }
}

async fn capture_receipts(
    client: &Arc<Client>,
) -> Arc<crate::transport::mock::CapturingMockTransport> {
    let transport = Arc::new(crate::transport::mock::CapturingMockTransport::new());
    let socket = crate::socket::NoiseSocket::new(
        Arc::new(crate::runtime_impl::TokioRuntime),
        transport.clone(),
        wacore::handshake::NoiseCipher::new(&[0; 32]).unwrap(),
        wacore::handshake::NoiseCipher::new(&[0; 32]).unwrap(),
    );
    *client.noise_socket.lock().unwrap() = Some(Arc::new(socket));
    client.set_connected_for_test(true);
    seed_test_pn(client).await;
    transport
}

const IDS: [&str; 3] = ["WF13_A", "WF13_B", "WF13_C"];

/// The drain's batch reaches the store as one conditional replacement of all
/// its rows, made before the hook is called: the per-message loop is gone.
#[tokio::test]
async fn drain_batch_calls_batched_cas_once() {
    let harness = Harness::new(|_| {}).await;
    harness.drain(&IDS).await;
    assert!(
        harness.journal_writes().is_empty(),
        "an accumulating drain batch writes no journal row"
    );

    assert!(
        harness
            .client
            .flush_inbound_commits_under_permit(false, None, None)
            .await
    );

    let writes = harness.journal_writes();
    assert_eq!(
        writes.iter().filter(|call| *call == REPLACE_BATCH).count(),
        1,
        "one batched replacement for the whole batch: {writes:?}"
    );
    assert!(
        !writes
            .iter()
            .any(|call| call == "replace_pending_inbound_if"),
        "no single-row replacement: {writes:?}"
    );
    assert_eq!(
        writes.first().map(String::as_str),
        Some(REPLACE_BATCH),
        "the rows are written before the hook is called: {writes:?}"
    );
    assert_eq!(
        harness.hook_batches(),
        vec![IDS.map(|id| (id.to_owned(), true)).to_vec()],
        "the one call wrote every row of the batch the hook then committed"
    );
}

/// Once the hook committed the batch, one conditional delete removes every
/// row, and only then is each stanza acked.
#[tokio::test]
async fn cleanup_calls_batched_delete_once() {
    let harness = Harness::new(|_| {}).await;
    let transport = capture_receipts(&harness.client).await;
    harness.drain(&IDS).await;

    assert!(
        harness
            .client
            .flush_inbound_commits_under_permit(false, None, None)
            .await
    );

    assert_eq!(
        harness.journal_writes(),
        [REPLACE_BATCH, HOOK, DELETE_BATCH],
        "two journal writes for the batch, the delete after the commit"
    );
    for id in IDS {
        assert_eq!(harness.row(id).await, None, "{id}'s row was removed");
    }
    crate::test_utils::wait_for_outbound_tasks(&harness.client).await;
    for id in IDS {
        assert_eq!(
            delivery_receipts_for(&transport.sent(), id),
            1,
            "{id} is acked once its row is gone"
        );
    }
}

/// The trait's defaults call the single-row methods, one per row and in
/// order, past a row's conflict and past a row's error, so a backend that
/// implements only those (the in-memory one) behaves as before. The in-memory
/// backend's injected failures live in its single-row methods.
#[tokio::test]
async fn default_batch_methods_loop_over_single_rows() {
    let store = InMemoryBackend::new();
    let missing = PendingInboundRevision::missing();
    let stale = PendingInboundRevision::for_bytes(b"stale");
    let revision = PendingInboundRevision::for_bytes;
    for (id, bytes) in [("A", b"a0"), ("B", b"b0")] {
        assert_eq!(
            store
                .replace_pending_inbound_if(key(id), missing, put(bytes), 16)
                .await
                .unwrap(),
            PendingInboundMutation::Applied
        );
    }
    let stored = async |id: &str| store.get_pending_inbound(CHAT, CHAT, id).await.unwrap();

    let replaced = store
        .replace_pending_inbound_batch_if(
            vec![
                PendingInboundCas {
                    key: key("A"),
                    expected: revision(b"a0"),
                    replacement: put(b"a1"),
                },
                PendingInboundCas {
                    key: key("B"),
                    expected: stale,
                    replacement: put(b"b1"),
                },
                PendingInboundCas {
                    key: key("C"),
                    expected: missing,
                    replacement: put(b"c1"),
                },
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
            PendingInboundMutation::Applied
        ]
    );
    assert_eq!(stored("A").await.as_deref(), Some(&b"a1"[..]));
    assert_eq!(
        stored("B").await.as_deref(),
        Some(&b"b0"[..]),
        "a conflicting row is left as it was"
    );
    assert_eq!(stored("C").await.as_deref(), Some(&b"c1"[..]));

    // The first row's replacement lands and then reports an error; the second
    // is still written, and the call returns the error.
    store.fail_next_pending_replace_after_commit();
    let failed = store
        .replace_pending_inbound_batch_if(
            vec![
                PendingInboundCas {
                    key: key("A"),
                    expected: revision(b"a1"),
                    replacement: put(b"a2"),
                },
                PendingInboundCas {
                    key: key("C"),
                    expected: revision(b"c1"),
                    replacement: put(b"c2"),
                },
            ],
            16,
        )
        .await;
    assert!(failed.is_err());
    assert_eq!(stored("A").await.as_deref(), Some(&b"a2"[..]));
    assert_eq!(
        stored("C").await.as_deref(),
        Some(&b"c2"[..]),
        "a row's error doesn't stop the rows after it"
    );

    let deleted = store
        .delete_pending_inbound_batch_if(
            &[(key("A"), revision(b"a2")), (key("B"), stale)],
            16,
            lease(),
        )
        .await
        .unwrap();
    assert_eq!(
        deleted,
        [
            PendingInboundMutation::Applied,
            PendingInboundMutation::Conflict
        ]
    );
    assert_eq!(stored("A").await, None);
    assert_eq!(stored("B").await.as_deref(), Some(&b"b0"[..]));

    // The first row's delete fails before it is applied; the second still is.
    store.fail_one_pending_delete(0, false);
    let failed = store
        .delete_pending_inbound_batch_if(
            &[(key("B"), revision(b"b0")), (key("C"), revision(b"c2"))],
            16,
            lease(),
        )
        .await;
    assert!(failed.is_err());
    assert_eq!(stored("B").await.as_deref(), Some(&b"b0"[..]));
    assert_eq!(
        stored("C").await,
        None,
        "a row's error doesn't stop the rows after it"
    );

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

/// Another writer changes one row while the batched call waits for the store:
/// before the hook (the journal write) or after it (the cleanup). The row
/// conflicts and stays as that writer left it, the batch's stanzas stay
/// unacked for redelivery, and the batch's other row is still written, or
/// still removed, as one call per row would have done.
#[tokio::test]
async fn batched_conflict_keeps_ack_withheld() {
    for gated in [REPLACE_BATCH, DELETE_BATCH] {
        let (entered, waiting) = async_channel::bounded(1);
        let (release, released) = async_channel::bounded(1);
        let harness = Harness::new(|probe| {
            probe.gate_method = gated;
            probe.entered = Some(entered);
            probe.gate = Some(released);
            probe.gate_once = true;
        })
        .await;
        let transport = capture_receipts(&harness.client).await;
        harness.drain(&["WF13_K1", "WF13_K2"]).await;

        let flush = tokio::spawn({
            let client = Arc::clone(&harness.client);
            async move {
                client
                    .flush_inbound_commits_under_permit(false, None, None)
                    .await
            }
        });
        waiting.recv().await.unwrap();
        harness
            .store
            .store_pending_inbound(CHAT, CHAT, "WF13_K1", b"successor")
            .await
            .unwrap();
        release.send(()).await.unwrap();
        let durable = flush.await.unwrap();

        crate::test_utils::wait_for_outbound_tasks(&harness.client).await;
        for id in ["WF13_K1", "WF13_K2"] {
            assert_eq!(
                delivery_receipts_for(&transport.sent(), id),
                0,
                "{gated}: {id} stays unacked"
            );
        }
        assert_eq!(
            harness.row("WF13_K1").await.as_deref(),
            Some(&b"successor"[..]),
            "{gated}: the conflicting row is the other writer's"
        );
        if gated == REPLACE_BATCH {
            assert!(!durable, "the journal write failed: nothing is durable");
            assert!(
                harness.hook_batches().is_empty(),
                "the hook is never called for a batch whose rows aren't written"
            );
            assert!(
                harness.row("WF13_K2").await.is_some(),
                "the other row was written"
            );
            assert_eq!(
                harness.client.inbound_commit_batch.pending_stats().0,
                2,
                "the batch is back in the batcher for its retry"
            );
        } else {
            assert!(durable, "the hook committed the batch");
            assert_eq!(harness.hook_batches().len(), 1);
            assert_eq!(
                harness.row("WF13_K2").await,
                None,
                "the other row was removed"
            );
        }
        assert_eq!(
            harness
                .journal_writes()
                .iter()
                .filter(|call| *call == gated)
                .count(),
            1,
            "{gated}: one batched call, which conflicted"
        );
    }
}

/// A row that also owes an undecryptable report (WF5) keeps it through the
/// batch: the journal write re-encodes it with the new occurrence, and the
/// cleanup leaves it alone in the row with one batched replacement beside the
/// batched delete of the other rows.
#[tokio::test]
async fn cleanup_keeps_owed_report_in_one_batched_replace() {
    let harness = Harness::new(|_| {}).await;
    let owed = OwedReport {
        decrypt_fail_mode: DecryptFailMode::Hide,
    };
    let owing = PendingInboundPayload::new(PendingJournal::owing_bytes(owed), lease());
    assert_eq!(
        harness
            .store
            .replace_pending_inbound_if(
                key(IDS[2]),
                PendingInboundRevision::missing(),
                owing,
                MAX_PENDING_BYTES
            )
            .await
            .unwrap(),
        PendingInboundMutation::Applied
    );
    harness.drain(&IDS).await;

    assert!(
        harness
            .client
            .flush_inbound_commits_under_permit(false, None, None)
            .await
    );

    assert_eq!(
        harness.journal_writes(),
        [REPLACE_BATCH, HOOK, DELETE_BATCH, REPLACE_BATCH],
        "the cleanup's rows go in one delete and one replacement"
    );
    assert_eq!(harness.row(IDS[0]).await, None);
    assert_eq!(harness.row(IDS[1]).await, None);
    let row = harness
        .row(IDS[2])
        .await
        .expect("the row that owes a report stays");
    let journal = PendingJournal::decode(row.into()).unwrap();
    assert_eq!(journal.owed, Some(owed), "the report is still owed");
    assert!(
        journal.occurrences.is_empty(),
        "what the batch committed is gone from the row"
    );
}
