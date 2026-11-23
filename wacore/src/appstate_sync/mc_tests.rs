//! WF3: every patch, snapshot and recovery hands its batch to
//! `AppStateMutationPersistence::persist_mutations` before the collection's
//! cursor moves, and a refusal leaves the cursor where it was; a caller that
//! retires before or during the batch's effects has none of its rows written.
//! WF14 at the end: on each path, a write the store refuses because another
//! writer moved the collection while the batch's commit was held leaves that
//! writer's state, and fails with the retryable conflict (a recovery answers
//! `RecoveryOutcome::Conflict`).
//!
//! The persistence below reads the store when it is called, so each test sees
//! what had been committed at that moment: neither the cursor nor the batch's
//! MAC rows, on any path. It also answers the caller's fence and journals each
//! ask beside its own calls, so a test sees where the processor asks.

use super::AppStateBatchKind::{Patch, Recovery, Snapshot};
use super::*;
use crate::appstate::hash::{generate_content_mac, generate_index_mac};
use crate::libsignal::crypto::aes_256_cbc_encrypt_into;
use crate::runtime::{AbortHandle, Runtime};
use crate::store::InMemoryBackend;
use crate::store::traits::{AppStateSyncKey, AppSyncStore};
use futures::channel::oneshot;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use wa::syncd_mutation::SyncdOperation;

const COLLECTION: WAPatchName = WAPatchName::Regular;
const KEY_ID: &[u8] = b"wf3-app-state-key";
const MASTER_KEY: [u8; 32] = [0x33; 32];
const FIRST_CHAT: &str = "120363000000000042@g.us";
const SECOND_CHAT: &str = "120363000000000043@g.us";
const THIRD_CHAT: &str = "120363000000000044@g.us";
const FOURTH_CHAT: &str = "120363000000000045@g.us";
const RECOVERED_HASH: [u8; 128] = [0x5A; 128];
const NEWER_HASH: [u8; 128] = [0x6B; 128];

struct TokioRuntime;

#[async_trait]
impl Runtime for TokioRuntime {
    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) -> AbortHandle {
        let handle = tokio::spawn(future);
        AbortHandle::new(move || handle.abort())
    }
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(tokio::time::sleep(duration))
    }
    fn spawn_blocking(
        &self,
        f: Box<dyn FnOnce() + Send>,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(async move {
            tokio::task::spawn_blocking(f)
                .await
                .expect("blocking worker");
        })
    }
    fn yield_now(&self) -> Option<Pin<Box<dyn Future<Output = ()> + Send>>> {
        None
    }
}

/// One call the processor made into the persistence, with the stored cursor
/// (and, for a batch, how many of its MAC rows were stored) at that moment, or
/// one ask of the caller's fence.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Call {
    StatusPrivacy {
        cursor: Option<u64>,
    },
    LidMappings {
        cursor: Option<u64>,
    },
    Batch {
        collection: String,
        kind: AppStateBatchKind,
        version: u64,
        indexes: Vec<Vec<String>>,
        full_sync: bool,
        cursor: Option<u64>,
        macs_stored: usize,
    },
    Asked {
        current: bool,
    },
}

#[derive(Debug, thiserror::Error)]
#[error("the host refused the commit")]
struct Refused;

/// Holds one `persist_mutations` call until the test lets it go, as a host
/// commit waiting on its database would.
struct Park {
    call: usize,
    entered: oneshot::Sender<()>,
    release: oneshot::Receiver<()>,
}

struct Recorder {
    backend: Arc<InMemoryBackend>,
    calls: std::sync::Mutex<Vec<Call>>,
    /// The first `persist_mutations` call to refuse, counting from 0;
    /// `usize::MAX` accepts every call.
    refuse_from: AtomicUsize,
    mutation_calls: AtomicUsize,
    /// What the caller's fence answers: whether its connection is still live.
    current: AtomicBool,
    /// The `persist_mutations` call during which the caller retires;
    /// `usize::MAX` for none.
    retire_during: AtomicUsize,
    park: std::sync::Mutex<Option<Park>>,
}

impl Recorder {
    async fn cursor(&self) -> Option<u64> {
        self.backend
            .get_version(COLLECTION.as_str())
            .await
            .expect("the in-memory store reads")
            .map(|state| state.version)
    }

    fn push(&self, call: Call) {
        self.calls.lock().expect("journal lock").push(call);
    }

    fn refuse_from(&self, call: usize) {
        self.refuse_from.store(call, Ordering::SeqCst);
    }

    fn take_calls(&self) -> Vec<Call> {
        std::mem::take(&mut *self.calls.lock().expect("journal lock"))
    }

    /// The caller's connection goes: every later ask of its fence is `false`.
    fn retire(&self) {
        self.current.store(false, Ordering::SeqCst);
    }

    /// The caller's fence, journalling each ask.
    fn fence(self: &Arc<Self>) -> impl Fn() -> bool + Send + Sync + 'static {
        let recorder = Arc::clone(self);
        move || {
            let current = recorder.current.load(Ordering::SeqCst);
            recorder.push(Call::Asked { current });
            current
        }
    }

    /// Park `persist_mutations` call `call` (from 0): the first receiver
    /// resolves once it is parked, and sending on the second lets it return.
    fn park_at(&self, call: usize) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (entered, parked) = oneshot::channel();
        let (release, released) = oneshot::channel();
        *self.park.lock().expect("park lock") = Some(Park {
            call,
            entered,
            release: released,
        });
        (parked, release)
    }
}

#[async_trait]
impl AppStateMutationPersistence for Recorder {
    async fn persist_status_privacy(
        &self,
        _action: &wa::sync_action_value::StatusPrivacyAction,
    ) -> crate::store::error::Result<()> {
        let cursor = self.cursor().await;
        self.push(Call::StatusPrivacy { cursor });
        Ok(())
    }

    async fn persist_lid_pn_mappings(
        &self,
        _mappings: Vec<(String, String)>,
    ) -> crate::store::error::Result<()> {
        let cursor = self.cursor().await;
        self.push(Call::LidMappings { cursor });
        Ok(())
    }

    async fn persist_mutations(&self, batch: AppStateBatch<'_>) -> Result<()> {
        let indexes: Vec<Vec<String>> = batch.mutations.iter().map(|m| m.index.clone()).collect();
        let macs_stored = stored_macs(&self.backend, &indexes).await;
        let cursor = self.cursor().await;
        self.push(Call::Batch {
            collection: batch.collection.to_string(),
            kind: batch.kind,
            version: batch.version,
            indexes,
            full_sync: batch.full_sync,
            cursor,
            macs_stored,
        });
        let call = self.mutation_calls.fetch_add(1, Ordering::SeqCst);
        let park = {
            let mut slot = self.park.lock().expect("park lock");
            if slot.as_ref().is_some_and(|park| park.call == call) {
                slot.take()
            } else {
                None
            }
        };
        if let Some(park) = park {
            park.entered.send(()).expect("the test waits for the park");
            park.release.await.expect("the test releases the park");
        }
        if call == self.retire_during.load(Ordering::SeqCst) {
            self.retire();
        }
        if call >= self.refuse_from.load(Ordering::SeqCst) {
            return Err(Refused.into());
        }
        Ok(())
    }
}

/// How many of these indexes have a MAC row in the collection.
async fn stored_macs(backend: &InMemoryBackend, indexes: &[Vec<String>]) -> usize {
    let index_key = expand_app_state_keys(&MASTER_KEY).index;
    let index_macs: Vec<IndexMac> = indexes
        .iter()
        .map(|index| {
            let index = serde_json::to_vec(index).expect("an index encodes");
            generate_index_mac(&index, &index_key)
                .try_into()
                .expect("an index MAC is 32 bytes")
        })
        .collect();
    backend
        .get_mutation_macs(COLLECTION.as_str(), &index_macs)
        .await
        .expect("the in-memory store reads")
        .len()
}

struct Fixture {
    backend: Arc<InMemoryBackend>,
    recorder: Arc<Recorder>,
    processor: AppStateProcessor,
}

async fn setup() -> Fixture {
    let backend = Arc::new(InMemoryBackend::new());
    backend
        .set_sync_key(
            KEY_ID,
            AppStateSyncKey {
                key_data: MASTER_KEY.to_vec(),
                ..Default::default()
            },
        )
        .await
        .expect("the in-memory store takes a key");
    let recorder = Arc::new(Recorder {
        backend: backend.clone(),
        calls: std::sync::Mutex::new(Vec::new()),
        refuse_from: AtomicUsize::new(usize::MAX),
        mutation_calls: AtomicUsize::new(0),
        current: AtomicBool::new(true),
        retire_during: AtomicUsize::new(usize::MAX),
        park: std::sync::Mutex::new(None),
    });
    let processor = AppStateProcessor::new(backend.clone(), Arc::new(TokioRuntime))
        .with_mutation_persistence(recorder.clone());
    Fixture {
        backend,
        recorder,
        processor,
    }
}

impl Fixture {
    async fn macs(&self, entries: &[&Entry]) -> usize {
        stored_macs(&self.backend, &indexes(entries)).await
    }

    async fn stored(&self) -> Option<HashState> {
        self.backend
            .get_version(COLLECTION.as_str())
            .await
            .expect("the in-memory store reads")
    }

    /// A MAC row for `entry` from an earlier state of the collection.
    async fn seed_mac(&self, entry: &Entry) {
        self.backend
            .put_mutation_macs(COLLECTION.as_str(), 1, &[mac_row(entry)])
            .await
            .expect("the in-memory store takes a MAC row");
    }

    async fn seed(&self, state: HashState) {
        self.backend
            .set_version(COLLECTION.as_str(), state)
            .await
            .expect("the in-memory store takes a version");
    }

    /// What the next connection's sync commits while the old connection's
    /// apply is parked: `entry` at v`version`, with its own ltHash.
    async fn newer_connection_commits(&self, version: u64, entry: &Entry) {
        self.backend
            .commit_patch(
                COLLECTION.as_str(),
                newer_state(version),
                &[],
                &[mac_row(entry)],
            )
            .await
            .expect("the in-memory store takes a patch");
    }

    async fn prepared(&self, list: PatchList) -> PreparedPatchList {
        self.processor
            .prepare_patch_list(list, &|_| panic!("the fixtures carry no external blob"))
            .await
    }
}

/// The collection as this side held it before the batch.
fn held_state(version: u64) -> HashState {
    HashState {
        version,
        hash: [0x11; 128],
        bootstrapped: true,
        ..Default::default()
    }
}

/// The collection as the next connection's sync left it.
fn newer_state(version: u64) -> HashState {
    HashState {
        version,
        hash: NEWER_HASH,
        bootstrapped: true,
        ..Default::default()
    }
}

/// One action as the primary writes it: its JSON index and its value.
struct Entry {
    index: Vec<u8>,
    value: wa::SyncActionValue,
}

impl Entry {
    fn index_of(&self) -> Vec<String> {
        serde_json::from_slice(&self.index).expect("the fixture's index is JSON")
    }
}

fn archive(chat: &str, archived: bool, timestamp: i64) -> Entry {
    let mut value = wa::SyncActionValue::default();
    value.timestamp = Some(timestamp);
    value.archive_chat_action = buffa::MessageField::some({
        let mut action = wa::sync_action_value::ArchiveChatAction::default();
        action.archived = Some(archived);
        action
    });
    Entry {
        index: serde_json::to_vec(&["archive", chat]).expect("an index encodes"),
        value,
    }
}

fn status_privacy(timestamp: i64) -> Entry {
    let mut value = wa::SyncActionValue::default();
    value.timestamp = Some(timestamp);
    value.status_privacy = buffa::MessageField::some({
        let mut action = wa::sync_action_value::StatusPrivacyAction::default();
        action.mode = Some(buffa::EnumValue::Unknown(99));
        action
    });
    Entry {
        index: serde_json::to_vec(&["status_privacy"]).expect("an index encodes"),
        value,
    }
}

fn pn_for_lid_chat(timestamp: i64) -> Entry {
    let mut value = wa::SyncActionValue::default();
    value.timestamp = Some(timestamp);
    value.pn_for_lid_chat_action.get_or_insert_default().pn_jid =
        Some("12025550111@s.whatsapp.net".into());
    Entry {
        index: serde_json::to_vec(&["pnForLidChat", "100000001@lid"]).expect("an index encodes"),
        value,
    }
}

fn indexes(entries: &[&Entry]) -> Vec<Vec<String>> {
    entries.iter().map(|entry| entry.index_of()).collect()
}

/// A stored MAC row for `entry`'s index.
fn mac_row(entry: &Entry) -> AppStateMutationMAC {
    AppStateMutationMAC {
        index_mac: generate_index_mac(&entry.index, &expand_app_state_keys(&MASTER_KEY).index),
        value_mac: vec![0x22; 32],
    }
}

fn key_id() -> wa::KeyId {
    let mut key = wa::KeyId::default();
    key.id = Some(KEY_ID.to_vec());
    key
}

fn version(version: u64) -> buffa::MessageField<wa::SyncdVersion> {
    let mut proto = wa::SyncdVersion::default();
    proto.version = Some(version);
    buffa::MessageField::some(proto)
}

/// The encrypted record for `entry`, with its real index and content MACs.
fn record(entry: &Entry) -> wa::SyncdRecord {
    let keys = expand_app_state_keys(&MASTER_KEY);
    let plaintext = waproto::codec::sync_action_data_to_vec(&entry.index, &entry.value, 0);
    let mut blob = vec![0u8; 16];
    let mut ciphertext = Vec::new();
    aes_256_cbc_encrypt_into(&plaintext, &keys.value_encryption, &blob, &mut ciphertext)
        .expect("AES-CBC takes a 32-byte key and a 16-byte IV");
    blob.extend_from_slice(&ciphertext);
    let value_mac = generate_content_mac(SyncdOperation::SET, &blob, KEY_ID, &keys.value_mac);
    blob.extend_from_slice(&value_mac);

    let mut record = wa::SyncdRecord::default();
    record.index = buffa::MessageField::some({
        let mut index = wa::SyncdIndex::default();
        index.blob = Some(generate_index_mac(&entry.index, &keys.index));
        index
    });
    record.value = buffa::MessageField::some({
        let mut value = wa::SyncdValue::default();
        value.blob = Some(blob);
        value
    });
    record.key_id = buffa::MessageField::some(key_id());
    record
}

/// A patch the processor applies with `validate_macs = false`: its MAC fields
/// are present, as the metadata checks require, but not computed.
fn patch(at: u64, entries: &[&Entry]) -> wa::SyncdPatch {
    let mut patch = wa::SyncdPatch::default();
    patch.version = version(at);
    patch.mutations = entries
        .iter()
        .map(|entry| {
            let mut mutation = wa::SyncdMutation::default();
            mutation.operation = Some(SyncdOperation::SET.into());
            mutation.record = buffa::MessageField::some(record(entry));
            mutation
        })
        .collect();
    patch.key_id = buffa::MessageField::some(key_id());
    patch.snapshot_mac = Some(vec![0; 32]);
    patch.patch_mac = Some(vec![0; 32]);
    patch
}

fn snapshot(at: u64, entries: &[&Entry]) -> wa::SyncdSnapshot {
    let mut snapshot = wa::SyncdSnapshot::default();
    snapshot.version = version(at);
    snapshot.records = entries.iter().map(|entry| record(entry)).collect();
    snapshot.key_id = buffa::MessageField::some(key_id());
    snapshot.mac = Some(vec![0; 32]);
    snapshot
}

fn list(snapshot: Option<wa::SyncdSnapshot>, patches: Vec<wa::SyncdPatch>) -> PatchList {
    PatchList {
        name: COLLECTION,
        has_more_patches: false,
        patches,
        snapshot,
        snapshot_ref: None,
        error: None,
    }
}

/// The collection as the primary sends it back: records in the clear.
fn recovery(at: u64, entries: &[&Entry]) -> wa::SyncdSnapshotRecovery {
    let mut recovery = wa::SyncdSnapshotRecovery::default();
    recovery.version = version(at);
    recovery.collection_name = Some(COLLECTION.as_str().to_string());
    recovery.collection_lthash = Some(RECOVERED_HASH.to_vec());
    recovery.mutation_records = entries
        .iter()
        .map(|entry| {
            let mut record = wa::SyncdPlainTextRecord::default();
            record.value = buffa::MessageField::some({
                let mut data = wa::SyncActionData::default();
                data.index = Some(entry.index.clone());
                data.value = buffa::MessageField::some(entry.value.clone());
                data
            });
            record.key_id = Some(KEY_ID.to_vec());
            record.mac = Some(vec![0x11; 32]);
            record
        })
        .collect();
    recovery
}

/// The call a batch of `kind` bringing the collection to `version` makes,
/// seeing the cursor at `cursor` and none of its own MAC rows.
fn batch(
    kind: AppStateBatchKind,
    version: u64,
    entries: &[&Entry],
    full_sync: bool,
    cursor: Option<u64>,
) -> Call {
    Call::Batch {
        collection: COLLECTION.as_str().to_string(),
        kind,
        version,
        indexes: indexes(entries),
        full_sync,
        cursor,
        macs_stored: 0,
    }
}

fn asked(current: bool) -> Call {
    Call::Asked { current }
}

fn returned_indexes(mutations: &[Mutation]) -> Vec<Vec<String>> {
    mutations.iter().map(|m| m.index.clone()).collect()
}

fn is_retired(error: &anyhow::Error) -> bool {
    matches!(
        error.downcast_ref::<AppStateSyncError>(),
        Some(AppStateSyncError::Retired)
    )
}

#[tokio::test]
async fn appstate_hook_runs_before_commit_patch_on_patch_path() {
    let fixture = setup().await;
    let archived = archive(FIRST_CHAT, true, 1_000);
    let audience = status_privacy(1_001);
    let mapping = pn_for_lid_chat(1_002);
    let first = [&archived, &audience, &mapping];

    let prepared = fixture.prepared(list(None, vec![patch(1, &first)])).await;
    let (mutations, state, _) = fixture
        .processor
        .process_prepared_patch_list(prepared, false, Provenance::Live, UNFENCED)
        .await
        .expect("the genesis patch applies");

    // The library's own effects first, then the batch, all before
    // `commit_patch`: nothing was stored, the cursor or the patch's MACs.
    assert_eq!(
        fixture.recorder.take_calls(),
        vec![
            Call::StatusPrivacy { cursor: None },
            Call::LidMappings { cursor: None },
            batch(Patch, 1, &first, false, None),
        ]
    );
    assert_eq!(returned_indexes(&mutations), indexes(&first));
    assert_eq!(state.version, 1);
    assert_eq!(fixture.stored().await.map(|s| s.version), Some(1));

    // On a collection with a cursor, the batch sees it unmoved.
    let unarchived = archive(SECOND_CHAT, false, 2_000);
    let prepared = fixture
        .prepared(list(None, vec![patch(2, &[&unarchived])]))
        .await;
    fixture
        .processor
        .process_prepared_patch_list(prepared, false, Provenance::Live, UNFENCED)
        .await
        .expect("the next patch applies");
    assert_eq!(
        fixture.recorder.take_calls(),
        vec![batch(Patch, 2, &[&unarchived], false, Some(1))]
    );
    assert_eq!(fixture.stored().await.map(|s| s.version), Some(2));
}

#[tokio::test]
async fn appstate_hook_runs_before_set_version_on_snapshot_path() {
    let fixture = setup().await;
    let first = archive(FIRST_CHAT, true, 1_000);
    let second = archive(SECOND_CHAT, true, 1_001);
    let after = archive(THIRD_CHAT, true, 2_000);

    let prepared = fixture
        .prepared(list(
            Some(snapshot(5, &[&first, &second])),
            vec![patch(6, &[&after])],
        ))
        .await;
    let (mutations, state, _) = fixture
        .processor
        .process_prepared_patch_list(prepared, false, Provenance::FullSync, UNFENCED)
        .await
        .expect("the snapshot and its patch apply");

    // The snapshot's batch comes before its MAC rows and `set_version`; the
    // patch after it sees the snapshot's cursor. Both carry the caller's
    // provenance.
    assert_eq!(
        fixture.recorder.take_calls(),
        vec![
            batch(Snapshot, 5, &[&first, &second], true, None),
            batch(Patch, 6, &[&after], true, Some(5)),
        ]
    );
    assert_eq!(
        returned_indexes(&mutations),
        indexes(&[&first, &second, &after])
    );
    assert_eq!(state.version, 6);
    assert_eq!(fixture.stored().await.map(|s| s.version), Some(6));
    assert_eq!(fixture.macs(&[&first, &second, &after]).await, 3);
}

#[tokio::test]
async fn appstate_hook_runs_before_set_version_on_recovery_path() {
    let fixture = setup().await;
    fixture.seed(held_state(3)).await;
    let stale = archive(THIRD_CHAT, true, 900);
    fixture.seed_mac(&stale).await;
    let first = archive(FIRST_CHAT, false, 1_000);
    let second = archive(SECOND_CHAT, true, 1_001);

    let outcome = fixture
        .processor
        .apply_snapshot_recovery(
            recovery(9, &[&first, &second]),
            COLLECTION.as_str(),
            UNFENCED,
        )
        .await
        .expect("the recovery applies");

    // Before the MAC rewrite and `set_version`, and always as a full sync.
    assert_eq!(
        fixture.recorder.take_calls(),
        vec![batch(Recovery, 9, &[&first, &second], true, Some(3))]
    );
    let RecoveryOutcome::Applied(mutations) = outcome else {
        panic!("expected the recovery to apply, got {outcome:?}");
    };
    assert_eq!(returned_indexes(&mutations), indexes(&[&first, &second]));
    let stored = fixture.stored().await.expect("the recovery wrote a cursor");
    assert_eq!(stored.version, 9);
    assert_eq!(stored.hash, RECOVERED_HASH);
    // Then the rewrite: the recovered rows in, the old one gone.
    assert_eq!(fixture.macs(&[&first, &second]).await, 2);
    assert_eq!(fixture.macs(&[&stale]).await, 0);
}

#[tokio::test]
async fn appstate_hook_error_keeps_cursor() {
    let first = archive(FIRST_CHAT, true, 1_000);
    let second = archive(SECOND_CHAT, true, 1_001);
    let stale = archive(THIRD_CHAT, true, 900);

    // Patch path. Refused on the first patch: nothing is committed, and the
    // host's own error comes back.
    let fixture = setup().await;
    let patches = || vec![patch(1, &[&first]), patch(2, &[&second])];
    fixture.recorder.refuse_from(0);
    let prepared = fixture.prepared(list(None, patches())).await;
    let error = fixture
        .processor
        .process_prepared_patch_list(prepared, false, Provenance::Live, UNFENCED)
        .await
        .expect_err("a refused commit fails the list");
    assert!(error.downcast_ref::<Refused>().is_some(), "{error:#}");
    assert!(fixture.stored().await.is_none());
    assert_eq!(
        fixture.recorder.take_calls(),
        vec![batch(Patch, 1, &[&first], false, None)]
    );

    // Refused on the second: the first patch stays committed and comes back
    // for dispatch, and the cursor stops after it.
    fixture.recorder.mutation_calls.store(0, Ordering::SeqCst);
    fixture.recorder.refuse_from(1);
    let prepared = fixture.prepared(list(None, patches())).await;
    let error = fixture
        .processor
        .process_prepared_patch_list(prepared, false, Provenance::Live, UNFENCED)
        .await
        .expect_err("a refused commit fails the list");
    let committed = error
        .downcast::<CommittedMutationsError>()
        .expect("the first patch was committed");
    let (mutations, state, collection, source) = committed.into_parts();
    assert_eq!(returned_indexes(&mutations), indexes(&[&first]));
    assert_eq!((state.version, collection), (1, COLLECTION));
    assert!(source.downcast_ref::<Refused>().is_some(), "{source:#}");
    assert_eq!(fixture.stored().await.map(|s| s.version), Some(1));
    assert_eq!(
        (
            fixture.macs(&[&first]).await,
            fixture.macs(&[&second]).await
        ),
        (1, 0)
    );
    assert_eq!(
        fixture.recorder.take_calls(),
        vec![
            batch(Patch, 1, &[&first], false, None),
            batch(Patch, 2, &[&second], false, Some(1)),
        ]
    );

    // The next sync offers the refused patch again, from that cursor.
    fixture.recorder.refuse_from(usize::MAX);
    let prepared = fixture
        .prepared(list(None, vec![patch(2, &[&second])]))
        .await;
    fixture
        .processor
        .process_prepared_patch_list(prepared, false, Provenance::Live, UNFENCED)
        .await
        .expect("the replayed patch applies");
    assert_eq!(
        fixture.recorder.take_calls(),
        vec![batch(Patch, 2, &[&second], false, Some(1))]
    );
    assert_eq!(fixture.stored().await.map(|s| s.version), Some(2));

    // Snapshot path: neither the cursor nor the MAC rows move, an earlier row
    // included, so the same snapshot is not stale and applies on the next
    // attempt.
    let fixture = setup().await;
    fixture.seed_mac(&stale).await;
    fixture.recorder.refuse_from(0);
    let snapshot_list = || list(Some(snapshot(5, &[&first, &second])), Vec::new());
    let prepared = fixture.prepared(snapshot_list()).await;
    let error = fixture
        .processor
        .process_prepared_patch_list(prepared, false, Provenance::FullSync, UNFENCED)
        .await
        .expect_err("a refused commit fails the snapshot");
    assert!(error.downcast_ref::<Refused>().is_some(), "{error:#}");
    assert!(fixture.stored().await.is_none());
    assert_eq!(
        (
            fixture.macs(&[&first, &second]).await,
            fixture.macs(&[&stale]).await
        ),
        (0, 1)
    );
    fixture.recorder.refuse_from(usize::MAX);
    let prepared = fixture.prepared(snapshot_list()).await;
    fixture
        .processor
        .process_prepared_patch_list(prepared, false, Provenance::FullSync, UNFENCED)
        .await
        .expect("the replayed snapshot applies");
    assert_eq!(
        fixture.recorder.take_calls(),
        vec![
            batch(Snapshot, 5, &[&first, &second], true, None),
            batch(Snapshot, 5, &[&first, &second], true, None),
        ]
    );
    assert_eq!(fixture.stored().await.map(|s| s.version), Some(5));
    assert_eq!(
        (
            fixture.macs(&[&first, &second]).await,
            fixture.macs(&[&stale]).await
        ),
        (2, 0)
    );

    // Recovery path: the cursor keeps its version and ltHash, and the MAC
    // rows are not rewritten.
    let fixture = setup().await;
    let held = held_state(3);
    fixture.seed(held.clone()).await;
    fixture.seed_mac(&stale).await;
    fixture.recorder.refuse_from(0);
    let error = fixture
        .processor
        .apply_snapshot_recovery(
            recovery(9, &[&first, &second]),
            COLLECTION.as_str(),
            UNFENCED,
        )
        .await
        .expect_err("a refused commit fails the recovery");
    assert!(error.downcast_ref::<Refused>().is_some(), "{error:#}");
    let stored = fixture.stored().await.expect("the held cursor stays");
    assert_eq!((stored.version, stored.hash), (held.version, held.hash));
    assert_eq!(
        (
            fixture.macs(&[&first, &second]).await,
            fixture.macs(&[&stale]).await
        ),
        (0, 1)
    );
    fixture.recorder.refuse_from(usize::MAX);
    let outcome = fixture
        .processor
        .apply_snapshot_recovery(
            recovery(9, &[&first, &second]),
            COLLECTION.as_str(),
            UNFENCED,
        )
        .await
        .expect("the repeated recovery applies");
    assert!(matches!(outcome, RecoveryOutcome::Applied(_)));
    assert_eq!(
        fixture.recorder.take_calls(),
        vec![
            batch(Recovery, 9, &[&first, &second], true, Some(3)),
            batch(Recovery, 9, &[&first, &second], true, Some(3)),
        ]
    );
    assert_eq!(fixture.stored().await.map(|s| s.version), Some(9));
    assert_eq!(
        (
            fixture.macs(&[&first, &second]).await,
            fixture.macs(&[&stale]).await
        ),
        (2, 0)
    );
}

/// The prepared entry points carry the caller's provenance, whatever the
/// batch's kind; the entry points that apply one list on their own report a
/// full sync when it carries a snapshot.
#[tokio::test]
async fn appstate_hook_full_sync_is_the_callers_provenance() {
    let first = archive(FIRST_CHAT, true, 1_000);
    let second = archive(SECOND_CHAT, true, 1_001);
    let third = archive(THIRD_CHAT, true, 1_002);
    let fourth = archive(FOURTH_CHAT, true, 1_003);

    // A page of a rebuild that carries no snapshot of its own.
    let fixture = setup().await;
    let prepared = fixture
        .prepared(list(None, vec![patch(1, &[&first])]))
        .await;
    fixture
        .processor
        .process_one_prepared_patch_list(prepared, false, Provenance::FullSync, UNFENCED)
        .await
        .expect("the page applies");
    let prepared = fixture
        .prepared(list(None, vec![patch(2, &[&second])]))
        .await;
    fixture
        .processor
        .process_prepared_patch_list(prepared, false, Provenance::FullSync, UNFENCED)
        .await
        .expect("the page applies");
    assert_eq!(
        fixture.recorder.take_calls(),
        vec![
            batch(Patch, 1, &[&first], true, None),
            batch(Patch, 2, &[&second], true, Some(1)),
        ]
    );

    // A snapshot a conflicting patch send absorbs: the whole collection, and
    // still live.
    let fixture = setup().await;
    let prepared = fixture
        .prepared(list(
            Some(snapshot(5, &[&first, &second])),
            vec![patch(6, &[&third])],
        ))
        .await;
    fixture
        .processor
        .process_prepared_patch_list(prepared, false, Provenance::Live, UNFENCED)
        .await
        .expect("the absorbed snapshot applies");
    assert_eq!(
        fixture.recorder.take_calls(),
        vec![
            batch(Snapshot, 5, &[&first, &second], false, None),
            batch(Patch, 6, &[&third], false, Some(5)),
        ]
    );

    // On their own: a patch-only list is live, a list with a snapshot is not.
    let fixture = setup().await;
    fixture
        .processor
        .process_patch_list(
            list(
                Some(snapshot(5, &[&first, &second])),
                vec![patch(6, &[&third])],
            ),
            false,
        )
        .await
        .expect("the snapshot list applies");
    fixture
        .processor
        .process_patch_list(list(None, vec![patch(7, &[&fourth])]), false)
        .await
        .expect("the patch list applies");
    assert_eq!(
        fixture.recorder.take_calls(),
        vec![
            batch(Snapshot, 5, &[&first, &second], true, None),
            batch(Patch, 6, &[&third], true, Some(5)),
            batch(Patch, 7, &[&fourth], false, Some(6)),
        ]
    );
}

/// An empty snapshot or recovery says the collection is empty, so it is
/// reported; an empty patch changes nothing and is not.
#[tokio::test]
async fn appstate_hook_hears_an_empty_collection_but_not_an_empty_patch() {
    let fixture = setup().await;
    fixture
        .processor
        .process_patch_list(list(Some(snapshot(5, &[])), vec![patch(6, &[])]), false)
        .await
        .expect("the empty list applies");
    assert_eq!(
        fixture.recorder.take_calls(),
        vec![batch(Snapshot, 5, &[], true, None)]
    );
    assert_eq!(fixture.stored().await.map(|s| s.version), Some(6));

    let outcome = fixture
        .processor
        .apply_snapshot_recovery(recovery(9, &[]), COLLECTION.as_str(), UNFENCED)
        .await
        .expect("the empty recovery applies");
    assert!(
        matches!(&outcome, RecoveryOutcome::Applied(mutations) if mutations.is_empty()),
        "{outcome:?}"
    );
    assert_eq!(
        fixture.recorder.take_calls(),
        vec![batch(Recovery, 9, &[], true, Some(6))]
    );
    assert_eq!(fixture.stored().await.map(|s| s.version), Some(9));
}

/// A reconnect lands while the host commits v12: the disconnect retires the
/// caller and clears its reservation, and the next connection's sync commits
/// v13. Released, the old apply writes nothing over it: v11, committed before
/// the reconnect, comes back for dispatch, and v12 is the next sync's to fetch.
#[tokio::test]
async fn appstate_hook_parked_across_a_reconnect_commits_no_patch() {
    let fixture = setup().await;
    fixture.seed(held_state(10)).await;
    let committed = archive(FIRST_CHAT, true, 1_000);
    let parked = archive(SECOND_CHAT, true, 1_001);
    let newer = archive(THIRD_CHAT, true, 1_002);

    let (entered, release) = fixture.recorder.park_at(1);
    let still_current = fixture.recorder.fence();
    let prepared = fixture
        .prepared(list(
            None,
            vec![patch(11, &[&committed]), patch(12, &[&parked])],
        ))
        .await;
    let apply = fixture.processor.process_prepared_patch_list(
        prepared,
        false,
        Provenance::Live,
        &still_current,
    );
    let reconnect = async {
        entered.await.expect("the hook parks");
        fixture.recorder.retire();
        fixture.newer_connection_commits(13, &newer).await;
        release.send(()).expect("the hook is parked");
    };
    let (applied, ()) = futures::join!(apply, reconnect);

    let (mutations, state, collection, source) = applied
        .expect_err("a retired apply fails the list")
        .downcast::<CommittedMutationsError>()
        .expect("v11 was committed before the reconnect")
        .into_parts();
    assert_eq!(returned_indexes(&mutations), indexes(&[&committed]));
    assert_eq!((state.version, collection), (11, COLLECTION));
    assert!(is_retired(&source), "{source:#}");
    let stored = fixture.stored().await.expect("the newer cursor stays");
    assert_eq!((stored.version, stored.hash), (13, NEWER_HASH));
    assert_eq!(
        (
            fixture.macs(&[&committed]).await,
            fixture.macs(&[&parked]).await,
            fixture.macs(&[&newer]).await
        ),
        (1, 0, 1)
    );
    // Asked once the collection is read, then before and after each batch's
    // effects: the last ask, after the hook, is the one that stops v12.
    assert_eq!(
        fixture.recorder.take_calls(),
        vec![
            asked(true),
            asked(true),
            batch(Patch, 11, &[&committed], false, Some(10)),
            asked(true),
            asked(true),
            batch(Patch, 12, &[&parked], false, Some(11)),
            asked(false),
        ]
    );
}

/// The same reconnect on the snapshot path: the old apply's MAC rewrite would
/// have wiped the next connection's rows and its `set_version` rolled the
/// collection back to v5.
#[tokio::test]
async fn appstate_hook_parked_across_a_reconnect_commits_no_snapshot() {
    let fixture = setup().await;
    let first = archive(FIRST_CHAT, true, 1_000);
    let second = archive(SECOND_CHAT, true, 1_001);
    let newer = archive(THIRD_CHAT, true, 1_002);

    let (entered, release) = fixture.recorder.park_at(0);
    let still_current = fixture.recorder.fence();
    let prepared = fixture
        .prepared(list(Some(snapshot(5, &[&first, &second])), Vec::new()))
        .await;
    let apply = fixture.processor.process_prepared_patch_list(
        prepared,
        false,
        Provenance::FullSync,
        &still_current,
    );
    let reconnect = async {
        entered.await.expect("the hook parks");
        fixture.recorder.retire();
        fixture.newer_connection_commits(6, &newer).await;
        release.send(()).expect("the hook is parked");
    };
    let (applied, ()) = futures::join!(apply, reconnect);

    let error = applied.expect_err("a retired apply fails the list");
    assert!(is_retired(&error), "{error:#}");
    let stored = fixture.stored().await.expect("the newer cursor stays");
    assert_eq!((stored.version, stored.hash), (6, NEWER_HASH));
    assert_eq!(
        (
            fixture.macs(&[&first, &second]).await,
            fixture.macs(&[&newer]).await
        ),
        (0, 1)
    );
    assert_eq!(
        fixture.recorder.take_calls(),
        vec![
            asked(true),
            asked(true),
            batch(Snapshot, 5, &[&first, &second], true, None),
            asked(false),
        ]
    );
}

/// A recovery whose connection went while its records were being read and
/// MACed persists nothing: not the status-privacy audience, which would
/// overwrite a newer one the next connection synced, not the LID mappings, and
/// not the host's commit.
#[tokio::test]
async fn appstate_recovery_retired_before_its_effects_persists_nothing() {
    let fixture = setup().await;
    let held = held_state(3);
    fixture.seed(held.clone()).await;
    let stale = archive(FOURTH_CHAT, true, 900);
    fixture.seed_mac(&stale).await;
    let audience = status_privacy(1_000);
    let mapping = pn_for_lid_chat(1_001);
    let archived = archive(FIRST_CHAT, true, 1_002);
    let records = [&audience, &mapping, &archived];

    // The processor's first ask stands for every retirement between the
    // caller's own check and the records' effects.
    fixture.recorder.retire();
    let still_current = fixture.recorder.fence();
    let outcome = fixture
        .processor
        .apply_snapshot_recovery(recovery(9, &records), COLLECTION.as_str(), &still_current)
        .await
        .expect("a retired recovery is dropped, not an error");
    assert!(matches!(outcome, RecoveryOutcome::Retired), "{outcome:?}");
    assert_eq!(fixture.recorder.take_calls(), vec![asked(false)]);
    let stored = fixture.stored().await.expect("the held cursor stays");
    assert_eq!((stored.version, stored.hash), (held.version, held.hash));
    assert_eq!(
        (fixture.macs(&records).await, fixture.macs(&[&stale]).await),
        (0, 1)
    );
}

/// A recovery whose connection goes while the host commits it has its effects
/// persisted, and none of the collection's rows written.
#[tokio::test]
async fn appstate_recovery_retired_during_the_hook_writes_no_rows() {
    let fixture = setup().await;
    let held = held_state(3);
    fixture.seed(held.clone()).await;
    let stale = archive(FOURTH_CHAT, true, 900);
    fixture.seed_mac(&stale).await;
    let audience = status_privacy(1_000);
    let mapping = pn_for_lid_chat(1_001);
    let archived = archive(FIRST_CHAT, true, 1_002);
    let records = [&audience, &mapping, &archived];

    fixture.recorder.retire_during.store(0, Ordering::SeqCst);
    let still_current = fixture.recorder.fence();
    let outcome = fixture
        .processor
        .apply_snapshot_recovery(recovery(9, &records), COLLECTION.as_str(), &still_current)
        .await
        .expect("a retired recovery is dropped, not an error");
    assert!(matches!(outcome, RecoveryOutcome::Retired), "{outcome:?}");
    assert_eq!(
        fixture.recorder.take_calls(),
        vec![
            asked(true),
            Call::StatusPrivacy { cursor: Some(3) },
            Call::LidMappings { cursor: Some(3) },
            batch(Recovery, 9, &records, true, Some(3)),
            asked(false),
        ]
    );
    let stored = fixture.stored().await.expect("the held cursor stays");
    assert_eq!((stored.version, stored.hash), (held.version, held.hash));
    assert_eq!(
        (fixture.macs(&records).await, fixture.macs(&[&stale]).await),
        (0, 1)
    );
}

// WF14: the collection's writes are conditioned on the record the apply read
// (its version and ltHash), and the store compares it as it writes. A writer
// the caller's fence can't see (it still answers that the caller is current, as
// for a retirement that lands after the fence's last ask, or for another client
// over the same store) moves the collection while the host holds the commit:
// the store refuses the held write, so the newer state stays, nothing of the
// held batch is written, and the error is the retryable conflict, never a
// recovery; a recovery reports the conflict as its outcome.

fn is_conflict(error: &anyhow::Error, base: Option<u64>, stored: Option<u64>) -> bool {
    matches!(
        error.downcast_ref::<AppStateSyncError>(),
        Some(AppStateSyncError::VersionConflict { base: b, stored: s }) if *b == base && *s == stored
    )
}

/// A conflict asks the primary for nothing: the collection is retried as any
/// failed sync is.
fn asks_no_recovery(error: &anyhow::Error) -> bool {
    crate::sync_engine::app_state::RecoveryRequest::for_error(COLLECTION, error.downcast_ref())
        == crate::sync_engine::app_state::RecoveryRequest::NotNeeded
}

/// The patch path: v11 commits, v12 is held while another writer commits v13;
/// the store refuses v12 and the list returns v11 for dispatch.
#[tokio::test]
async fn appstate_patch_over_a_moved_collection_writes_nothing() {
    let fixture = setup().await;
    fixture.seed(held_state(10)).await;
    let committed = archive(FIRST_CHAT, true, 1_000);
    let held = archive(SECOND_CHAT, true, 1_001);
    let newer = archive(THIRD_CHAT, true, 1_002);

    let (entered, release) = fixture.recorder.park_at(1);
    let still_current = fixture.recorder.fence();
    let prepared = fixture
        .prepared(list(
            None,
            vec![patch(11, &[&committed]), patch(12, &[&held])],
        ))
        .await;
    let apply = fixture.processor.process_prepared_patch_list(
        prepared,
        false,
        Provenance::Live,
        &still_current,
    );
    let other_writer = async {
        entered.await.expect("the hook parks");
        fixture.newer_connection_commits(13, &newer).await;
        release.send(()).expect("the hook is parked");
    };
    let (applied, ()) = futures::join!(apply, other_writer);

    let (mutations, state, collection, source) = applied
        .expect_err("a refused write fails the list")
        .downcast::<CommittedMutationsError>()
        .expect("v11 was committed before the other write")
        .into_parts();
    assert_eq!(returned_indexes(&mutations), indexes(&[&committed]));
    assert_eq!((state.version, collection), (11, COLLECTION));
    assert!(is_conflict(&source, Some(11), Some(13)), "{source:#}");
    assert!(asks_no_recovery(&source));
    let stored = fixture.stored().await.expect("the newer cursor stays");
    assert_eq!((stored.version, stored.hash), (13, NEWER_HASH));
    assert_eq!(
        (
            fixture.macs(&[&committed]).await,
            fixture.macs(&[&held]).await,
            fixture.macs(&[&newer]).await
        ),
        (1, 0, 1)
    );
    // The fence held at every ask, after the hook too: the store refused.
    assert_eq!(
        fixture.recorder.take_calls(),
        vec![
            asked(true),
            asked(true),
            batch(Patch, 11, &[&committed], false, Some(10)),
            asked(true),
            asked(true),
            batch(Patch, 12, &[&held], false, Some(11)),
            asked(true),
        ]
    );
}

/// The snapshot path: the snapshot of a collection with no record is held
/// while another writer commits v6; the store refuses the snapshot's rows and
/// its version together.
#[tokio::test]
async fn appstate_snapshot_over_a_moved_collection_writes_nothing() {
    let fixture = setup().await;
    let first = archive(FIRST_CHAT, true, 1_000);
    let second = archive(SECOND_CHAT, true, 1_001);
    let newer = archive(THIRD_CHAT, true, 1_002);

    let (entered, release) = fixture.recorder.park_at(0);
    let still_current = fixture.recorder.fence();
    let prepared = fixture
        .prepared(list(Some(snapshot(5, &[&first, &second])), Vec::new()))
        .await;
    let apply = fixture.processor.process_prepared_patch_list(
        prepared,
        false,
        Provenance::FullSync,
        &still_current,
    );
    let other_writer = async {
        entered.await.expect("the hook parks");
        fixture.newer_connection_commits(6, &newer).await;
        release.send(()).expect("the hook is parked");
    };
    let (applied, ()) = futures::join!(apply, other_writer);

    let error = applied.expect_err("a refused write fails the list");
    assert!(
        error.downcast_ref::<CommittedMutationsError>().is_none(),
        "nothing was committed before the snapshot"
    );
    assert!(is_conflict(&error, None, Some(6)), "{error:#}");
    assert!(asks_no_recovery(&error));
    let stored = fixture.stored().await.expect("the newer cursor stays");
    assert_eq!((stored.version, stored.hash), (6, NEWER_HASH));
    assert_eq!(
        (
            fixture.macs(&[&first, &second]).await,
            fixture.macs(&[&newer]).await
        ),
        (0, 1)
    );
    assert_eq!(
        fixture.recorder.take_calls(),
        vec![
            asked(true),
            asked(true),
            batch(Snapshot, 5, &[&first, &second], true, None),
            asked(true),
        ]
    );
}

/// The recovery path: the recovery of v3 to v9 is held while another writer
/// commits v4; the store refuses the recovery, which doesn't roll the
/// collection back to the version it read.
#[tokio::test]
async fn appstate_recovery_over_a_moved_collection_writes_nothing() {
    let fixture = setup().await;
    fixture.seed(held_state(3)).await;
    let recovered = archive(FIRST_CHAT, true, 1_000);
    let newer = archive(THIRD_CHAT, true, 1_002);

    let (entered, release) = fixture.recorder.park_at(0);
    let still_current = fixture.recorder.fence();
    let apply = fixture.processor.apply_snapshot_recovery(
        recovery(9, &[&recovered]),
        COLLECTION.as_str(),
        &still_current,
    );
    let other_writer = async {
        entered.await.expect("the hook parks");
        fixture.newer_connection_commits(4, &newer).await;
        release.send(()).expect("the hook is parked");
    };
    let (applied, ()) = futures::join!(apply, other_writer);

    let outcome = applied.expect("a refused recovery is an outcome, not an error");
    let RecoveryOutcome::Conflict { stored } = outcome else {
        panic!("the store refuses the recovery: {outcome:?}");
    };
    assert_eq!(
        stored,
        Some(CollectionBase::from(&newer_state(4))),
        "the conflict reports the record the other writer left"
    );
    let stored = fixture.stored().await.expect("the newer cursor stays");
    assert_eq!((stored.version, stored.hash), (4, NEWER_HASH));
    assert_eq!(
        (
            fixture.macs(&[&recovered]).await,
            fixture.macs(&[&newer]).await
        ),
        (0, 1)
    );
}

/// What a conflict says of the two records (WF20 formats it without a string
/// per record): their versions, no record for either, and the ltHash where the
/// versions alone would read the same.
#[test]
fn version_conflict_names_the_two_records() {
    let message = |base, stored| AppStateSyncError::VersionConflict { base, stored }.to_string();
    let prefix = "app-state collection changed under the apply: built on ";
    for (base, stored, said) in [
        (Some(11), Some(13), "v11, stored v13"),
        (None, Some(6), "no record, stored v6"),
        (Some(7), None, "v7, stored no record"),
        (Some(7), Some(7), "v7, stored v7 with another ltHash"),
    ] {
        assert_eq!(message(base, stored), format!("{prefix}{said}"));
    }
}
