//! WF3 through the client. The hook registered on the builder receives every
//! app-state commit before its cursor moves, with its kind and version and
//! under the provenance the mutations' events carry in `from_full_sync`, on
//! each path the client applies mutations by: a rebuild the server pages, a
//! live patch, a full-sync task, the re-sync after a patch send, the patches a
//! conflicting patch send absorbs, and a recovery from the primary phone. Each
//! commit precedes the events that announce it, a refused one announces
//! nothing and is fetched again (after a send, by the client's own retry), and
//! one whose connection is replaced while the host commits writes nothing over
//! the replacement's.
//!
//! Patches are signed as the server's would be (index, content, snapshot and
//! patch MACs), since the client validates every MAC; IQs are answered over the
//! capturing transport, as `test_utils::create_iq_test_client` does.

use super::*;
use crate::client::ClientBuilder;
use crate::transport::mock::{CapturingMockTransport, CapturingMockTransportFactory};
use futures::FutureExt;
use futures::channel::oneshot;
use std::sync::atomic::{AtomicBool, Ordering};
use wacore::appstate::hash::{
    HashState, generate_content_mac, generate_index_mac, generate_patch_mac,
};
use wacore::appstate::keys::expand_app_state_keys;
use wacore::appstate::processor::AppStateMutationMAC;
use wacore::appstate_sync::AppStateBatchKind::{self, Patch};
use wacore::appstate_sync::AppStateSyncError;
use wacore::handshake::NoiseCipher;
use wacore::libsignal::crypto::aes_256_cbc_encrypt_into;
use wacore::store::traits::{AppStateSyncKey, Backend};
use wacore::types::events::{Event, EventHandler, EventInterest, Subscription};
use wacore_binary::node::Node;

const COLLECTION: WAPatchName = WAPatchName::Regular;
const KEY_ID: &[u8] = b"wf3-client-key";
const MASTER_KEY: [u8; 32] = [0x44; 32];
const FIRST_CHAT: &str = "120363000000000042@g.us";
const SECOND_CHAT: &str = "120363000000000043@g.us";
const THIRD_CHAT: &str = "120363000000000044@g.us";

/// What the host saw, in order: its commits, with the stored cursor at that
/// moment, and the `ArchiveUpdate` events.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Seen {
    Commit {
        collection: String,
        kind: AppStateBatchKind,
        version: u64,
        chats: Vec<String>,
        full_sync: bool,
        cursor: Option<u64>,
    },
    Archive {
        chat: String,
        from_full_sync: bool,
    },
}

fn commit(
    collection: WAPatchName,
    kind: AppStateBatchKind,
    version: u64,
    chats: &[&str],
    full_sync: bool,
    cursor: Option<u64>,
) -> Seen {
    Seen::Commit {
        collection: collection.as_str().to_string(),
        kind,
        version,
        chats: chats.iter().map(|chat| chat.to_string()).collect(),
        full_sync,
        cursor,
    }
}

fn archived(chat: &str, from_full_sync: bool) -> Seen {
    Seen::Archive {
        chat: chat.to_string(),
        from_full_sync,
    }
}

#[derive(Debug, thiserror::Error)]
#[error("the host refused the commit")]
struct Refused;

/// The host: its app-state hook and its event handler, writing one journal.
struct Host {
    backend: Arc<dyn Backend>,
    seen: std::sync::Mutex<Vec<Seen>>,
    refuse: AtomicBool,
    /// Holds the next commit until the test lets it go, as a commit waiting on
    /// the host's database would.
    park: std::sync::Mutex<Option<(oneshot::Sender<()>, oneshot::Receiver<()>)>>,
    /// Woken by each `ArchiveUpdate`, for a test waiting on work the client
    /// runs in the background.
    announced: tokio::sync::Notify,
}

impl Host {
    async fn new() -> Arc<Self> {
        let backend = crate::test_utils::create_test_backend().await;
        backend
            .set_sync_key(
                KEY_ID,
                AppStateSyncKey {
                    key_data: MASTER_KEY.to_vec(),
                    ..Default::default()
                },
            )
            .await
            .expect("the test store takes a key");
        Arc::new(Self {
            backend,
            seen: std::sync::Mutex::new(Vec::new()),
            refuse: AtomicBool::new(false),
            park: std::sync::Mutex::new(None),
            announced: tokio::sync::Notify::new(),
        })
    }

    /// Give the collection a bootstrapped baseline at `version`, before the
    /// client is built, and return it for the server to build on.
    async fn baseline(&self, version: u64) -> HashState {
        let base = HashState {
            version,
            bootstrapped: true,
            ..Default::default()
        };
        self.backend
            .set_version(COLLECTION.as_str(), base.clone())
            .await
            .expect("the test store takes a version");
        base
    }

    /// Park the next commit: the receiver resolves once it is parked, and
    /// sending on the sender lets it return.
    fn park_next(&self) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (entered, parked) = oneshot::channel();
        let (release, released) = oneshot::channel();
        *self.park.lock().expect("park lock") = Some((entered, released));
        (parked, release)
    }

    fn push(&self, seen: Seen) {
        self.seen.lock().expect("journal lock").push(seen);
    }

    fn take(&self) -> Vec<Seen> {
        std::mem::take(&mut *self.seen.lock().expect("journal lock"))
    }

    async fn version(&self, collection: WAPatchName) -> Option<u64> {
        self.backend
            .get_version(collection.as_str())
            .await
            .expect("the test store reads")
            .map(|state| state.version)
    }

    /// Whether `chat`'s archive index has a MAC row in the collection.
    async fn has_mac(&self, chat: &str) -> bool {
        self.backend
            .get_mutation_mac(COLLECTION.as_str(), &mac_row(chat).index_mac)
            .await
            .expect("the test store reads")
            .is_some()
    }
}

#[async_trait::async_trait]
impl crate::AppStateDurabilityHook for Host {
    async fn on_mutations(&self, batch: AppStateBatch<'_>) -> Result<()> {
        let cursor = self
            .backend
            .get_version(batch.collection)
            .await?
            .map(|state| state.version);
        self.push(Seen::Commit {
            collection: batch.collection.to_string(),
            kind: batch.kind,
            version: batch.version,
            chats: batch
                .mutations
                .iter()
                .map(|mutation| mutation.index[1].clone())
                .collect(),
            full_sync: batch.full_sync,
            cursor,
        });
        let park = self.park.lock().expect("park lock").take();
        if let Some((entered, release)) = park {
            entered.send(()).expect("the test waits for the park");
            release.await.expect("the test releases the park");
        }
        if self.refuse.load(Ordering::SeqCst) {
            return Err(Refused.into());
        }
        Ok(())
    }
}

impl EventHandler for Host {
    fn handle_event(&self, event: Arc<Event>) {
        if let Event::ArchiveUpdate(update) = &*event {
            self.push(Seen::Archive {
                chat: update.jid.to_string(),
                from_full_sync: update.from_full_sync,
            });
            self.announced.notify_one();
        }
    }

    fn interest(&self) -> EventInterest {
        EventInterest::ALL
    }
}

/// A client built with the host's hook, connected over the capturing
/// transport and wired as `test_utils::create_iq_test_client` wires its own.
async fn client_for(host: &Arc<Host>) -> (Arc<Client>, Arc<CapturingMockTransport>, Subscription) {
    let persistence = Arc::new(
        PersistenceManager::new(host.backend.clone())
            .await
            .expect("persistence manager should initialize"),
    );
    let factory = CapturingMockTransportFactory::new();
    let transport = factory.transport();
    let (client, _sync_tasks) = Client::builder()
        .with_runtime(crate::runtime_impl::TokioRuntime)
        .with_persistence_manager(persistence)
        .with_transport_factory_arc(Arc::new(factory))
        .with_http_client(crate::test_utils::MockHttpClient)
        .with_app_state_durability_hook_arc(host.clone())
        .build()
        .await
        .expect("test client should build")
        .into_parts();
    let noise_socket = NoiseSocket::with_observers(
        client.runtime.clone(),
        transport.clone() as Arc<dyn crate::transport::Transport>,
        NoiseCipher::new(&[0u8; 32]).expect("32-byte key"),
        NoiseCipher::new(&[0u8; 32]).expect("32-byte key"),
        crate::socket::noise_socket::SendObservers::with_stats(client.stats.clone())
            .with_sent_frames(client.sent_frame_tap.clone()),
    );
    *client.noise_socket.lock().unwrap() = Some(Arc::new(noise_socket));
    client.set_connected_for_test(true);
    client.set_driver_running_for_test(true, Ordering::Release);
    client.enter_live_mode_for_tests();
    // The settled fixture's wait: a late mapping warmup would otherwise
    // retire a sync scope taken before it published.
    while !client.lid_pn_cache.startup_finished_for_tests() {
        tokio::task::yield_now().await;
    }
    drop(client.lid_pn_cache.lock_mutation().await);
    let subscription = client.subscribe_handler(host.clone());
    (client, transport, subscription)
}

fn key_id() -> buffa::MessageField<wa::KeyId> {
    let mut key = wa::KeyId::default();
    key.id = Some(KEY_ID.to_vec());
    buffa::MessageField::some(key)
}

fn version(version: u64) -> buffa::MessageField<wa::SyncdVersion> {
    let mut proto = wa::SyncdVersion::default();
    proto.version = Some(version);
    buffa::MessageField::some(proto)
}

fn archive_value(timestamp: i64) -> wa::SyncActionValue {
    let mut value = wa::SyncActionValue::default();
    value.timestamp = Some(timestamp);
    value.archive_chat_action = buffa::MessageField::some({
        let mut action = wa::sync_action_value::ArchiveChatAction::default();
        action.archived = Some(true);
        action
    });
    value
}

fn archive_index(chat: &str) -> Vec<u8> {
    serde_json::to_vec(&["archive", chat]).expect("an index encodes")
}

/// A stored MAC row for `chat`'s archive index.
fn mac_row(chat: &str) -> AppStateMutationMAC {
    AppStateMutationMAC {
        index_mac: generate_index_mac(
            &archive_index(chat),
            &expand_app_state_keys(&MASTER_KEY).index,
        ),
        value_mac: vec![0x22; 32],
    }
}

/// Logged in on the live generation, so a sync that checks reachability runs
/// rather than deferring.
fn reachable(client: &Client) {
    client.set_logged_in_for_test(true, Ordering::Relaxed);
    client.authenticated_generation.store(
        client.connection_generation.load(Ordering::SeqCst),
        Ordering::SeqCst,
    );
}

/// The collection as the server holds it, signing each patch it serves.
#[derive(Default)]
struct Server {
    state: HashState,
}

impl Server {
    /// The next patch: one archive of `chat`, an index the collection lacks.
    fn patch(&mut self, chat: &str, timestamp: i64) -> wa::SyncdPatch {
        let keys = expand_app_state_keys(&MASTER_KEY);
        let index = archive_index(chat);
        let plaintext =
            waproto::codec::sync_action_data_to_vec(&index, &archive_value(timestamp), 0);
        let mut blob = vec![0u8; 16];
        let mut ciphertext = Vec::new();
        aes_256_cbc_encrypt_into(&plaintext, &keys.value_encryption, &blob, &mut ciphertext)
            .expect("AES-CBC takes a 32-byte key and a 16-byte IV");
        blob.extend_from_slice(&ciphertext);
        let value_mac = generate_content_mac(
            wa::syncd_mutation::SyncdOperation::SET,
            &blob,
            KEY_ID,
            &keys.value_mac,
        );
        blob.extend_from_slice(&value_mac);

        let mut mutation = wa::SyncdMutation::default();
        mutation.operation = Some(wa::syncd_mutation::SyncdOperation::SET.into());
        mutation.record = buffa::MessageField::some({
            let mut record = wa::SyncdRecord::default();
            record.index = buffa::MessageField::some({
                let mut proto = wa::SyncdIndex::default();
                proto.blob = Some(generate_index_mac(&index, &keys.index));
                proto
            });
            record.value = buffa::MessageField::some({
                let mut proto = wa::SyncdValue::default();
                proto.blob = Some(blob);
                proto
            });
            record.key_id = key_id();
            record
        });

        let mutations = vec![mutation];
        let (_, folded) = self.state.update_hash(&mutations, |_, _| Ok(None));
        folded.expect("a new index folds into the ltHash");
        self.state.version += 1;
        let mut patch = wa::SyncdPatch::default();
        patch.version = version(self.state.version);
        patch.mutations = mutations;
        patch.key_id = key_id();
        patch.snapshot_mac = Some(
            self.state
                .generate_snapshot_mac(COLLECTION.as_str(), &keys.snapshot_mac),
        );
        patch.patch_mac = Some(generate_patch_mac(
            &patch,
            COLLECTION.as_str(),
            &keys.patch_mac,
            self.state.version,
        ));
        patch
    }
}

fn patches(patches: &[wa::SyncdPatch]) -> Node {
    NodeBuilder::new("patches")
        .children(patches.iter().map(|patch| {
            NodeBuilder::new("patch")
                .bytes(waproto::codec::syncd_patch_to_vec(patch))
                .build()
        }))
        .build()
}

fn iq_result(request_id: &str, collection: Node) -> Node {
    NodeBuilder::new("iq")
        .attr("type", "result")
        .attr("id", request_id)
        .attr("from", "s.whatsapp.net")
        .children([NodeBuilder::new("sync").children([collection]).build()])
        .build()
}

type Answer = Box<dyn Fn(&str) -> Node>;

/// One page of the collection: `served`, and whether more follow.
fn page(has_more: bool, served: Vec<wa::SyncdPatch>) -> Answer {
    Box::new(move |request_id| {
        iq_result(
            request_id,
            NodeBuilder::new("collection")
                .attr("name", COLLECTION.as_str())
                .attr("has_more_patches", if has_more { "true" } else { "false" })
                .children([patches(&served)])
                .build(),
        )
    })
}

/// A 409 for a patch built on a stale base, carrying the patches it missed.
fn conflict(served: Vec<wa::SyncdPatch>) -> Answer {
    Box::new(move |request_id| {
        iq_result(
            request_id,
            NodeBuilder::new("collection")
                .attr("name", COLLECTION.as_str())
                .attr("type", "error")
                .attr("has_more_patches", "false")
                .children([
                    NodeBuilder::new("error")
                        .attr("code", "409")
                        .attr("text", "conflict")
                        .build(),
                    patches(&served),
                ])
                .build(),
        )
    })
}

/// Runs `call` while answering the client's IQs, from frame `first_frame` on,
/// with `answers` in order.
async fn serve<T>(
    client: &Arc<Client>,
    transport: &Arc<CapturingMockTransport>,
    first_frame: usize,
    answers: Vec<Answer>,
    call: impl Future<Output = T>,
) -> T {
    let server = async {
        for (offset, answer) in answers.iter().enumerate() {
            let request = crate::test_utils::decode_sent_iq(transport, first_frame + offset).await;
            let request = request.get().to_owned();
            let id = request
                .attrs()
                .optional_string("id")
                .expect("every IQ carries an id")
                .into_owned();
            crate::test_utils::answer_iq(client, &id, &answer(&id)).await;
        }
        std::future::pending::<()>().await
    };
    futures::pin_mut!(server);
    futures::pin_mut!(call);
    futures::select! {
        result = call.fuse() => result,
        () = server.fuse() => unreachable!("the server never finishes"),
    }
}

async fn sync_collection(
    client: &Arc<Client>,
    transport: &Arc<CapturingMockTransport>,
    first_frame: usize,
    answers: Vec<Answer>,
) -> Result<BatchedSyncOutcome> {
    serve(
        client,
        transport,
        first_frame,
        answers,
        client.sync_collections_batched(vec![COLLECTION], client.sync_scope(None)),
    )
    .await
}

/// A collection without a baseline is rebuilt, and every page of the rebuild
/// commits as a full sync, the pages after the first included; once it is
/// bootstrapped, a patch commits as live. Each commit sees the cursor before
/// it, and precedes its event.
#[tokio::test]
async fn app_state_hook_commits_each_page_of_a_rebuild_as_a_full_sync() {
    let host = Host::new().await;
    let (client, transport, _subscription) = client_for(&host).await;
    let mut server = Server::default();
    let first = server.patch(FIRST_CHAT, 1_000);
    let second = server.patch(SECOND_CHAT, 1_001);
    let third = server.patch(THIRD_CHAT, 1_002);

    let outcome = sync_collection(
        &client,
        &transport,
        0,
        vec![page(true, vec![first]), page(false, vec![second])],
    )
    .await
    .expect("the rebuild syncs");
    assert_eq!(outcome.synced, vec![COLLECTION]);
    assert_eq!(
        host.take(),
        vec![
            commit(COLLECTION, Patch, 1, &[FIRST_CHAT], true, None),
            archived(FIRST_CHAT, true),
            commit(COLLECTION, Patch, 2, &[SECOND_CHAT], true, Some(1)),
            archived(SECOND_CHAT, true),
        ]
    );

    let outcome = sync_collection(&client, &transport, 2, vec![page(false, vec![third])])
        .await
        .expect("the live patch syncs");
    assert_eq!(outcome.synced, vec![COLLECTION]);
    assert_eq!(
        host.take(),
        vec![
            commit(COLLECTION, Patch, 3, &[THIRD_CHAT], false, Some(2)),
            archived(THIRD_CHAT, false),
        ]
    );
    assert_eq!(host.version(COLLECTION).await, Some(3));
}

/// A refused commit fails the sync with the host's error: the cursor stays,
/// nothing is announced, and the next sync fetches the same patch again.
#[tokio::test]
async fn app_state_hook_refusal_keeps_the_cursor_until_the_next_sync() {
    let host = Host::new().await;
    let (client, transport, _subscription) = client_for(&host).await;
    let mut server = Server::default();
    let first = server.patch(FIRST_CHAT, 1_000);

    host.refuse.store(true, Ordering::SeqCst);
    let error = sync_collection(
        &client,
        &transport,
        0,
        vec![page(false, vec![first.clone()])],
    )
    .await
    .expect_err("a refused commit fails the sync");
    assert!(error.downcast_ref::<Refused>().is_some(), "{error:#}");
    assert_eq!(
        host.take(),
        vec![commit(COLLECTION, Patch, 1, &[FIRST_CHAT], true, None)]
    );
    assert_eq!(host.version(COLLECTION).await, None);

    host.refuse.store(false, Ordering::SeqCst);
    let outcome = sync_collection(&client, &transport, 1, vec![page(false, vec![first])])
        .await
        .expect("the retried sync applies the patch");
    assert_eq!(outcome.synced, vec![COLLECTION]);
    assert_eq!(
        host.take(),
        vec![
            commit(COLLECTION, Patch, 1, &[FIRST_CHAT], true, None),
            archived(FIRST_CHAT, true),
        ]
    );
    assert_eq!(host.version(COLLECTION).await, Some(1));
}

/// The patches a conflicting send absorbs commit as live, as their events say.
#[tokio::test]
async fn app_state_hook_commits_an_absorbed_conflict_as_live() {
    let host = Host::new().await;
    let base = host.baseline(7).await;
    let (client, transport, _subscription) = client_for(&host).await;
    // Reachable, so the re-sync after the send runs rather than deferring.
    reachable(&client);
    let mut server = Server { state: base };
    let missed = server.patch(FIRST_CHAT, 1_000);

    serve(
        &client,
        &transport,
        0,
        // The patch built on v7 conflicts with v8; the one rebuilt on v8 is
        // accepted, and the re-sync after it finds nothing new.
        vec![
            conflict(vec![missed]),
            page(false, Vec::new()),
            page(false, Vec::new()),
        ],
        client.send_app_state_patch(COLLECTION.as_str(), vec![wa::SyncdMutation::default()]),
    )
    .await
    .expect("the send resolves its conflict");
    assert_eq!(
        host.take(),
        vec![
            commit(COLLECTION, Patch, 8, &[FIRST_CHAT], false, Some(7)),
            archived(FIRST_CHAT, false),
        ]
    );
    assert_eq!(host.version(COLLECTION).await, Some(8));
}

/// A full-sync task rebuilds a collection that already has a baseline, and
/// every page of it commits as a full sync, the pages after the first
/// included.
#[tokio::test]
async fn app_state_hook_commits_each_page_of_a_full_sync_task_as_a_full_sync() {
    let host = Host::new().await;
    let base = host.baseline(7).await;
    let (client, transport, _subscription) = client_for(&host).await;
    reachable(&client);
    let mut server = Server { state: base };
    let first = server.patch(FIRST_CHAT, 1_000);
    let second = server.patch(SECOND_CHAT, 1_001);

    serve(
        &client,
        &transport,
        0,
        vec![page(true, vec![first]), page(false, vec![second])],
        client.process_sync_task(MajorSyncTask::AppStateSync {
            name: COLLECTION,
            full_sync: true,
        }),
    )
    .await;
    assert_eq!(
        host.take(),
        vec![
            commit(COLLECTION, Patch, 8, &[FIRST_CHAT], true, Some(7)),
            archived(FIRST_CHAT, true),
            commit(COLLECTION, Patch, 9, &[SECOND_CHAT], true, Some(8)),
            archived(SECOND_CHAT, true),
        ]
    );
    assert_eq!(host.version(COLLECTION).await, Some(9));
}

/// The re-sync a send runs once the server accepts its patch commits what it
/// fetches as live, as its events say.
#[tokio::test]
async fn app_state_hook_commits_a_resync_after_a_send_as_live() {
    let host = Host::new().await;
    let base = host.baseline(7).await;
    let (client, transport, _subscription) = client_for(&host).await;
    reachable(&client);
    // The server's v8, on the base the send built on.
    let echoed = Server { state: base }.patch(FIRST_CHAT, 1_000);

    serve(
        &client,
        &transport,
        0,
        // The send is accepted, and the re-sync after it fetches v8.
        vec![page(false, Vec::new()), page(false, vec![echoed])],
        client.send_app_state_patch(COLLECTION.as_str(), vec![wa::SyncdMutation::default()]),
    )
    .await
    .expect("the send is accepted");
    assert_eq!(
        host.take(),
        vec![
            commit(COLLECTION, Patch, 8, &[FIRST_CHAT], false, Some(7)),
            archived(FIRST_CHAT, false),
        ]
    );
    assert_eq!(host.version(COLLECTION).await, Some(8));
}

/// A commit refused in the re-sync after a send does not fail the send, whose
/// patch the server accepted, and is not left for some later trigger: the
/// client retries the collection's sync with backoff, and the retry commits
/// the same patch once the host takes it.
#[tokio::test(start_paused = true)]
async fn app_state_hook_refusal_after_a_send_is_retried_with_backoff() {
    let host = Host::new().await;
    let base = host.baseline(7).await;
    let (client, transport, _subscription) = client_for(&host).await;
    reachable(&client);
    let echoed = Server { state: base }.patch(FIRST_CHAT, 1_000);

    host.refuse.store(true, Ordering::SeqCst);
    serve(
        &client,
        &transport,
        0,
        vec![page(false, Vec::new()), page(false, vec![echoed.clone()])],
        client.send_app_state_patch(COLLECTION.as_str(), vec![wa::SyncdMutation::default()]),
    )
    .await
    .expect("the send is accepted; its re-sync is not the send");
    // Before anything else runs, so the retry finds a host that accepts.
    host.refuse.store(false, Ordering::SeqCst);
    assert_eq!(
        host.take(),
        vec![commit(COLLECTION, Patch, 8, &[FIRST_CHAT], false, Some(7))]
    );
    assert_eq!(host.version(COLLECTION).await, Some(7));

    // The clock is paused, so the retry's first backoff elapses once nothing
    // else can run. Resumed after it, so the IQ helpers keep their hang guards.
    tokio::time::sleep(APP_STATE_RETRY_BACKOFF_MIN).await;
    tokio::time::resume();
    serve(
        &client,
        &transport,
        2,
        vec![page(false, vec![echoed])],
        host.announced.notified(),
    )
    .await;
    assert_eq!(
        host.take(),
        vec![
            commit(COLLECTION, Patch, 8, &[FIRST_CHAT], false, Some(7)),
            archived(FIRST_CHAT, false),
        ]
    );
    assert_eq!(host.version(COLLECTION).await, Some(8));
}

/// A collection the primary phone sends back commits whole, as a full sync,
/// before the client rewrites its MAC rows and writes the recovered cursor.
#[tokio::test]
async fn app_state_hook_commits_a_recovery_as_a_full_sync() {
    let host = Host::new().await;
    let collection = WAPatchName::RegularLow;
    host.backend
        .set_version(
            collection.as_str(),
            HashState {
                version: 3,
                bootstrapped: true,
                ..Default::default()
            },
        )
        .await
        .expect("the test store takes a version");
    let (client, _transport, _subscription) = client_for(&host).await;

    let mut recovery = wa::SyncdSnapshotRecovery::default();
    recovery.version = version(9);
    recovery.collection_name = Some(collection.as_str().to_string());
    recovery.collection_lthash = Some(vec![0x5A; 128]);
    recovery.mutation_records = [FIRST_CHAT, SECOND_CHAT]
        .iter()
        .zip(1_000..)
        .map(|(chat, timestamp)| {
            let mut record = wa::SyncdPlainTextRecord::default();
            record.value = buffa::MessageField::some({
                let mut data = wa::SyncActionData::default();
                data.index = Some(archive_index(chat));
                data.value = buffa::MessageField::some(archive_value(timestamp));
                data
            });
            record.key_id = Some(KEY_ID.to_vec());
            record.mac = Some(vec![0x11; 32]);
            record
        })
        .collect();

    client
        .apply_recovered_collection(collection.as_str(), None, recovery)
        .await;
    assert_eq!(
        host.take(),
        vec![
            commit(
                collection,
                AppStateBatchKind::Recovery,
                9,
                &[FIRST_CHAT, SECOND_CHAT],
                true,
                Some(3)
            ),
            archived(FIRST_CHAT, true),
            archived(SECOND_CHAT, true),
        ]
    );
    assert_eq!(host.version(collection).await, Some(9));
}

/// A reconnect lands while the host commits: the disconnect moves the
/// generation on and clears the reservations, and the next connection's sync
/// commits a newer version of the collection. Released, the old sync writes
/// nothing over it, announces nothing, and fails with the retirement, leaving
/// its patch to the collection's next sync.
#[tokio::test]
async fn app_state_hook_parked_across_a_reconnect_leaves_the_newer_commit() {
    let host = Host::new().await;
    let (client, transport, _subscription) = client_for(&host).await;
    let mut server = Server::default();
    let first = server.patch(FIRST_CHAT, 1_000);

    let (entered, release) = host.park_next();
    let reconnect = async {
        entered.await.expect("the hook parks");
        client.advance_generation_for_test(1, Ordering::SeqCst);
        client.app_state_syncing.clear();
        host.backend
            .commit_patch(
                COLLECTION.as_str(),
                HashState {
                    version: 2,
                    bootstrapped: true,
                    ..Default::default()
                },
                &[],
                &[mac_row(SECOND_CHAT)],
            )
            .await
            .expect("the test store takes a patch");
        release.send(()).expect("the hook is parked");
    };
    let sync_across_the_reconnect = async {
        let synced = client.sync_collections_batched(vec![COLLECTION], client.sync_scope(None));
        futures::join!(synced, reconnect).0
    };
    let error = serve(
        &client,
        &transport,
        0,
        vec![page(false, vec![first])],
        sync_across_the_reconnect,
    )
    .await
    .expect_err("the retired sync fails");

    assert!(
        matches!(
            error.downcast_ref::<AppStateSyncError>(),
            Some(AppStateSyncError::Retired)
        ),
        "{error:#}"
    );
    assert_eq!(
        host.take(),
        vec![commit(COLLECTION, Patch, 1, &[FIRST_CHAT], true, None)]
    );
    assert_eq!(host.version(COLLECTION).await, Some(2));
    assert_eq!(
        (
            host.has_mac(FIRST_CHAT).await,
            host.has_mac(SECOND_CHAT).await
        ),
        (false, true)
    );
}

/// A single-collection sync whose connection is replaced while its IQ is in
/// flight discards the answer, even once the replacement has logged in and the
/// client reads as reachable again: the reservation the sync runs under went
/// with the old connection.
#[tokio::test]
async fn app_state_sync_task_discards_an_answer_its_connection_outlived() {
    let host = Host::new().await;
    let (client, transport, _subscription) = client_for(&host).await;
    reachable(&client);
    let generation = client.sync_scope(None).generation();
    let mut server = Server::default();
    let answer = page(false, vec![server.patch(FIRST_CHAT, 1_000)]);
    let replaced: Answer = {
        let client = Arc::clone(&client);
        Box::new(move |request_id: &str| {
            client.advance_generation_for_test(1, Ordering::SeqCst);
            reachable(&client);
            answer(request_id)
        })
    };

    let outcome = serve(
        &client,
        &transport,
        0,
        vec![replaced],
        client.process_app_state_sync_task(COLLECTION, false, generation),
    )
    .await
    .expect("deferring is not an error");
    assert_eq!(outcome, SyncOutcome::Deferred);
    assert!(client.can_reach_server(), "the replacement is live");
    assert_eq!(host.take(), Vec::new());
    assert_eq!(host.version(COLLECTION).await, None);
}

struct Accept;

#[async_trait::async_trait]
impl crate::AppStateDurabilityHook for Accept {
    async fn on_mutations(&self, _batch: AppStateBatch<'_>) -> Result<()> {
        Ok(())
    }
}

async fn build_with(
    register: impl FnOnce(ClientBuilder) -> ClientBuilder,
) -> Option<Arc<dyn crate::AppStateDurabilityHook>> {
    let persistence = Arc::new(
        PersistenceManager::new(crate::test_utils::create_test_backend().await)
            .await
            .expect("persistence manager should initialize"),
    );
    let builder = Client::builder()
        .with_runtime(crate::runtime_impl::TokioRuntime)
        .with_persistence_manager(persistence)
        .with_transport_factory(crate::transport::mock::MockTransportFactory::new())
        .with_http_client(crate::test_utils::MockHttpClient);
    let (client, _sync_tasks) = register(builder)
        .build()
        .await
        .expect("test client should build")
        .into_parts();
    client.app_state_durability_hook.clone()
}

/// The builder installs the hook the processor forwards to, by value or
/// shared; the last registration wins, and a shared one keeps its identity.
#[tokio::test]
async fn app_state_hook_last_registration_wins() {
    let shared: Arc<dyn crate::AppStateDurabilityHook> = Arc::new(Accept);

    let installed = build_with(|builder| {
        builder
            .with_app_state_durability_hook(Accept)
            .with_app_state_durability_hook_arc(shared.clone())
    })
    .await
    .expect("a hook is registered");
    assert!(Arc::ptr_eq(&installed, &shared));

    let installed = build_with(|builder| {
        builder
            .with_app_state_durability_hook_arc(shared.clone())
            .with_app_state_durability_hook(Accept)
    })
    .await
    .expect("a hook is registered");
    assert!(!Arc::ptr_eq(&installed, &shared));

    assert!(build_with(|builder| builder).await.is_none());
}
