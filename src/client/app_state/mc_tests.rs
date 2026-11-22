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
//!
//! WF10 at the end: the critical bootstrap pairing owes is recorded in the
//! device record with the new identity, so a client built over the device
//! after the one that paired it runs that bootstrap, once, and the pairing
//! client itself behaves as before. Over a store that already holds the
//! app-state key, that client starts it without waiting for a key share.
//!
//! WF14 after it: a patch or a snapshot whose commit the host holds while
//! another writer moves the collection writes nothing over that writer's
//! version, whether a reconnect or a writer the connection can't see moved it,
//! and the collection's next sync goes on from there. The snapshot comes as the
//! server sends one, an encrypted blob behind a reference, from a media host.
//! The re-sync after a send whose commit is refused that way syncs again at
//! once, and a recovery from the primary refused that way is converged by a
//! sync.

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
use wacore::types::events::{Event, EventHandler, EventInterest, EventKind, Subscription};
use wacore_binary::node::{Node, NodeContent};

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
        self.mac(chat).await.is_some()
    }

    /// The value MAC of `chat`'s archive index in the collection, if any.
    async fn mac(&self, chat: &str) -> Option<Vec<u8>> {
        self.backend
            .get_mutation_mac(COLLECTION.as_str(), &mac_row(chat).index_mac)
            .await
            .expect("the test store reads")
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
    client_with(host, Arc::new(crate::test_utils::MockHttpClient)).await
}

/// [`client_for`], with `http` serving the client's downloads.
async fn client_with(
    host: &Arc<Host>,
    http: Arc<dyn crate::http::HttpClient>,
) -> (Arc<Client>, Arc<CapturingMockTransport>, Subscription) {
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
        .with_http_client_arc(http)
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

/// `chat`'s archive as the primary encrypts it: its index MAC, and the value
/// with its content MAC.
fn archive_record(chat: &str, timestamp: i64) -> wa::SyncdRecord {
    let keys = expand_app_state_keys(&MASTER_KEY);
    let index = archive_index(chat);
    let plaintext = waproto::codec::sync_action_data_to_vec(&index, &archive_value(timestamp), 0);
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
}

impl Server {
    /// The next patch: one archive of `chat`, an index the collection lacks.
    fn patch(&mut self, chat: &str, timestamp: i64) -> wa::SyncdPatch {
        let keys = expand_app_state_keys(&MASTER_KEY);
        let mut mutation = wa::SyncdMutation::default();
        mutation.operation = Some(wa::syncd_mutation::SyncdOperation::SET.into());
        mutation.record = buffa::MessageField::some(archive_record(chat, timestamp));

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

    /// The collection rebuilt as a snapshot at `at` holding `chats`' archives,
    /// signed as the server signs it; the server's collection is that from now
    /// on.
    fn snapshot(&mut self, at: u64, chats: &[&str]) -> wa::SyncdSnapshot {
        let keys = expand_app_state_keys(&MASTER_KEY);
        let records: Vec<_> = chats
            .iter()
            .zip(1_000..)
            .map(|(chat, timestamp)| archive_record(chat, timestamp))
            .collect();
        self.state = HashState {
            version: at,
            ..Default::default()
        };
        let folded = self.state.update_hash_from_records(&records);
        assert_eq!(folded.folded, records.len(), "every record folds");
        let mut snapshot = wa::SyncdSnapshot::default();
        snapshot.version = version(at);
        snapshot.records = records;
        snapshot.key_id = key_id();
        snapshot.mac = Some(
            self.state
                .generate_snapshot_mac(COLLECTION.as_str(), &keys.snapshot_mac),
        );
        snapshot
    }
}

/// `snapshot` as the server hands it out, an encrypted media blob: the
/// reference a `<snapshot>` node carries, and the blob behind it.
#[allow(
    clippy::disallowed_methods,
    reason = "test fixtures encode their protos directly"
)]
fn snapshot_blob(snapshot: &wa::SyncdSnapshot) -> (Vec<u8>, Vec<u8>) {
    let plaintext = buffa::Message::encode_to_vec(snapshot);
    let encrypted = wacore::upload::encrypt_media(&plaintext, crate::download::MediaType::AppState)
        .expect("a snapshot encrypts");
    let mut reference = wa::ExternalBlobReference::default();
    reference.direct_path = Some("/wf14-snapshot".into());
    reference.media_key = Some(encrypted.media_key.to_vec());
    reference.file_sha256 = Some(encrypted.file_sha256.to_vec());
    reference.file_enc_sha256 = Some(encrypted.file_enc_sha256.to_vec());
    reference.file_size_bytes = Some(plaintext.len() as u64);
    (
        buffa::Message::encode_to_vec(&reference),
        encrypted.data_to_upload,
    )
}

/// Serves one blob for every download, as a media host holding a snapshot.
struct BlobHost(Vec<u8>);

#[async_trait::async_trait]
impl crate::http::HttpClient for BlobHost {
    async fn execute(
        &self,
        _request: crate::http::HttpRequest,
    ) -> Result<crate::http::HttpResponse> {
        Ok(crate::http::HttpResponse::new(200, self.0.clone()))
    }
}

/// A media route, so a download goes to the client's HTTP client without
/// asking the server for one first.
async fn media_route(client: &Client) {
    *client.media_conn.write().await = Some(crate::mediaconn::MediaConn {
        auth: "wf14".into(),
        ttl: 3600,
        auth_ttl: None,
        hosts: vec![crate::mediaconn::MediaConnHost::new(
            "cdn.example.com".into(),
        )],
        fetched_at: wacore::time::Instant::now(),
    });
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

/// The collection rebuilt from a snapshot, its blob behind `reference`.
fn snapshot_page(reference: Vec<u8>) -> Answer {
    Box::new(move |request_id| {
        iq_result(
            request_id,
            NodeBuilder::new("collection")
                .attr("name", COLLECTION.as_str())
                .attr("has_more_patches", "false")
                .children([NodeBuilder::new("snapshot")
                    .bytes(reference.clone())
                    .build()])
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

/// `collection` as the primary phone sends it back at `at`, holding `chats`'
/// archives.
fn recovery(collection: WAPatchName, at: u64, chats: &[&str]) -> wa::SyncdSnapshotRecovery {
    let mut recovery = wa::SyncdSnapshotRecovery::default();
    recovery.version = version(at);
    recovery.collection_name = Some(collection.as_str().to_string());
    recovery.collection_lthash = Some(vec![0x5A; 128]);
    recovery.mutation_records = chats
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
    recovery
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

    client
        .apply_recovered_collection(
            collection.as_str(),
            None,
            recovery(collection, 9, &[FIRST_CHAT, SECOND_CHAT]),
        )
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

// WF10: the bootstrap pairing owes, recorded with the identity.

/// The business name the pairing carries. A business account's push name
/// comes from pairing, so the push-name trigger stays off and the bootstrap
/// gate alone decides whether a connection runs the critical bootstrap.
const BUSINESS_NAME: &str = "WF10 Business";

/// The pairing fixture's signed `pair-success`, for a business account.
fn business_pair_success(client: &Client) -> Node {
    let mut iq = pair::tests::signed_pair_success(client);
    let Some(NodeContent::Nodes(children)) = &mut iq.content else {
        panic!("the fixture's iq holds its pair-success");
    };
    let Some(NodeContent::Nodes(success)) = &mut children[0].content else {
        panic!("the fixture's pair-success holds its identity");
    };
    success.push(NodeBuilder::new("biz").attr("name", BUSINESS_NAME).build());
    iq
}

/// What a client sends, frame by frame in wire order, as its sent-frame tap
/// hands each one over once the transport has taken it. `serve_until` waits
/// for the next frame rather than polling for it, so the test's task is idle
/// exactly when the client's are, and a paused clock moves only on the
/// client's own timers.
struct Frames {
    sent: async_channel::Receiver<bytes::Bytes>,
    _forwarding: SentFrameLease,
    _subscription: Subscription,
}

/// Feeds a [`Frames`].
struct FrameFeed(async_channel::Sender<bytes::Bytes>);

impl EventHandler for FrameFeed {
    fn handle_event(&self, event: Arc<Event>) {
        if let Event::SentFrame(frame) = &*event {
            // Unbounded: it fails only once the test has stopped reading.
            let _ = self.0.try_send(frame.plaintext.clone());
        }
    }

    fn interest(&self) -> EventInterest {
        EventInterest::of(&[EventKind::SentFrame])
    }
}

/// A client over `backend`, connected over the capturing transport, and the
/// frames it sends, once its mapping warmup has settled: a late one would
/// retire a sync scope taken before it published.
async fn client_over(backend: &Arc<dyn Backend>) -> (Arc<Client>, Frames) {
    let (client, _transport) =
        crate::test_utils::create_iq_test_client_with_backend(backend.clone()).await;
    while !client.lid_pn_cache.startup_finished_for_tests() {
        tokio::task::yield_now().await;
    }
    drop(client.lid_pn_cache.lock_mutation().await);
    let (feed, sent) = async_channel::unbounded();
    let frames = Frames {
        sent,
        _forwarding: client.acquire_sent_frame_forwarding(),
        _subscription: client.subscribe_handler(Arc::new(FrameFeed(feed))),
    };
    (client, frames)
}

/// Pairs `client` as a business account.
async fn pair(client: &Arc<Client>) {
    let iq = business_pair_success(client);
    assert!(pair::handle_iq(client, &iq.as_node_ref()).await);
    let paired = client.persistence_manager.get_device_snapshot();
    assert!(paired.pn.is_some(), "the pairing committed");
    assert_eq!(paired.push_name, BUSINESS_NAME);
}

/// Pairs a client over `backend` and shuts it down before the reconnect that
/// would log it in, as a host that pairs with one client and serves the
/// account with another does. The shutdown saves the device.
async fn pair_and_close(backend: &Arc<dyn Backend>) {
    let (client, _frames) = client_over(backend).await;
    pair(&client).await;
    client
        .shutdown()
        .await
        .device
        .expect("the shutdown saves the device");
    let stored = stored_device(backend).await;
    assert!(stored.pn.is_some(), "the stored record holds the identity");
    assert!(
        stored.initial_full_sync_owed,
        "and, written with it, the bootstrap it owes"
    );
}

/// The device record as the store holds it.
async fn stored_device(backend: &Arc<dyn Backend>) -> wacore::store::Device {
    backend
        .load()
        .await
        .expect("the test store reads")
        .expect("a device row")
}

/// Logs `client` in on a new connection: the one the 515 after pairing, or a
/// later reconnect, brings up. Its offline backlog is drained and the
/// primary's app-state key share has reached this process, so the post-login
/// sequence waits on nothing but the IQs `serve_until` answers.
async fn log_in(client: &Arc<Client>) {
    client
        .initial_app_state_keys_received
        .store(true, Ordering::SeqCst);
    log_in_without_key_share(client).await;
}

/// [`log_in`] in a process the primary's key share has not reached, as in any
/// process after the one that received it: whether the bootstrap waits for
/// the share is the client's own decision.
async fn log_in_without_key_share(client: &Arc<Client>) {
    client.clear_expected_session_disconnect();
    client.advance_generation_for_test(1, Ordering::SeqCst);
    client.invalidate_session_authentication();
    client.offline_sync_completed.store(true, Ordering::SeqCst);
    let success = NodeBuilder::new("success").build();
    client.handle_success(&success.as_node_ref()).await;
}

/// What a connection sent while `serve_until` answered it.
#[derive(Default)]
struct Wire {
    /// Each app-state sync answered, as the collections it asked for, sorted.
    app_state: Vec<Vec<String>>,
    /// `<presence>` stanzas. A connection that owes no bootstrap announces the
    /// session with one first; the bootstrap sends none before its syncs.
    presences: usize,
}

impl Wire {
    /// Whether the connection has shown which path it took.
    fn decided(&self) -> bool {
        !self.app_state.is_empty() || self.presences > 0
    }
}

fn sorted(names: &[WAPatchName]) -> Vec<String> {
    let mut names: Vec<String> = names.iter().map(|name| name.as_str().to_string()).collect();
    names.sort();
    names
}

/// The bootstrap's two syncs: the critical collections, then the rest.
fn bootstrap_syncs() -> Vec<Vec<String>> {
    vec![
        sorted(&[WAPatchName::CriticalBlock, WAPatchName::CriticalUnblockLow]),
        sorted(&[
            WAPatchName::RegularLow,
            WAPatchName::RegularHigh,
            WAPatchName::Regular,
        ]),
    ]
}

/// Answers the client's requests in the order they reach the wire until `done`
/// holds: an app-state sync with every collection it names, clean (synced,
/// nothing new), any other request with an empty result. It waits on the
/// client's frames, never on a clock.
async fn serve_until(
    client: &Arc<Client>,
    frames: &Frames,
    wire: &mut Wire,
    done: impl Fn(&Wire) -> bool,
) {
    while !done(wire) {
        let plaintext = frames
            .sent
            .recv()
            .await
            .expect("the feed lives as long as its subscription");
        let node = wacore_binary::marshal::unmarshal_packed_ref(&plaintext)
            .expect("a sent frame decodes as the stanza it carried");
        if node.tag.as_ref() == "presence" {
            wire.presences += 1;
            continue;
        }
        let request = node.tag.as_ref() == "iq"
            && matches!(
                node.attrs().optional_string("type").as_deref(),
                Some("get" | "set")
            );
        if !request {
            continue;
        }
        let id = node
            .attrs()
            .optional_string("id")
            .expect("every IQ carries an id")
            .into_owned();
        // An IQ's waiter is registered before the IQ is sent, so a request
        // without one is one nobody waits for any more.
        if !client.response_waiters_guard().contains_key(&id) {
            continue;
        }
        if node.attrs().optional_string("xmlns").as_deref() == Some("w:sync:app:state") {
            let mut names: Vec<String> = node
                .get_optional_child("sync")
                .expect("an app-state sync names its collections")
                .get_children_by_tag("collection")
                .map(|collection| {
                    collection
                        .attrs()
                        .optional_string("name")
                        .expect("a collection has a name")
                        .into_owned()
                })
                .collect();
            let clean: Vec<(&str, Option<&str>)> =
                names.iter().map(|name| (name.as_str(), None)).collect();
            crate::test_utils::answer_iq(client, &id, &batch_result(&id, &clean)).await;
            names.sort();
            wire.app_state.push(names);
        } else {
            let answer = NodeBuilder::new("iq")
                .attr("type", "result")
                .attr("id", id.as_str())
                .attr("from", "s.whatsapp.net")
                .build();
            crate::test_utils::answer_iq(client, &id, &answer).await;
        }
    }
}

/// Waits until the stored device record says `owed`: the save of the
/// bootstrap's last settle.
async fn stored_owed_reaches(backend: &Arc<dyn Backend>, owed: bool) {
    while stored_device(backend).await.initial_full_sync_owed != owed {
        tokio::task::yield_now().await;
    }
}

/// A client built over a device whose pairing client was shut down before its
/// first login starts with the bootstrap armed, and runs it on its first
/// connection, as the pairing client would have after its 515.
#[tokio::test]
async fn bootstrap_owed_survives_client_rebuild() {
    let backend = crate::test_utils::create_test_backend().await;
    pair_and_close(&backend).await;

    let (client, frames) = client_over(&backend).await;
    assert!(
        client.needs_initial_full_sync.is_armed(),
        "the gate starts from the record that owes the bootstrap"
    );
    let mut wire = Wire::default();
    log_in(&client).await;
    serve_until(&client, &frames, &mut wire, Wire::decided).await;
    assert_eq!(
        wire.app_state,
        bootstrap_syncs()[..1],
        "the first login syncs the critical collections"
    );
    assert_eq!(wire.presences, 0, "before announcing the session");
}

/// The bootstrap's completion clears the record as well as the gate, and saves
/// it: neither a later connection of the same client nor a client built after
/// it runs the bootstrap again.
#[tokio::test]
async fn bootstrap_cleared_after_completion() {
    let backend = crate::test_utils::create_test_backend().await;
    pair_and_close(&backend).await;

    let (client, frames) = client_over(&backend).await;
    let mut first = Wire::default();
    log_in(&client).await;
    serve_until(&client, &frames, &mut first, |wire| {
        wire.app_state.len() == 2
    })
    .await;
    assert_eq!(first.app_state, bootstrap_syncs());
    stored_owed_reaches(&backend, false).await;
    assert!(!client.needs_initial_full_sync.is_armed());

    let mut second = Wire::default();
    log_in(&client).await;
    serve_until(&client, &frames, &mut second, Wire::decided).await;
    assert_eq!(
        (second.app_state.len(), second.presences),
        (0, 1),
        "the next connection announces the session and syncs nothing"
    );

    client
        .shutdown()
        .await
        .device
        .expect("the shutdown saves the device");
    let (rebuilt, rebuilt_frames) = client_over(&backend).await;
    assert!(!rebuilt.needs_initial_full_sync.is_armed());
    let mut wire = Wire::default();
    log_in(&rebuilt).await;
    serve_until(&rebuilt, &rebuilt_frames, &mut wire, Wire::decided).await;
    assert_eq!(
        (wire.app_state.len(), wire.presences),
        (0, 1),
        "nor does a client built after it"
    );
}

/// The client that pairs keeps the library's own semantics: pairing arms its
/// gate past the pairing connection, which cannot settle it, the connection
/// the 515 brings up runs the bootstrap once, and the record that owes it from
/// the identity's own write clears with the gate.
#[tokio::test]
async fn pairing_client_unchanged_without_rebuild() {
    let backend = crate::test_utils::create_test_backend().await;
    let (client, frames) = client_over(&backend).await;
    assert!(!client.needs_initial_full_sync.is_armed());
    let pairing = client.sync_scope(None);
    pair(&client).await;
    assert!(client.needs_initial_full_sync.is_armed());
    // Saved as a host saves at pair-success.
    client
        .persistence_manager
        .flush()
        .await
        .expect("the device saves");
    let stored = stored_device(&backend).await;
    assert!(stored.pn.is_some(), "the stored record holds the identity");
    assert!(
        stored.initial_full_sync_owed,
        "and, written with it, the bootstrap it owes"
    );

    client.settle_bootstrap(pairing, false).await;
    assert!(
        client.needs_initial_full_sync.is_armed(),
        "the pairing connection cannot answer for the bootstrap pairing asked for"
    );
    assert!(
        client
            .persistence_manager
            .get_device_snapshot()
            .initial_full_sync_owed,
        "and a settle that does not take leaves the record alone"
    );

    let mut first = Wire::default();
    log_in(&client).await;
    serve_until(&client, &frames, &mut first, |wire| {
        wire.app_state.len() == 2
    })
    .await;
    assert_eq!(first.app_state, bootstrap_syncs());
    assert_eq!(first.presences, 0);
    stored_owed_reaches(&backend, false).await;
    assert!(!client.needs_initial_full_sync.is_armed());

    let mut second = Wire::default();
    log_in(&client).await;
    serve_until(&client, &frames, &mut second, Wire::decided).await;
    assert_eq!(
        (second.app_state.len(), second.presences),
        (0, 1),
        "the bootstrap ran once"
    );
}

/// A client built while the bootstrap is still owed, over a store that already
/// holds the app-state key (an earlier client received the primary's share and
/// stopped before the bootstrap completed), starts the critical sync at once.
/// The primary doesn't share the key again, so the key-share grace would only
/// hold the session back for its whole length.
#[tokio::test(start_paused = true)]
async fn bootstrap_owed_with_a_stored_key_skips_the_key_share_grace() {
    let backend = crate::test_utils::create_test_backend().await;
    pair_and_close(&backend).await;
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

    let (client, frames) = client_over(&backend).await;
    assert!(client.needs_initial_full_sync.is_armed());
    let mut wire = Wire::default();
    let logged_in = tokio::time::Instant::now();
    log_in_without_key_share(&client).await;
    serve_until(&client, &frames, &mut wire, Wire::decided).await;
    assert_eq!(
        wire.app_state,
        bootstrap_syncs()[..1],
        "the first login syncs the critical collections"
    );
    // The paused clock moves only once every task waits on a timer, so a
    // client that sat the grace out would have moved it by the whole grace.
    assert!(
        logged_in.elapsed() < Duration::from_secs(node_io::KEY_SHARE_GRACE_SECS),
        "without waiting out the key-share grace"
    );
}

// WF14: a commit the host holds while the collection moves under it, by the
// stage's scenario: the hook parks on a signal; the generation moves on (for a
// reconnect); another writer commits a newer version; the hook is released.
// Either way the held sync writes nothing over the newer version, announces
// nothing and fails retryably, and the collection's next sync goes on from the
// newer version.

const FOURTH_CHAT: &str = "120363000000000045@g.us";

/// Who moves the collection while the hook is parked.
#[derive(Clone, Copy, Debug)]
enum Mover {
    /// The next connection, after a reconnect: the generation moves on and the
    /// reservations are cleared, so the fence asked after the hook stops the
    /// held sync before its write.
    Reconnect,
    /// A writer the generation can't see (another client over the same store,
    /// or a retirement landing after the fence's last ask): the fence still
    /// holds, and only the store's comparison refuses the held write.
    Unseen,
}

impl Mover {
    /// The generation (for a reconnect), then the collection: `state` with
    /// `rows`, committed as that writer's sync would.
    async fn moves(
        self,
        client: &Client,
        host: &Host,
        state: HashState,
        rows: &[AppStateMutationMAC],
    ) {
        if let Mover::Reconnect = self {
            client.advance_generation_for_test(1, Ordering::SeqCst);
            client.app_state_syncing.clear();
        }
        host.backend
            .commit_patch(COLLECTION.as_str(), state, &[], rows)
            .await
            .expect("the test store takes a patch");
    }

    /// The held sync's error: the retirement, or the store's conflict over
    /// `base` with `stored`. Either is retryable: the collection is synced
    /// again as any failed sync is, and the primary is asked for nothing.
    fn failed(self, error: &anyhow::Error, base: Option<u64>, stored: u64) {
        let found = error.downcast_ref::<AppStateSyncError>();
        match self {
            Mover::Reconnect => assert!(
                matches!(found, Some(AppStateSyncError::Retired)),
                "{error:#}"
            ),
            Mover::Unseen => assert!(
                matches!(
                    found,
                    Some(AppStateSyncError::VersionConflict { base: b, stored: Some(s) })
                        if *b == base && *s == stored
                ),
                "{error:#}"
            ),
        }
        assert_eq!(
            RecoveryRequest::for_error(COLLECTION, error.downcast_ref()),
            RecoveryRequest::NotNeeded,
            "{self:?}"
        );
    }
}

/// The patch path: v8 is held over v7 while the mover commits v9.
async fn patch_held_while_the_collection_moves(mover: Mover) {
    let host = Host::new().await;
    let base = host.baseline(7).await;
    let (client, transport, _subscription) = client_for(&host).await;
    let mut server = Server { state: base };
    let held = server.patch(FIRST_CHAT, 1_000);
    server.patch(SECOND_CHAT, 1_001);
    let moved = server.state.clone();
    let next = server.patch(THIRD_CHAT, 1_002);
    let rows = [mac_row(FIRST_CHAT), mac_row(SECOND_CHAT)];

    let (entered, release) = host.park_next();
    let move_it = async {
        entered.await.expect("the hook parks");
        mover.moves(&client, &host, moved, &rows).await;
        release.send(()).expect("the hook is parked");
    };
    let held_sync = async {
        let synced = client.sync_collections_batched(vec![COLLECTION], client.sync_scope(None));
        futures::join!(synced, move_it).0
    };
    let error = serve(
        &client,
        &transport,
        0,
        vec![page(false, vec![held])],
        held_sync,
    )
    .await
    .expect_err("the held sync fails");

    mover.failed(&error, Some(7), 9);
    assert_eq!(
        host.take(),
        vec![commit(COLLECTION, Patch, 8, &[FIRST_CHAT], false, Some(7))],
        "{mover:?}: the held commit, and no event"
    );
    assert_eq!(host.version(COLLECTION).await, Some(9), "{mover:?}");
    assert_eq!(
        (host.mac(FIRST_CHAT).await, host.mac(SECOND_CHAT).await),
        (
            Some(rows[0].value_mac.clone()),
            Some(rows[1].value_mac.clone())
        ),
        "{mover:?}: the mover's rows, not the held patch's"
    );

    // The replacement connection, logged in, syncs the collection from v9.
    reachable(&client);
    let outcome = sync_collection(&client, &transport, 1, vec![page(false, vec![next])])
        .await
        .expect("the next sync applies v10");
    assert_eq!(outcome.synced, vec![COLLECTION], "{mover:?}");
    assert_eq!(
        host.take(),
        vec![
            commit(COLLECTION, Patch, 10, &[THIRD_CHAT], false, Some(9)),
            archived(THIRD_CHAT, false),
        ],
        "{mover:?}"
    );
    assert_eq!(host.version(COLLECTION).await, Some(10), "{mover:?}");
}

/// The snapshot path: a collection with no record bootstraps from a snapshot
/// at v5, held while the mover commits v6.
async fn snapshot_held_while_the_collection_moves(mover: Mover) {
    let host = Host::new().await;
    let mut server = Server::default();
    let (reference, blob) = snapshot_blob(&server.snapshot(5, &[FIRST_CHAT, SECOND_CHAT]));
    server.patch(THIRD_CHAT, 1_002);
    let moved = server.state.clone();
    let next = server.patch(FOURTH_CHAT, 1_003);
    let rows = [
        mac_row(FIRST_CHAT),
        mac_row(SECOND_CHAT),
        mac_row(THIRD_CHAT),
    ];
    let (client, transport, _subscription) = client_with(&host, Arc::new(BlobHost(blob))).await;
    media_route(&client).await;

    let (entered, release) = host.park_next();
    let move_it = async {
        entered.await.expect("the hook parks");
        mover.moves(&client, &host, moved, &rows).await;
        release.send(()).expect("the hook is parked");
    };
    let held_sync = async {
        let synced = client.sync_collections_batched(vec![COLLECTION], client.sync_scope(None));
        futures::join!(synced, move_it).0
    };
    let error = serve(
        &client,
        &transport,
        0,
        vec![snapshot_page(reference)],
        held_sync,
    )
    .await
    .expect_err("the held sync fails");

    mover.failed(&error, None, 6);
    assert_eq!(
        host.take(),
        vec![commit(
            COLLECTION,
            AppStateBatchKind::Snapshot,
            5,
            &[FIRST_CHAT, SECOND_CHAT],
            true,
            None
        )],
        "{mover:?}: the held commit, and no event"
    );
    assert_eq!(host.version(COLLECTION).await, Some(6), "{mover:?}");
    assert_eq!(
        (
            host.mac(FIRST_CHAT).await,
            host.mac(SECOND_CHAT).await,
            host.mac(THIRD_CHAT).await
        ),
        (
            Some(rows[0].value_mac.clone()),
            Some(rows[1].value_mac.clone()),
            Some(rows[2].value_mac.clone())
        ),
        "{mover:?}: the mover's rows, not the held snapshot's"
    );

    // The replacement connection, logged in, syncs the collection from v6.
    reachable(&client);
    let outcome = sync_collection(&client, &transport, 1, vec![page(false, vec![next])])
        .await
        .expect("the next sync applies v7");
    assert_eq!(outcome.synced, vec![COLLECTION], "{mover:?}");
    assert_eq!(
        host.take(),
        vec![
            commit(COLLECTION, Patch, 7, &[FOURTH_CHAT], false, Some(6)),
            archived(FOURTH_CHAT, false),
        ],
        "{mover:?}"
    );
    assert_eq!(host.version(COLLECTION).await, Some(7), "{mover:?}");
}

/// A patch held across a move of its collection writes nothing over the newer
/// version, whichever writer moved it.
#[tokio::test]
async fn app_state_patch_held_while_the_collection_moves_writes_nothing() {
    for mover in [Mover::Reconnect, Mover::Unseen] {
        patch_held_while_the_collection_moves(mover).await;
    }
}

/// A snapshot held across a move of its collection writes none of its rows or
/// its version over the newer version, whichever writer moved it.
#[tokio::test]
async fn app_state_snapshot_held_while_the_collection_moves_writes_nothing() {
    for mover in [Mover::Reconnect, Mover::Unseen] {
        snapshot_held_while_the_collection_moves(mover).await;
    }
}

/// The patch path when the collection comes back to the very version the held
/// patch was built on, by a writer the connection can't see. The local v7 had
/// diverged from the server's (another ltHash), so v8 is folded over the
/// diverged copy; while it is held, the collection is stood down and rebuilt as
/// the server holds v7, the repair a consumer's snapshot resync makes. The
/// store compares the collection's ltHash with the version and refuses v8, so
/// the repair stays, and the collection's next sync applies v8 over the
/// rebuilt v7, whose ltHash its snapshot MAC now matches.
#[tokio::test]
async fn app_state_patch_held_across_a_rebuild_to_its_version_writes_nothing() {
    let host = Host::new().await;
    let mut server = Server {
        state: HashState {
            version: 7,
            bootstrapped: true,
            ..Default::default()
        },
    };
    let rebuilt = server.state.clone();
    let diverged = HashState {
        hash: [0x5A; 128],
        ..rebuilt.clone()
    };
    host.backend
        .set_version(COLLECTION.as_str(), diverged)
        .await
        .expect("the test store takes a version");
    let (client, transport, _subscription) = client_for(&host).await;
    let held = server.patch(FIRST_CHAT, 1_000);

    let (entered, release) = host.park_next();
    let rebuild = async {
        entered.await.expect("the hook parks");
        host.backend
            .delete_version(COLLECTION.as_str())
            .await
            .expect("the test store stands the collection down");
        host.backend
            .set_version(COLLECTION.as_str(), rebuilt.clone())
            .await
            .expect("the test store takes the rebuilt version");
        release.send(()).expect("the hook is parked");
    };
    let held_sync = async {
        let synced = client.sync_collections_batched(vec![COLLECTION], client.sync_scope(None));
        futures::join!(synced, rebuild).0
    };
    let error = serve(
        &client,
        &transport,
        0,
        vec![page(false, vec![held.clone()])],
        held_sync,
    )
    .await
    .expect_err("the held sync fails");

    Mover::Unseen.failed(&error, Some(7), 7);
    assert_eq!(
        host.take(),
        vec![commit(COLLECTION, Patch, 8, &[FIRST_CHAT], false, Some(7))],
        "the held commit, and no event"
    );
    let stored = host
        .backend
        .get_version(COLLECTION.as_str())
        .await
        .expect("the test store reads")
        .expect("the rebuilt record");
    assert_eq!(
        (stored.version, stored.hash, stored.mac_mismatch_fatal),
        (7, rebuilt.hash, false),
        "the repair stays"
    );
    assert!(
        !host.has_mac(FIRST_CHAT).await,
        "none of the held patch's rows"
    );

    // The replacement for the held sync applies v8 over the rebuilt v7.
    reachable(&client);
    let outcome = sync_collection(&client, &transport, 1, vec![page(false, vec![held])])
        .await
        .expect("the next sync applies v8");
    assert_eq!(outcome.synced, vec![COLLECTION]);
    assert_eq!(
        host.take(),
        vec![
            commit(COLLECTION, Patch, 8, &[FIRST_CHAT], false, Some(7)),
            archived(FIRST_CHAT, false),
        ]
    );
    let stored = host
        .backend
        .get_version(COLLECTION.as_str())
        .await
        .expect("the test store reads")
        .expect("the synced record");
    assert_eq!(
        (stored.version, stored.hash, stored.mac_mismatch_fatal),
        (8, server.state.hash, false),
        "v8 over the server's v7, its snapshot MAC matched"
    );
}

/// The re-sync after an accepted send has its commit refused, because a writer
/// the connection can't see moved the collection while the host held it. That
/// writer has committed, so the re-sync syncs the collection again at once,
/// from the version it left, within the send rather than after the retry
/// scheduler's backoff.
#[tokio::test]
async fn app_state_resync_after_a_send_retries_a_conflict_at_once() {
    let host = Host::new().await;
    let base = host.baseline(7).await;
    let (client, transport, _subscription) = client_for(&host).await;
    reachable(&client);
    let mut server = Server { state: base };
    let echoed = server.patch(FIRST_CHAT, 1_000);
    server.patch(SECOND_CHAT, 1_001);
    let moved = server.state.clone();
    let next = server.patch(THIRD_CHAT, 1_002);
    let rows = [mac_row(FIRST_CHAT), mac_row(SECOND_CHAT)];

    let (entered, release) = host.park_next();
    let move_it = async {
        entered.await.expect("the hook parks");
        Mover::Unseen.moves(&client, &host, moved, &rows).await;
        release.send(()).expect("the hook is parked");
    };
    let send = async {
        let sent =
            client.send_app_state_patch(COLLECTION.as_str(), vec![wa::SyncdMutation::default()]);
        futures::join!(sent, move_it).0
    };
    serve(
        &client,
        &transport,
        0,
        // The send is accepted; its re-sync fetches v8, whose commit the mover
        // beats to the store; the retry fetches v10 from the mover's v9.
        vec![
            page(false, Vec::new()),
            page(false, vec![echoed]),
            page(false, vec![next]),
        ],
        send,
    )
    .await
    .expect("the send is accepted");

    assert_eq!(
        host.take(),
        vec![
            commit(COLLECTION, Patch, 8, &[FIRST_CHAT], false, Some(7)),
            commit(COLLECTION, Patch, 10, &[THIRD_CHAT], false, Some(9)),
            archived(THIRD_CHAT, false),
        ],
        "the refused commit announces nothing, and the retry commits v10 before its event"
    );
    assert_eq!(host.version(COLLECTION).await, Some(10));
    assert_eq!(
        host.mac(FIRST_CHAT).await,
        Some(rows[0].value_mac.clone()),
        "the mover's row, not the refused patch's"
    );
}

/// A recovery from the primary whose write the store refuses, because a writer
/// the connection can't see moved the collection while the host held the
/// recovery's commit, writes none of its rows and announces nothing; the
/// collection is then converged by a sync from the version that writer left.
#[tokio::test]
async fn app_state_recovery_refused_by_the_store_converges_by_a_sync() {
    let host = Host::new().await;
    let base = host.baseline(3).await;
    let (client, transport, _subscription) = client_for(&host).await;
    reachable(&client);
    let mut server = Server { state: base };
    server.patch(SECOND_CHAT, 1_001);
    let moved = server.state.clone();
    let next = server.patch(THIRD_CHAT, 1_002);
    let rows = [mac_row(SECOND_CHAT)];
    let first_frame = transport.sent().len();

    let (entered, release) = host.park_next();
    let move_it = async {
        entered.await.expect("the hook parks");
        Mover::Unseen.moves(&client, &host, moved, &rows).await;
        release.send(()).expect("the hook is parked");
    };
    futures::join!(
        client.apply_recovered_collection(
            COLLECTION.as_str(),
            None,
            recovery(COLLECTION, 9, &[FIRST_CHAT])
        ),
        move_it
    );

    assert_eq!(
        host.take(),
        vec![commit(
            COLLECTION,
            AppStateBatchKind::Recovery,
            9,
            &[FIRST_CHAT],
            true,
            Some(3)
        )],
        "the held commit, and no event"
    );
    assert_eq!(host.version(COLLECTION).await, Some(4));
    assert_eq!(
        (host.mac(FIRST_CHAT).await, host.mac(SECOND_CHAT).await),
        (None, Some(rows[0].value_mac.clone())),
        "the mover's rows, none of the recovery's"
    );

    // The refusal scheduled a sync of the collection. The clock is paused for
    // that sync's first backoff, which then elapses once nothing else can run,
    // and resumed after it, so the IQ helpers keep their hang guards.
    tokio::time::pause();
    tokio::time::sleep(APP_STATE_RETRY_BACKOFF_MIN).await;
    tokio::time::resume();
    serve(
        &client,
        &transport,
        first_frame,
        vec![page(false, vec![next])],
        host.announced.notified(),
    )
    .await;
    assert_eq!(
        host.take(),
        vec![
            commit(COLLECTION, Patch, 5, &[THIRD_CHAT], false, Some(4)),
            archived(THIRD_CHAT, false),
        ]
    );
    assert_eq!(host.version(COLLECTION).await, Some(5));
}
