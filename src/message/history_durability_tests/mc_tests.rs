//! WF22: the history worker tells the host when it gives a durable chunk up, and
//! one key has one download at a time.
//!
//! Each way a worker task ends without the chunk captured and parsed reaches
//! `on_chunk_failed` once, with its reason: a download the network fails, one
//! the media server refuses, a body that doesn't verify, no connection to
//! download over, the host's own capture refused, a chunk that doesn't parse.
//! A stop of the client calls nothing. A host replay, or a redelivered carrier,
//! of a key whose task is in flight joins that task: the chunk is downloaded
//! once. A replay joined to another replay answers as that one ended.
//!
//! WF27 at the end: the hook shares the host's replayed bytes.

use super::*;
use crate::HistoryChunkFailure;

/// The media host: answers `status` with `body` once let go, counting requests.
struct MediaHost {
    status: u16,
    body: Vec<u8>,
    requests: AtomicUsize,
    entered: tokio::sync::Notify,
    release: tokio::sync::Semaphore,
}

#[async_trait::async_trait]
impl crate::http::HttpClient for MediaHost {
    async fn execute(
        &self,
        _request: crate::http::HttpRequest,
    ) -> anyhow::Result<crate::http::HttpResponse> {
        self.requests.fetch_add(1, Ordering::SeqCst);
        self.entered.notify_one();
        self.release.acquire().await.unwrap().forget();
        Ok(crate::http::HttpResponse::new(
            self.status,
            self.body.clone(),
        ))
    }
}

/// [`notification`]'s chunk behind a blob on the media host, which answers
/// `status` (with the encrypted chunk) once let go: it holds `permits` answers.
fn external(status: u16, permits: usize) -> (wa::message::HistorySyncNotification, Arc<MediaHost>) {
    let mut notification = notification();
    let compressed = notification
        .initial_hist_bootstrap_inline_payload
        .take()
        .unwrap();
    let encrypted =
        wacore::upload::encrypt_media(&compressed, wacore::download::MediaType::History).unwrap();
    notification.direct_path = Some("/wf22-history".to_owned());
    notification.media_key = Some(encrypted.media_key.to_vec());
    notification.file_sha256 = Some(encrypted.file_sha256.to_vec());
    notification.file_enc_sha256 = Some(encrypted.file_enc_sha256.to_vec());
    let host = Arc::new(MediaHost {
        status,
        body: encrypted.data_to_upload,
        requests: AtomicUsize::new(0),
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Semaphore::new(permits),
    });
    (notification, host)
}

/// A client whose downloads go to `host`, over a route it holds already; its
/// sync worker isn't started.
async fn client_of(
    host: Arc<MediaHost>,
) -> (
    Arc<Client>,
    Arc<RecordingHistory>,
    async_channel::Receiver<crate::sync_task::MajorSyncTask>,
) {
    let (client, hook, _transport, receiver) = client_with_http_and_runtime(
        Arc::new(wacore::store::in_memory::InMemoryBackend::new()),
        Arc::new(crate::runtime_impl::TokioRuntime),
        host,
    )
    .await;
    *client.media_conn.write().await = Some(crate::mediaconn::MediaConn {
        auth: "wf22-auth".to_owned(),
        ttl: 3600,
        auth_ttl: None,
        hosts: vec![wacore::iq::mediaconn::MediaConnHost::new(
            "media.example.com".to_owned(),
        )],
        fetched_at: wacore::time::Instant::now(),
    });
    (client, hook, receiver)
}

/// How a case's task ends.
#[derive(Clone, Copy, Debug)]
enum Case {
    /// The media host fails the download (500).
    ServerError,
    /// The media host refuses the reference (404): it doesn't serve the blob,
    /// which no other host or route changes.
    Refused,
    /// The media host serves a body whose MAC fails: the blob's bytes, which a
    /// later try gets again.
    Corrupt,
    /// The connection is gone when the worker takes the task.
    Disconnected,
    /// The host's `on_compressed_chunk` fails.
    CaptureRefused,
    /// The inline chunk doesn't inflate.
    Malformed,
}

/// Runs `case`'s carrier through the worker to its end, and returns what the
/// hook heard and the key it was the carrier of.
async fn failures_of(case: Case) -> (Vec<(HistorySyncKey, HistoryChunkFailure)>, HistorySyncKey) {
    let (mut notification, host) = match case {
        Case::ServerError => external(500, 1),
        Case::Refused => external(404, 1),
        Case::Corrupt => {
            let (notification, mut host) = external(200, 1);
            // The MAC is the body's last ten bytes.
            *Arc::get_mut(&mut host).unwrap().body.last_mut().unwrap() ^= 1;
            (notification, host)
        }
        Case::Disconnected => external(200, 1),
        Case::CaptureRefused | Case::Malformed => (notification(), external(200, 0).1),
    };
    if let Case::Malformed = case {
        notification.initial_hist_bootstrap_inline_payload = Some(vec![1, 2, 3]);
    }
    let (client, hook, receiver) = client_of(host).await;
    if let Case::CaptureRefused = case {
        hook.fail.store(2, Ordering::SeqCst);
    }
    let info = info(&format!("WF22_{case:?}"));
    assert!(receive(&client, &info, notification).await);
    if let Case::Disconnected = case {
        client.set_connected_for_test(false);
    }
    client.start_sync_task_worker(receiver);
    history_idle(&client).await;
    let failures = hook.failures.lock().unwrap().clone();
    (failures, key(&info))
}

/// The media host's own failure (500) is the network's: a later try can get
/// past it.
#[tokio::test]
async fn a_failed_download_reaches_the_hook_as_the_networks() {
    let (failures, key) = failures_of(Case::ServerError).await;
    assert_eq!(failures, vec![(key, HistoryChunkFailure::Network)]);
}

/// A reference the media server refuses is its refusal.
#[tokio::test]
async fn a_refused_blob_reaches_the_hook_as_refused() {
    let (failures, key) = failures_of(Case::Refused).await;
    assert_eq!(failures, vec![(key, HistoryChunkFailure::Refused)]);
}

/// A body that fails its MAC on every host is the blob's: refused, not the
/// network's, which a later try would download again.
#[tokio::test]
async fn a_body_that_doesnt_verify_reaches_the_hook_as_refused() {
    let (failures, key) = failures_of(Case::Corrupt).await;
    assert_eq!(failures, vec![(key, HistoryChunkFailure::Refused)]);
}

/// No connection to download over is the network's failure.
#[tokio::test]
async fn a_download_without_a_connection_reaches_the_hook_as_the_networks() {
    let (failures, key) = failures_of(Case::Disconnected).await;
    assert_eq!(failures, vec![(key, HistoryChunkFailure::Network)]);
}

/// The host's own capture refused is a capture failure.
#[tokio::test]
async fn a_refused_capture_reaches_the_hook_as_a_capture_failure() {
    let (failures, key) = failures_of(Case::CaptureRefused).await;
    assert_eq!(failures, vec![(key, HistoryChunkFailure::Capture)]);
}

/// A chunk that doesn't parse is malformed.
#[tokio::test]
async fn a_chunk_that_doesnt_parse_reaches_the_hook_as_malformed() {
    let (failures, key) = failures_of(Case::Malformed).await;
    assert_eq!(failures, vec![(key, HistoryChunkFailure::Malformed)]);
}

/// A download the client's stop interrupts is no failure of the chunk: nothing
/// is said, and the host replays at its next start.
#[tokio::test]
async fn a_stop_of_the_client_calls_nothing() {
    let (notification, host) = external(500, 0);
    let (client, hook, receiver) = client_of(host.clone()).await;
    client.start_sync_task_worker(receiver);
    let info = info("WF22_STOPPED");
    let entered = host.entered.notified();
    assert!(receive(&client, &info, notification).await);
    entered.await;
    client.signal_shutdown_sync();
    assert!(client.is_permanently_stopped());
    host.release.add_permits(1);
    history_idle(&client).await;
    assert!(hook.failures.lock().unwrap().is_empty());
    assert_eq!(hook.chunks.load(Ordering::SeqCst), 0);
}

/// The host replays a key whose worker task is still downloading (one queued
/// when its connection ended survives into the next, where the host replays the
/// same key): the replay waits for the task and answers as it ended, and the
/// chunk is downloaded, captured and parsed once.
#[tokio::test]
async fn a_replay_of_a_key_in_flight_downloads_once() {
    let (notification, host) = external(200, 0);
    let (client, hook, receiver) = client_of(host.clone()).await;
    client.start_sync_task_worker(receiver);
    let info = info("WF22_REPLAY");
    let entered = host.entered.notified();
    assert!(receive(&client, &info, notification).await);
    entered.await;
    let (key, bytes) = hook.records.lock().unwrap()[0].clone();
    let replay = tokio::spawn({
        let client = client.clone();
        let key = key.clone();
        async move { client.replay_history_sync_notification(&key, bytes).await }
    });
    // The replay has joined the task's flight: the registry, the task and it.
    crate::test_utils::poll_until("the replay joined the worker's flight", || {
        client.history_sync_activity.flight_holders(&key) >= 3
    })
    .await;
    // Room for a second download, which a replay of its own would make.
    host.release.add_permits(2);
    replay.await.unwrap().unwrap();
    history_idle(&client).await;
    assert_eq!(host.requests.load(Ordering::SeqCst), 1);
    assert_eq!(hook.chunks.load(Ordering::SeqCst), 1);
    assert!(hook.failures.lock().unwrap().is_empty());
    assert_eq!(client.history_sync_activity.flight_holders(&key), 0);
}

/// A replay that joins a task which then gives the chunk up answers with the
/// task's failure, in its error's chain; the hook hears it once, from the task.
#[tokio::test]
async fn a_replay_joined_to_a_failed_task_answers_its_failure() {
    let (notification, host) = external(500, 0);
    let (client, hook, receiver) = client_of(host.clone()).await;
    client.start_sync_task_worker(receiver);
    let info = info("WF22_REPLAY_FAILED");
    let entered = host.entered.notified();
    assert!(receive(&client, &info, notification).await);
    entered.await;
    let (key, bytes) = hook.records.lock().unwrap()[0].clone();
    let replay = tokio::spawn({
        let client = client.clone();
        let key = key.clone();
        async move { client.replay_history_sync_notification(&key, bytes).await }
    });
    crate::test_utils::poll_until("the replay joined the worker's flight", || {
        client.history_sync_activity.flight_holders(&key) >= 3
    })
    .await;
    host.release.add_permits(2);
    let error = replay.await.unwrap().unwrap_err();
    assert_eq!(
        error.downcast_ref::<HistoryChunkFailure>(),
        Some(&HistoryChunkFailure::Network)
    );
    history_idle(&client).await;
    assert_eq!(host.requests.load(Ordering::SeqCst), 1);
    assert_eq!(
        *hook.failures.lock().unwrap(),
        vec![(key, HistoryChunkFailure::Network)]
    );
}

/// A replay that leads a key ends its flight as it ended, whichever exit it
/// took: one whose notification doesn't decode answers `Malformed`, and so does
/// a replay of the key that joined it (not the network failure of a flight
/// dropped unfinished).
#[tokio::test]
async fn a_replay_joined_to_a_malformed_replay_answers_malformed() {
    let (client, hook, _transport) = memory_client().await;
    hook.require_journal.store(false, Ordering::SeqCst);
    // Another key's replay holds the one replay permit, parked in its hook.
    hook.chunk_parked.store(true, Ordering::SeqCst);
    let holder = tokio::spawn({
        let client = client.clone();
        async move {
            let bytes = Bytes::from(waproto::codec::history_sync_notification_to_vec(
                &notification(),
            ));
            client
                .replay_history_sync_notification(&key(&info("WF22_HOLDER")), bytes)
                .await
        }
    });
    hook.chunk_entered.notified().await;
    // The first replay of the key leads it and waits for the permit; the second
    // joins its flight: the registry, the lead and it.
    let malformed = key(&info("WF22_MALFORMED"));
    let mut leader =
        Box::pin(client.replay_history_sync_notification(&malformed, Bytes::from_static(&[255])));
    assert!(futures::poll!(leader.as_mut()).is_pending());
    let mut joiner =
        Box::pin(client.replay_history_sync_notification(&malformed, Bytes::from_static(&[255])));
    assert!(futures::poll!(joiner.as_mut()).is_pending());
    assert_eq!(client.history_sync_activity.flight_holders(&malformed), 3);
    hook.chunk_parked.store(false, Ordering::SeqCst);
    hook.chunk_gate.notify_one();
    holder.await.unwrap().unwrap();
    for error in [leader.await.unwrap_err(), joiner.await.unwrap_err()] {
        assert_eq!(
            error.downcast_ref::<HistoryChunkFailure>(),
            Some(&HistoryChunkFailure::Malformed),
            "{error:#}"
        );
    }
    assert_eq!(client.history_sync_activity.flight_holders(&malformed), 0);
}

/// A carrier redelivered while its key's task downloads isn't queued again.
#[tokio::test]
async fn a_redelivered_carrier_in_flight_is_not_queued_again() {
    let (notification, host) = external(200, 0);
    let (client, hook, receiver) = client_of(host.clone()).await;
    client.start_sync_task_worker(receiver);
    let info = info("WF22_REDELIVERED");
    let entered = host.entered.notified();
    assert!(receive(&client, &info, notification.clone()).await);
    entered.await;
    assert!(receive(&client, &info, notification).await);
    assert_eq!(hook.notifications.load(Ordering::SeqCst), 2);
    host.release.add_permits(2);
    history_idle(&client).await;
    assert_eq!(host.requests.load(Ordering::SeqCst), 1);
    assert_eq!(hook.chunks.load(Ordering::SeqCst), 1);
}

/// WF27: the hook takes the notification the host replays as the host's own
/// bytes, shared, not copied.
#[tokio::test]
async fn a_replayed_notification_reaches_the_hook_as_the_hosts_bytes() {
    let (client, hook, _transport) = memory_client().await;
    hook.require_journal.store(false, Ordering::SeqCst);
    let held = Bytes::from(waproto::codec::history_sync_notification_to_vec(
        &notification(),
    ));
    client
        .replay_history_sync_notification(&key(&info("WF27_SHARED")), held.clone())
        .await
        .unwrap();
    let records = hook.records.lock().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].1, held);
    assert_eq!(
        records[0].1.as_ptr(),
        held.as_ptr(),
        "the hook got a copy of the host's bytes"
    );
}
