//! WF21: a change announced while another sync holds its collection, by a
//! `server_sync` or by the `syncd_app_state` dirty bit's re-sync. The holder is
//! a sync of the collection whose first page the host parks, so it holds the
//! reservation with its fetch already answered; the announcement's own sync
//! skips behind it. Once the holder releases the collection, the announcement
//! is fetched, unless what the holder stored reached it; a connection that ends
//! before it is fetched hands it to the next one. The registry's own paths
//! follow: a release that takes what an earlier holder left untaken, a
//! collection released before its follow, a follower that meets another sync.

use super::*;
use crate::handlers::ib::resync_dirty_app_state;
use crate::handlers::notification::server_sync;
use Announcement::{Dirty, ServerSync};

/// What announces a change of the collection.
enum Announcement<'a> {
    /// A `server_sync` notification naming the collection once for each
    /// version here (0 for none).
    ServerSync(&'a [u64]),
    /// The `syncd_app_state` dirty bit's re-sync, once its clean IQ is sent.
    Dirty,
}

/// `announcement`'s sync, on the connection `generation`.
async fn announce(client: &Arc<Client>, announcement: &Announcement<'_>, generation: u64) {
    match announcement {
        ServerSync(versions) => {
            let collections = versions.iter().map(|&version| (COLLECTION, version));
            server_sync(client.clone(), collections.collect(), generation).await;
        }
        Dirty => {
            let scope = SyncScope {
                generation,
                deadline: None,
            };
            resync_dirty_app_state(client, vec![COLLECTION], scope).await;
        }
    }
}

/// The holder's sync, whose page the host parks, beside the sync of `first`,
/// made while it is parked, which skips behind the holder and follows it. Once
/// that follower waits for the release, `meanwhile` runs (given the
/// connection), then the holder is let go. `answers` serves the holder's IQ and
/// every IQ after it, in order, until both syncs have ended. Returns what the
/// holder's sync ended with.
async fn while_held(
    host: &Arc<Host>,
    client: &Arc<Client>,
    transport: &Arc<CapturingMockTransport>,
    first: &Announcement<'_>,
    meanwhile: impl AsyncFnOnce(u64),
    answers: Vec<Answer>,
) -> Result<BatchedSyncOutcome> {
    let (entered, release) = host.park_next();
    let holder = client.sync_collections_batched(vec![COLLECTION], client.sync_scope(None));
    let announcing = async {
        entered.await.expect("the holder's commit parks");
        let generation = client.connection_generation.load(Ordering::SeqCst);
        let follows = announce(client, first, generation);
        let then = async {
            // The first announcement's sync skipped behind the holder and
            // waits for its release.
            crate::test_utils::wait_for_notifier_listeners(&client.app_state_syncing.released, 1)
                .await;
            meanwhile(generation).await;
            release.send(()).expect("the holder's commit is parked");
        };
        futures::join!(follows, then);
    };
    let (held, ()) = serve(client, transport, 0, answers, async {
        futures::join!(holder, announcing)
    })
    .await;
    held
}

/// [`while_held`] with `announced`, all made while the holder is parked: the
/// first one's sync follows the holder, the rest leave theirs on it. Returns
/// what the holder's sync ended with.
async fn announced_while_held(
    host: &Arc<Host>,
    client: &Arc<Client>,
    transport: &Arc<CapturingMockTransport>,
    announced: &[Announcement<'_>],
    answers: Vec<Answer>,
) -> BatchedSyncOutcome {
    let (first, rest) = announced.split_first().expect("one announcement at least");
    let others = async |generation: u64| {
        for announcement in rest {
            announce(client, announcement, generation).await;
        }
    };
    while_held(host, client, transport, first, others, answers)
        .await
        .expect("the holder's sync ends")
}

/// A reconnect, as cleanup makes one: the generation moves on first, then the
/// reservations go.
fn reconnect(client: &Client) {
    client.advance_generation_for_test(1, Ordering::SeqCst);
    client.app_state_syncing.clear();
}

/// The next connection logs in, and the sync the one before it carried over
/// runs on it once the retry's first backoff elapses: `answers` serves its IQs
/// from frame `first_frame` on, until `chat`'s archive is announced.
async fn carried_over_to_the_next_connection(
    host: &Host,
    client: &Arc<Client>,
    transport: &Arc<CapturingMockTransport>,
    first_frame: usize,
    answers: Vec<Answer>,
    chat: &str,
) {
    reachable(client);
    // The clock is paused for the retry's first backoff, which then elapses
    // once nothing else can run, and resumed after it, so the IQ helpers keep
    // their hang guards.
    tokio::time::pause();
    tokio::time::sleep(APP_STATE_RETRY_BACKOFF_MIN).await;
    tokio::time::resume();
    let announced = archived(chat, false);
    let applied = crate::test_utils::poll_until("the carried-over sync's change announced", || {
        host.seen.lock().expect("journal lock").contains(&announced)
    });
    serve(client, transport, first_frame, answers, applied).await;
}

/// The change announced while the holder held the collection is fetched once it
/// lets go, by one more IQ, after the holder's own page.
#[tokio::test]
async fn a_server_sync_behind_a_sync_is_fetched_after_it() {
    let host = Host::new().await;
    let base = host.baseline(7).await;
    let (client, transport, _subscription) = client_for(&host).await;
    let mut server = Server { state: base };
    let held = server.patch(FIRST_CHAT, 1_000);
    let announced = server.patch(SECOND_CHAT, 1_001);

    let outcome = announced_while_held(
        &host,
        &client,
        &transport,
        &[ServerSync(&[9])],
        vec![page(false, vec![held]), page(false, vec![announced])],
    )
    .await;

    assert_eq!(outcome.synced, vec![COLLECTION]);
    assert_eq!(
        transport.sent().len(),
        2,
        "the holder's IQ, then the follower's"
    );
    assert_eq!(host.version(COLLECTION).await, Some(9));
    assert_eq!(
        host.take(),
        vec![
            commit(COLLECTION, Patch, 8, &[FIRST_CHAT], false, Some(7)),
            archived(FIRST_CHAT, false),
            commit(COLLECTION, Patch, 9, &[SECOND_CHAT], false, Some(8)),
            archived(SECOND_CHAT, false),
        ]
    );
}

/// A change the holder's fetch already carried isn't fetched again: the holder
/// stored the version announced. (A second IQ would be answered, and counted.)
#[tokio::test]
async fn a_server_sync_the_holder_reached_is_not_fetched_again() {
    let host = Host::new().await;
    let base = host.baseline(7).await;
    let (client, transport, _subscription) = client_for(&host).await;
    let mut server = Server { state: base };
    let held = server.patch(FIRST_CHAT, 1_000);

    let outcome = announced_while_held(
        &host,
        &client,
        &transport,
        &[ServerSync(&[8])],
        vec![page(false, vec![held]), page(false, Vec::new())],
    )
    .await;

    assert_eq!(outcome.synced, vec![COLLECTION]);
    assert_eq!(transport.sent().len(), 1, "the holder's IQ alone");
    assert_eq!(host.version(COLLECTION).await, Some(8));
}

/// An announcement without a version can't be found reached: the collection is
/// fetched again after the holder, which here brings nothing new.
#[tokio::test]
async fn a_server_sync_without_a_version_is_fetched_after_the_sync_it_met() {
    let host = Host::new().await;
    let base = host.baseline(7).await;
    let (client, transport, _subscription) = client_for(&host).await;
    let mut server = Server { state: base };
    let held = server.patch(FIRST_CHAT, 1_000);

    announced_while_held(
        &host,
        &client,
        &transport,
        &[ServerSync(&[0])],
        vec![page(false, vec![held]), page(false, Vec::new())],
    )
    .await;

    assert_eq!(
        transport.sent().len(),
        2,
        "the holder's IQ, then the follower's"
    );
    assert_eq!(host.version(COLLECTION).await, Some(8));
}

/// Two announcements behind one holder are fetched by one sync, which knows the
/// later one: it fetches past the first's version to the second's.
#[tokio::test]
async fn announcements_behind_one_sync_are_fetched_once() {
    let host = Host::new().await;
    let base = host.baseline(7).await;
    let (client, transport, _subscription) = client_for(&host).await;
    let mut server = Server { state: base };
    let held = server.patch(FIRST_CHAT, 1_000);
    let ninth = server.patch(SECOND_CHAT, 1_001);
    let tenth = server.patch(THIRD_CHAT, 1_002);

    announced_while_held(
        &host,
        &client,
        &transport,
        &[ServerSync(&[9]), ServerSync(&[10])],
        vec![
            page(false, vec![held]),
            page(false, vec![ninth, tenth]),
            page(false, Vec::new()),
        ],
    )
    .await;

    assert_eq!(
        transport.sent().len(),
        2,
        "the holder's IQ, then one follower's"
    );
    assert_eq!(host.version(COLLECTION).await, Some(10));
}

/// One `server_sync` naming the collection twice is followed to the later
/// version: the holder's page reached the first, and the follower fetches the
/// second.
#[tokio::test]
async fn a_collection_named_twice_is_followed_to_its_later_version() {
    let host = Host::new().await;
    let base = host.baseline(7).await;
    let (client, transport, _subscription) = client_for(&host).await;
    let mut server = Server { state: base };
    let held = server.patch(FIRST_CHAT, 1_000);
    let ninth = server.patch(SECOND_CHAT, 1_001);

    announced_while_held(
        &host,
        &client,
        &transport,
        &[ServerSync(&[8, 9])],
        vec![page(false, vec![held]), page(false, vec![ninth])],
    )
    .await;

    assert_eq!(
        transport.sent().len(),
        2,
        "the holder's IQ, then the follower's"
    );
    assert_eq!(host.version(COLLECTION).await, Some(9));
}

/// A child without a version beside one the holder's page reached still has
/// the collection fetched after the holder: no stored version reaches it.
#[tokio::test]
async fn a_collection_named_without_a_version_too_is_fetched_after_the_sync() {
    let host = Host::new().await;
    let base = host.baseline(7).await;
    let (client, transport, _subscription) = client_for(&host).await;
    let mut server = Server { state: base };
    let held = server.patch(FIRST_CHAT, 1_000);

    announced_while_held(
        &host,
        &client,
        &transport,
        &[ServerSync(&[8, 0])],
        vec![page(false, vec![held]), page(false, Vec::new())],
    )
    .await;

    assert_eq!(
        transport.sent().len(),
        2,
        "the holder's IQ, then the follower's"
    );
    assert_eq!(host.version(COLLECTION).await, Some(8));
}

/// The dirty bit's re-sync behind a sync of the collection fetches it after
/// that sync: the bit names no version, so the holder's answer may predate it.
#[tokio::test]
async fn a_dirty_bit_behind_a_sync_is_fetched_after_it() {
    let host = Host::new().await;
    let base = host.baseline(7).await;
    let (client, transport, _subscription) = client_for(&host).await;
    let mut server = Server { state: base };
    let held = server.patch(FIRST_CHAT, 1_000);

    announced_while_held(
        &host,
        &client,
        &transport,
        &[Dirty],
        vec![page(false, vec![held]), page(false, Vec::new())],
    )
    .await;

    assert_eq!(
        transport.sent().len(),
        2,
        "the holder's IQ, then the follower's"
    );
    assert_eq!(host.version(COLLECTION).await, Some(8));
}

/// The connection ends while the holder holds the collection: the follower
/// hands the announcement to the next connection, which fetches it once it logs
/// in (an ordinary reconnect runs no app-state sync of its own). The holder's
/// page, held across the reconnect, wrote nothing, so that fetch brings both.
#[tokio::test]
async fn a_server_sync_behind_a_sync_its_connection_ended_is_fetched_on_the_next() {
    let host = Host::new().await;
    let base = host.baseline(7).await;
    let (client, transport, _subscription) = client_for(&host).await;
    let mut server = Server { state: base };
    let held = server.patch(FIRST_CHAT, 1_000);
    let announced = server.patch(SECOND_CHAT, 1_001);

    let ended = while_held(
        &host,
        &client,
        &transport,
        &ServerSync(&[9]),
        async |_: u64| reconnect(&client),
        vec![page(false, vec![held.clone()])],
    )
    .await;
    let error = ended.expect_err("the holder's connection retired under it");
    assert!(
        matches!(error.downcast_ref(), Some(AppStateSyncError::Retired)),
        "{error:#}"
    );
    assert_eq!(transport.sent().len(), 1, "the holder's IQ alone");

    carried_over_to_the_next_connection(
        &host,
        &client,
        &transport,
        1,
        vec![page(false, vec![held, announced])],
        SECOND_CHAT,
    )
    .await;
    assert_eq!(transport.sent().len(), 2, "one IQ on the next connection");
    assert_eq!(host.version(COLLECTION).await, Some(9));
    assert_eq!(
        host.take(),
        vec![
            commit(COLLECTION, Patch, 8, &[FIRST_CHAT], false, Some(7)),
            commit(COLLECTION, Patch, 8, &[FIRST_CHAT], false, Some(7)),
            commit(COLLECTION, Patch, 9, &[SECOND_CHAT], false, Some(8)),
            archived(FIRST_CHAT, false),
            archived(SECOND_CHAT, false),
        ],
        "the held commit, then the next connection's page, announced once it is applied"
    );
}

/// A `server_sync` whose own sync loses its connection while the host commits:
/// that sync's outcome is the old connection's, dropped, but not its work,
/// which the next connection fetches once it logs in.
#[tokio::test]
async fn a_server_sync_whose_connection_ends_under_it_is_fetched_on_the_next() {
    let host = Host::new().await;
    let base = host.baseline(7).await;
    let (client, transport, _subscription) = client_for(&host).await;
    let announced = Server { state: base }.patch(FIRST_CHAT, 1_000);

    let (entered, release) = host.park_next();
    let generation = client.connection_generation.load(Ordering::SeqCst);
    let reconnect_under_it = async {
        entered.await.expect("the sync's commit parks");
        reconnect(&client);
        release.send(()).expect("the sync's commit is parked");
    };
    let synced = server_sync(client.clone(), vec![(COLLECTION, 8)], generation);
    serve(
        &client,
        &transport,
        0,
        vec![page(false, vec![announced.clone()])],
        async { futures::join!(synced, reconnect_under_it) },
    )
    .await;
    assert_eq!(host.version(COLLECTION).await, Some(7), "its write fenced");

    carried_over_to_the_next_connection(
        &host,
        &client,
        &transport,
        1,
        vec![page(false, vec![announced])],
        FIRST_CHAT,
    )
    .await;
    assert_eq!(transport.sent().len(), 2, "one IQ on the next connection");
    assert_eq!(host.version(COLLECTION).await, Some(8));
}

/// A `server_sync` whose task starts once its connection has ended (the
/// notification is acked as it arrives, before the task runs) is fetched on the
/// next connection.
#[tokio::test]
async fn a_server_sync_that_starts_after_its_connection_is_fetched_on_the_next() {
    let host = Host::new().await;
    let base = host.baseline(7).await;
    let (client, transport, _subscription) = client_for(&host).await;
    let announced = Server { state: base }.patch(FIRST_CHAT, 1_000);

    let generation = client.connection_generation.load(Ordering::SeqCst);
    reconnect(&client);
    server_sync(client.clone(), vec![(COLLECTION, 8)], generation).await;
    assert!(transport.sent().is_empty(), "nothing on the old connection");

    carried_over_to_the_next_connection(
        &host,
        &client,
        &transport,
        0,
        vec![page(false, vec![announced])],
        FIRST_CHAT,
    )
    .await;
    assert_eq!(host.version(COLLECTION).await, Some(8));
}

/// A release takes what an earlier holder left and its follower hasn't taken
/// yet (the later holder began after that release, so after those
/// announcements), for the later holder's follower; one nothing was announced
/// to leaves it where it was.
#[test]
fn a_release_takes_what_an_earlier_holder_left_untaken() {
    let registry = SyncInFlight::new();
    let first = registry.try_begin(COLLECTION).expect("nothing holds it");
    let Follow::After(earlier) = registry.follow(COLLECTION, Announced::Unversioned) else {
        panic!("the first announcement on a reservation follows it");
    };
    drop(first);
    let second = registry.try_begin(COLLECTION).expect("released");
    let Follow::After(later) = registry.follow(COLLECTION, Announced::Version(8)) else {
        panic!("the first announcement on a reservation follows it");
    };
    drop(second);
    assert_eq!(
        registry.left_by(COLLECTION, earlier),
        Left::Cleared,
        "taken by the later release"
    );
    assert_eq!(
        registry.left_by(COLLECTION, later),
        Left::Released(Announced::Unversioned),
        "both, merged"
    );

    let third = registry.try_begin(COLLECTION).expect("released");
    let Follow::After(followed) = registry.follow(COLLECTION, Announced::Version(9)) else {
        panic!("the first announcement on a reservation follows it");
    };
    drop(third);
    drop(registry.try_begin(COLLECTION).expect("released"));
    assert_eq!(
        registry.left_by(COLLECTION, followed),
        Left::Released(Announced::Version(9)),
        "a release with nothing announced to it takes nothing"
    );
    assert_eq!(
        registry.follow(COLLECTION, Announced::Version(10)),
        Follow::Free,
        "nothing holds it"
    );
}

/// A collection its holder released between the batched round's skip and the
/// follow is synced at once: it leaves the round's outcome, and its follower
/// fetches it.
#[tokio::test]
async fn a_collection_released_before_its_follow_is_synced_at_once() {
    let host = Host::new().await;
    let base = host.baseline(7).await;
    let (client, transport, _subscription) = client_for(&host).await;
    let announced = Server { state: base }.patch(FIRST_CHAT, 1_000);

    let mut result = Ok(BatchedSyncOutcome {
        skipped: vec![COLLECTION],
        ..Default::default()
    });
    let followers = client.follow_skipped(&mut result, &[(COLLECTION, Announced::Version(8))]);
    assert_eq!(
        result.as_ref().expect("the round's outcome").skipped,
        Vec::new(),
        "covered by its follower"
    );

    let follow = client.run_followers(followers, client.sync_scope(None), "the test's follower");
    serve(
        &client,
        &transport,
        0,
        vec![page(false, vec![announced])],
        follow,
    )
    .await;
    assert_eq!(transport.sent().len(), 1, "the follower's IQ");
    assert_eq!(host.version(COLLECTION).await, Some(8));
}

/// A follower whose own sync meets another sync of the collection, which began
/// after the release it followed, follows that one in turn, and fetches the
/// collection once it lets go.
#[tokio::test]
async fn a_follower_that_meets_another_sync_follows_it() {
    let host = Host::new().await;
    let base = host.baseline(7).await;
    let (client, transport, _subscription) = client_for(&host).await;
    let announced = Server { state: base }.patch(FIRST_CHAT, 1_000);

    let registry = Arc::clone(&client.app_state_syncing);
    let first = registry.try_begin(COLLECTION).expect("nothing holds it");
    let generation = client.connection_generation.load(Ordering::SeqCst);
    let follows = server_sync(client.clone(), vec![(COLLECTION, 8)], generation);
    let handed_on = async move {
        crate::test_utils::wait_for_notifier_listeners(&registry.released, 1).await;
        // Released and taken again before the follower runs: it finds what the
        // first left, and its sync skips behind the second.
        drop(first);
        let second = registry.try_begin(COLLECTION).expect("released");
        crate::test_utils::poll_until("the follower follows the second sync", || {
            registry
                .reservations()
                .held
                .get(&COLLECTION)
                .is_some_and(|held| held.announced.is_some())
        })
        .await;
        drop(second);
    };
    serve(
        &client,
        &transport,
        0,
        vec![page(false, vec![announced])],
        async { futures::join!(follows, handed_on) },
    )
    .await;

    assert_eq!(transport.sent().len(), 1, "the follower's IQ, after both");
    assert_eq!(host.version(COLLECTION).await, Some(8));
}
