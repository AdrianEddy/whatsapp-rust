//! WF19: a batched round whose first collection another writer moves while it is
//! applied. Its list holds two patches: the first commits, and the second is
//! held by the host while the writer commits past it. The round's other
//! collection comes back as a patch, or as the server's own conflict.

use super::*;
use crate::store::release::tests::ProbeBackend;

const OTHER: WAPatchName = WAPatchName::RegularLow;

/// What the round's response carries of the other collection, and what the
/// host makes of it.
#[derive(Clone, Copy)]
enum Other {
    /// A patch, behind the first collection's page, which the host commits.
    Applied,
    /// The same patch, whose commit the host refuses.
    Refused,
    /// The server's own conflict with no more pages, ahead of the first
    /// collection's page: over the baseline the collection holds, it is synced.
    ServerConflict,
}

/// One response holding these collections, in this order.
fn response(collections: Vec<Node>) -> Answer {
    Box::new(move |request_id| {
        NodeBuilder::new("iq")
            .attr("type", "result")
            .attr("id", request_id)
            .attr("from", "s.whatsapp.net")
            .children([NodeBuilder::new("sync")
                .children(collections.iter().cloned())
                .build()])
            .build()
    })
}

/// The last page of `name`, holding `served`.
fn last_page(name: WAPatchName, served: &[wa::SyncdPatch]) -> Node {
    NodeBuilder::new("collection")
        .attr("name", name.as_str())
        .attr("has_more_patches", "false")
        .children([patches(served)])
        .build()
}

/// The server's 409 for `name`, with no more pages.
fn server_conflict(name: WAPatchName) -> Node {
    NodeBuilder::new("collection")
        .attr("name", name.as_str())
        .attr("type", "error")
        .attr("has_more_patches", "false")
        .children([NodeBuilder::new("error")
            .attr("code", "409")
            .attr("text", "conflict")
            .build()])
        .build()
}

/// The round over both collections, the first moved by `mover` between its
/// two patches, and what the round ended with.
struct Round {
    host: Arc<Host>,
    client: Arc<Client>,
    transport: Arc<CapturingMockTransport>,
    _subscription: Subscription,
    /// The first collection's next patch, on the version the mover left.
    next: wa::SyncdPatch,
    ended: Result<BatchedSyncOutcome>,
}

async fn round(mover: Mover, other: Other) -> Round {
    round_on(Host::new().await, mover, other, async |_: &Client| {}).await
}

/// [`round`] of `host`, beside `meanwhile`.
async fn round_on(
    host: Arc<Host>,
    mover: Mover,
    other_page: Other,
    meanwhile: impl AsyncFnOnce(&Client),
) -> Round {
    let base = host.baseline(7).await;
    let mut other = HashState {
        version: 3,
        bootstrapped: true,
        ..Default::default()
    };
    host.backend
        .set_version(OTHER.as_str(), other.clone())
        .await
        .expect("the test store takes a version");
    let (client, transport, subscription) = client_for(&host).await;
    let mut server = Server { state: base };
    let first = server.patch(FIRST_CHAT, 1_000);
    let held = server.patch(SECOND_CHAT, 1_001);
    server.patch(THIRD_CHAT, 1_002);
    let moved = server.state.clone();
    let next = server.patch("120363000000000046@g.us", 1_003);
    let rows = [mac_row(SECOND_CHAT), mac_row(THIRD_CHAT)];
    let first_page = last_page(COLLECTION, &[first, held]);
    let collections = match other_page {
        Other::Applied | Other::Refused => vec![
            first_page,
            last_page(OTHER, &[next_patch(OTHER, &mut other, FOURTH_CHAT, 1_004)]),
        ],
        Other::ServerConflict => vec![server_conflict(OTHER), first_page],
    };

    let (entered, release) = host.park_after(1);
    let move_it = async {
        entered.await.expect("the hook parks");
        mover.moves(&client, &host, moved, &rows).await;
        host.refuse
            .store(matches!(other_page, Other::Refused), Ordering::SeqCst);
        release.send(()).expect("the hook is parked");
    };
    let synced = async {
        let synced =
            client.sync_collections_batched(vec![COLLECTION, OTHER], client.sync_scope(None));
        futures::join!(synced, move_it, meanwhile(&client)).0
    };
    let ended = serve(&client, &transport, 0, vec![response(collections)], synced).await;
    Round {
        host,
        client,
        transport,
        _subscription: subscription,
        next,
        ended,
    }
}

/// The commits of the first collection: the patch that landed, and the one the
/// store refused.
fn commits() -> [Seen; 2] {
    [
        commit(COLLECTION, Patch, 8, &[FIRST_CHAT], false, Some(7)),
        commit(COLLECTION, Patch, 9, &[SECOND_CHAT], false, Some(8)),
    ]
}

/// A conflict is its collection's: the round's other collection is applied and
/// announced, what the first committed before it is announced after that, and
/// the first is left to be synced again from the mover's version, which the
/// primary is asked nothing about.
#[tokio::test]
async fn app_state_conflict_leaves_the_rounds_other_collections_applied() {
    let round = round(Mover::Unseen, Other::Applied).await;
    assert_eq!(
        round.ended.expect("a conflict ends no round"),
        BatchedSyncOutcome {
            synced: vec![OTHER],
            retryable: vec![COLLECTION],
            reached_server: true,
            ..Default::default()
        }
    );
    let [first, held] = commits();
    assert_eq!(
        round.host.take(),
        vec![
            first,
            held,
            commit(OTHER, Patch, 4, &[FOURTH_CHAT], false, Some(3)),
            archived(FOURTH_CHAT, false),
            archived(FIRST_CHAT, false),
        ],
        "nothing is announced of the refused patch"
    );
    assert_eq!(round.host.version(COLLECTION).await, Some(10));
    assert_eq!(round.host.version(OTHER).await, Some(4));
    assert_eq!(
        round.transport.sent_count(),
        1,
        "one IQ, and nothing asked of the primary"
    );

    // The first collection's next sync goes on from the mover's version.
    reachable(&round.client);
    let outcome = sync_collection(
        &round.client,
        &round.transport,
        1,
        vec![page(false, vec![round.next])],
    )
    .await
    .expect("the next sync applies v11");
    assert_eq!(outcome.synced, vec![COLLECTION]);
    assert_eq!(round.host.version(COLLECTION).await, Some(11));
}

/// A collection that fails after the conflict still fails the round, with its
/// own error, once the conflict's prefix has been announced.
#[tokio::test]
async fn app_state_failure_after_a_conflict_fails_the_round() {
    let round = round(Mover::Unseen, Other::Refused).await;
    let error = round.ended.expect_err("the host refused the other commit");
    assert!(error.downcast_ref::<Refused>().is_some(), "{error:#}");
    let [first, held] = commits();
    assert_eq!(
        round.host.take(),
        vec![
            first,
            held,
            commit(OTHER, Patch, 4, &[FOURTH_CHAT], false, Some(3)),
            archived(FIRST_CHAT, false),
        ],
    );
    assert_eq!(round.host.version(COLLECTION).await, Some(10));
    assert_eq!(round.host.version(OTHER).await, Some(3));
}

/// A conflict of a connection that retired while the store wrote sets nothing
/// aside: it ends the round as any error of one does, and its prefix, which
/// the store has kept, is announced.
#[tokio::test]
async fn app_state_conflict_of_a_retired_round_ends_it() {
    let (mut store, _dropped) = ProbeBackend::new();
    let (entered, written) = async_channel::unbounded();
    let (release, gate) = async_channel::unbounded();
    store.gate_method = "after:commit_patch_if";
    store.entered = Some(entered);
    store.gate = Some(gate);
    let host = Host::over(Arc::new(store)).await;
    let round = round_on(
        host,
        Mover::Unseen,
        Other::Applied,
        async |client: &Client| {
            written.recv().await.expect("the first patch is written");
            release.send(()).await.expect("the write is parked");
            written.recv().await.expect("the second is refused");
            client.advance_generation_for_test(1, Ordering::SeqCst);
            release.send(()).await.expect("the write is parked");
        },
    )
    .await;
    let error = round.ended.expect_err("a retired round fails");
    assert!(is_version_conflict(&error), "{error:#}");
    let [first, held] = commits();
    assert_eq!(
        round.host.take(),
        vec![first, held, archived(FIRST_CHAT, false)]
    );
    assert_eq!(round.host.version(COLLECTION).await, Some(10));
    assert_eq!(round.host.version(OTHER).await, Some(3));
    assert_eq!(
        round.transport.sent_count(),
        1,
        "one IQ, and nothing asked of the primary"
    );
}

/// A retired connection is not one collection's conflict: the round ends where
/// it stood, and the collections behind are left to the next connection.
#[tokio::test]
async fn app_state_retirement_in_a_round_ends_it() {
    let round = round(Mover::Reconnect, Other::Applied).await;
    let error = round.ended.expect_err("a retired round fails");
    assert!(
        matches!(error.downcast_ref(), Some(AppStateSyncError::Retired)),
        "{error:#}"
    );
    let [first, held] = commits();
    assert_eq!(
        round.host.take(),
        vec![first, held, archived(FIRST_CHAT, false)]
    );
    assert_eq!(round.host.version(COLLECTION).await, Some(10));
    assert_eq!(round.host.version(OTHER).await, Some(3));
}

/// The server's own conflict on the other collection, ahead of the first in the
/// response, is judged on the version the apply read for it: a store that fails
/// every read once the applies are done takes nothing from the round, and what
/// the first collection committed before its conflict is announced.
#[tokio::test]
async fn app_state_round_announces_without_reading_the_store_again() {
    let (mut store, _dropped) = ProbeBackend::new();
    let (entered, written) = async_channel::unbounded();
    let (release, gate) = async_channel::unbounded();
    let failing = Arc::new(AtomicBool::new(false));
    store.gate_method = "after:commit_patch_if";
    store.entered = Some(entered);
    store.gate = Some(gate);
    store.fail_before_method = Some(("get_version", failing.clone()));
    let host = Host::over(Arc::new(store)).await;
    let round = round_on(
        host,
        Mover::Unseen,
        Other::ServerConflict,
        async |_: &Client| {
            written.recv().await.expect("the first patch is written");
            release.send(()).await.expect("the write is parked");
            written.recv().await.expect("the second is refused");
            failing.store(true, Ordering::SeqCst);
            release.send(()).await.expect("the write is parked");
        },
    )
    .await;
    assert_eq!(
        round.ended.expect("the round reads nothing more"),
        BatchedSyncOutcome {
            synced: vec![OTHER],
            retryable: vec![COLLECTION],
            reached_server: true,
            ..Default::default()
        }
    );
    let [first, held] = commits();
    assert_eq!(
        round.host.take(),
        vec![first, held, archived(FIRST_CHAT, false)]
    );
    failing.store(false, Ordering::SeqCst);
    assert_eq!(round.host.version(COLLECTION).await, Some(10));
    assert_eq!(round.host.version(OTHER).await, Some(3));
}
