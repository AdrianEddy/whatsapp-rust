//! `PortableCache::try_get_with`: the fallible single-flight init that WF5's
//! undecryptable report runs its hook call in.
//!
//! The futures are polled by hand (`futures::poll!`), so which caller holds a
//! key's init lock and which waits for it is fixed by the test, not by a
//! scheduler.

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

/// An `Err` goes to the caller whose init failed and inserts nothing; a caller
/// waiting behind it then runs its own init, whose `Ok` is inserted. The key's
/// init lock is reclaimed once both are done.
#[tokio::test]
async fn try_get_with_err_inserts_nothing_and_next_waiter_runs_its_own_init() {
    let cache: PortableCache<u32, u32> = PortableCache::builder().max_capacity(100).build();
    let (release, released) = async_channel::bounded::<()>(1);
    let waiter_inits = AtomicUsize::new(0);

    let mut first = std::pin::pin!(cache.try_get_with(1, async {
        released
            .recv()
            .await
            .expect("the test releases the first init");
        Err::<u32, &str>("refused")
    }));
    assert!(
        futures::poll!(&mut first).is_pending(),
        "the first init holds the key"
    );
    let mut waiter = std::pin::pin!(cache.try_get_with(1, async {
        waiter_inits.fetch_add(1, Ordering::Relaxed);
        Ok::<u32, &str>(20)
    }));
    assert!(
        futures::poll!(&mut waiter).is_pending(),
        "the second caller waits for the first init"
    );
    assert_eq!(waiter_inits.load(Ordering::Relaxed), 0);

    release.send(()).await.expect("the first init waits");
    assert_eq!(first.await, Err("refused"));
    assert_eq!(cache.get(&1).await, None, "an `Err` inserts nothing");

    assert_eq!(waiter.await, Ok(20), "the waiter ran its own init");
    assert_eq!(waiter_inits.load(Ordering::Relaxed), 1);
    assert_eq!(cache.get(&1).await, Some(20));
    assert!(
        cache.init_locks().map.lock().await.is_empty(),
        "the key's init lock is reclaimed"
    );
}

/// A caller waiting behind an init that succeeds gets the inserted value
/// without running its own init, as `get_with`'s waiters do, and a later
/// caller finds it without an init either.
#[tokio::test]
async fn try_get_with_ok_is_shared_with_waiters() {
    let cache: PortableCache<u32, u32> = PortableCache::builder().max_capacity(100).build();
    let (release, released) = async_channel::bounded::<()>(1);
    let waiter_inits = AtomicUsize::new(0);

    let mut first = std::pin::pin!(cache.try_get_with(1, async {
        released
            .recv()
            .await
            .expect("the test releases the first init");
        Ok::<u32, &str>(10)
    }));
    assert!(
        futures::poll!(&mut first).is_pending(),
        "the first init holds the key"
    );
    let mut waiter = std::pin::pin!(cache.try_get_with(1, async {
        waiter_inits.fetch_add(1, Ordering::Relaxed);
        Err::<u32, &str>("the waiter's init must not run")
    }));
    assert!(
        futures::poll!(&mut waiter).is_pending(),
        "the second caller waits for the first init"
    );

    release.send(()).await.expect("the first init waits");
    assert_eq!(first.await, Ok(10));
    assert_eq!(waiter.await, Ok(10), "the waiter gets the inserted value");
    assert_eq!(
        waiter_inits.load(Ordering::Relaxed),
        0,
        "without running its own init"
    );
    assert_eq!(
        cache
            .try_get_with(1, async { Err::<u32, &str>("a hit runs no init") })
            .await,
        Ok(10)
    );
    assert!(
        cache.init_locks().map.lock().await.is_empty(),
        "the key's init lock is reclaimed"
    );
}
