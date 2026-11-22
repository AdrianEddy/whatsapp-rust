//! WF14 beside upstream's tests of the bootstrap record: the clear before a
//! genesis patch runs on every sync of a collection at version 0 with an empty
//! ltHash, a legitimately empty one included, and it clears the MAC rows only,
//! leaving the version record as it is. So a quiet, empty collection's sync
//! writes no version, as a quiet collection's at any other version doesn't.

use super::*;
use std::sync::atomic::Ordering;

/// `a_marked_collection_at_the_head_writes_nothing` at version 0, over the
/// record `an_empty_bootstrap_records_an_empty_collection` leaves: the answer
/// reaches the genesis clear, which must not record the version again.
#[tokio::test]
async fn a_marked_empty_collection_at_the_head_writes_nothing() {
    let backend = Arc::new(MockBackend::default());
    let processor =
        AppStateProcessor::new(backend.clone(), Arc::new(crate::runtime_impl::TokioRuntime));
    let name = WAPatchName::RegularLow;
    backend
        .set_version(
            name.as_str(),
            HashState {
                version: 0,
                bootstrapped: true,
                ..Default::default()
            },
        )
        .await
        .expect("test backend should accept a version");
    let writes = backend.set_version_calls.load(Ordering::Relaxed);

    processor
        .process_patch_list(tip_answer(name), true)
        .await
        .expect("an empty answer processes");

    assert_eq!(
        backend.set_version_calls.load(Ordering::Relaxed),
        writes,
        "an empty collection already marked has nothing to record"
    );
    let stored = backend
        .get_version(name.as_str())
        .await
        .expect("version readable")
        .expect("the record is still there");
    assert_eq!(
        (stored.version, stored.hash, stored.bootstrapped),
        (0, [0u8; 128], true)
    );
}
