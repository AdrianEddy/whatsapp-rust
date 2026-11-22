//! WF14: a collection's conditional writes as every store must answer them.
//! `AppSyncStore::commit_patch_if` and `replace_collection` write only while
//! the collection is stored as the base they are given (its version and
//! ltHash; `None`: no record), and otherwise answer
//! `CollectionWrite::Conflict` with the base found and write nothing;
//! `CollectionRecord::Keep` replaces the rows alone, the record left byte for
//! byte; other collections are never touched. Shared by the bundled stores'
//! tests (`wacore/tests/mc_collection_cas.rs` and the SQLite store's
//! `tests/mc_collection_cas.rs`), as `appstate_commit_contract.rs` is.

#![allow(dead_code, reason = "each test binary uses a different part")]

use wacore::appstate::{hash::HashState, processor::AppStateMutationMAC};
use wacore::store::traits::{AppSyncStore, CollectionBase, CollectionRecord, CollectionWrite};

use CollectionRecord::{Keep, Remove, Set};
use CollectionWrite::{Applied, Conflict};

pub const NAME: &str = "regular";
pub const OTHER: &str = "regular_low";

/// A version `version` whose ltHash's bytes all read `version`, so a reader
/// tells the states apart.
pub fn state(version: u64) -> HashState {
    HashState {
        version,
        hash: [version as u8; 128],
        bootstrapped: true,
        ..Default::default()
    }
}

/// [`state`]'s version with another ltHash (its bytes all read `!version`):
/// what a rebuild leaves at the version a diverged copy held.
pub fn rebuilt(version: u64) -> HashState {
    HashState {
        hash: [!(version as u8); 128],
        ..state(version)
    }
}

/// The base of a write built on `state`.
pub fn base(state: &HashState) -> Option<CollectionBase> {
    Some(CollectionBase::from(state))
}

/// A MAC row of index `index` (32 bytes of it) whose value MAC's bytes all
/// read `value`.
pub fn mac(index: u8, value: u8) -> AppStateMutationMAC {
    AppStateMutationMAC {
        index_mac: vec![index; 32],
        value_mac: vec![value; 32],
    }
}

/// The collection as a reader sees it: its version and the first byte of its
/// ltHash, and the first byte of the value MAC of indexes 1 to 4.
pub async fn collection(
    store: &impl AppSyncStore,
    name: &str,
) -> (Option<(u64, u8)>, [Option<u8>; 4]) {
    let version = store
        .get_version(name)
        .await
        .unwrap()
        .map(|state| (state.version, state.hash[0]));
    let mut macs = [None; 4];
    for (slot, index) in macs.iter_mut().zip(1u8..) {
        *slot = store
            .get_mutation_mac(name, &[index; 32])
            .await
            .unwrap()
            .map(|value| value[0]);
    }
    (version, macs)
}

/// Asserts the stored record is `expected`, every field of it.
pub async fn assert_record(
    store: &impl AppSyncStore,
    name: &str,
    expected: &HashState,
    what: &str,
) {
    let stored = store.get_version(name).await.unwrap().expect(what);
    assert_eq!(
        (
            stored.version,
            stored.hash,
            &stored.index_value_map,
            stored.mac_mismatch_fatal,
            stored.bootstrapped
        ),
        (
            expected.version,
            expected.hash,
            &expected.index_value_map,
            expected.mac_mismatch_fatal,
            expected.bootstrapped
        ),
        "{what}"
    );
}

/// `commit_patch_if` commits only on its base, as `commit_patch` would; a
/// conflict reports the base found and writes nothing.
pub async fn assert_conditional_commit_contract(store: &impl AppSyncStore) {
    assert_eq!(
        store
            .commit_patch_if(NAME, base(&state(0)), state(1), vec![], vec![mac(1, 11)])
            .await
            .unwrap(),
        Conflict { stored: None },
        "a base of a record over no record"
    );
    assert_eq!(collection(store, NAME).await, (None, [None; 4]));
    assert_eq!(
        store
            .commit_patch_if(NAME, None, state(1), vec![], vec![mac(1, 11), mac(2, 12)])
            .await
            .unwrap(),
        Applied,
        "a base of no record over no record"
    );
    store
        .commit_patch(OTHER, state(7), &[], &[mac(1, 71)])
        .await
        .unwrap();

    for (what, built_on) in [
        ("v0", base(&state(0))),
        ("no record", None),
        ("v2", base(&state(2))),
        ("v1 with another ltHash", base(&rebuilt(1))),
    ] {
        assert_eq!(
            store
                .commit_patch_if(
                    NAME,
                    built_on,
                    state(2),
                    vec![vec![1; 32]],
                    vec![mac(3, 23)]
                )
                .await
                .unwrap(),
            Conflict {
                stored: base(&state(1))
            },
            "base {what}"
        );
    }
    assert_eq!(
        collection(store, NAME).await,
        (Some((1, 1)), [Some(11), Some(12), None, None]),
        "a conflict writes nothing"
    );

    // The version, the removals, then the additions: index 1 both removed and
    // added ends added.
    assert_eq!(
        store
            .commit_patch_if(
                NAME,
                base(&state(1)),
                state(2),
                vec![vec![1; 32], vec![2; 32]],
                vec![mac(3, 23), mac(1, 21)],
            )
            .await
            .unwrap(),
        Applied
    );
    assert_eq!(
        collection(store, NAME).await,
        (Some((2, 2)), [Some(21), None, Some(23), None])
    );

    // A change of the record that leaves the rows as they are, as the
    // processor records a finished bootstrap. The flags are not part of the
    // base, so the unmarked record is still the base of `state(2)`.
    let unmarked = HashState {
        bootstrapped: false,
        ..state(2)
    };
    assert_eq!(
        store
            .commit_patch_if(NAME, base(&state(2)), unmarked.clone(), vec![], vec![])
            .await
            .unwrap(),
        Applied
    );
    assert_record(store, NAME, &unmarked, "the unmarked record").await;
    assert_eq!(
        collection(store, NAME).await,
        (Some((2, 2)), [Some(21), None, Some(23), None])
    );

    assert_eq!(
        collection(store, OTHER).await,
        (Some((7, 7)), [Some(71), None, None, None]),
        "another collection is untouched"
    );
}

/// `replace_collection` replaces the record and every MAC row only on its
/// base; a conflict reports the base found and writes nothing.
pub async fn assert_replace_collection_contract(store: &impl AppSyncStore) {
    store
        .commit_patch(NAME, state(3), &[], &[mac(1, 31), mac(2, 32)])
        .await
        .unwrap();
    store
        .commit_patch(OTHER, state(7), &[], &[mac(1, 71)])
        .await
        .unwrap();

    for (what, built_on) in [
        ("no record", None),
        ("v2", base(&state(2))),
        ("v4", base(&state(4))),
        ("v3 with another ltHash", base(&rebuilt(3))),
    ] {
        for (mode, record) in [("set", Set(state(5))), ("keep", Keep), ("remove", Remove)] {
            assert_eq!(
                store
                    .replace_collection(NAME, built_on, record, vec![mac(3, 53)])
                    .await
                    .unwrap(),
                Conflict {
                    stored: base(&state(3))
                },
                "{mode} on base {what}"
            );
        }
    }
    assert_eq!(
        collection(store, NAME).await,
        (Some((3, 3)), [Some(31), Some(32), None, None]),
        "a conflict writes nothing"
    );

    // The whole collection: the rows it doesn't list go, and an index listed
    // twice keeps its last value.
    assert_eq!(
        store
            .replace_collection(
                NAME,
                base(&state(3)),
                Set(state(5)),
                vec![mac(3, 50), mac(4, 54), mac(3, 53)],
            )
            .await
            .unwrap(),
        Applied
    );
    assert_eq!(
        collection(store, NAME).await,
        (Some((5, 5)), [None, None, Some(53), Some(54)])
    );

    // No record and no rows: a rebuild's stand-down. Then a base of a record
    // conflicts with no record, and a base of no record replaces it.
    store
        .put_mutation_macs(NAME, 5, &[mac(1, 51)])
        .await
        .unwrap();
    assert_eq!(
        store
            .replace_collection(NAME, base(&state(5)), Remove, vec![])
            .await
            .unwrap(),
        Applied
    );
    assert_eq!(collection(store, NAME).await, (None, [None; 4]));
    assert_eq!(
        store
            .replace_collection(NAME, base(&state(5)), Set(state(6)), vec![])
            .await
            .unwrap(),
        Conflict { stored: None }
    );
    assert_eq!(
        store
            .replace_collection(NAME, None, Set(state(6)), vec![mac(2, 62)])
            .await
            .unwrap(),
        Applied
    );
    assert_eq!(
        collection(store, NAME).await,
        (Some((6, 6)), [None, Some(62), None, None])
    );

    assert_eq!(
        collection(store, OTHER).await,
        (Some((7, 7)), [Some(71), None, None, None]),
        "another collection is untouched"
    );
}

/// `CollectionRecord::Keep` replaces the MAC rows alone, on its base: the
/// record stays byte for byte, its flags and map included, and on another base
/// nothing is written. Over no record it clears the rows a reset left and
/// records nothing: the genesis patch's clear.
pub async fn assert_kept_record_contract(store: &impl AppSyncStore) {
    let record = HashState {
        index_value_map: [("index".to_owned(), vec![4, 2])].into(),
        mac_mismatch_fatal: true,
        bootstrapped: false,
        ..state(4)
    };
    store
        .commit_patch(NAME, record.clone(), &[], &[mac(1, 41), mac(2, 42)])
        .await
        .unwrap();
    store
        .commit_patch(OTHER, state(7), &[], &[mac(1, 71)])
        .await
        .unwrap();

    for (what, built_on) in [
        ("no record", None),
        ("v3", base(&state(3))),
        ("v4 with another ltHash", base(&rebuilt(4))),
    ] {
        assert_eq!(
            store
                .replace_collection(NAME, built_on, Keep, vec![mac(3, 43)])
                .await
                .unwrap(),
            Conflict {
                stored: base(&record)
            },
            "base {what}"
        );
    }
    assert_eq!(
        collection(store, NAME).await,
        (Some((4, 4)), [Some(41), Some(42), None, None]),
        "a conflict writes nothing"
    );

    assert_eq!(
        store
            .replace_collection(NAME, base(&record), Keep, vec![mac(3, 43), mac(4, 44)])
            .await
            .unwrap(),
        Applied
    );
    assert_eq!(
        collection(store, NAME).await,
        (Some((4, 4)), [None, None, Some(43), Some(44)])
    );
    assert_record(store, NAME, &record, "the record as it was").await;

    // No rows: the clear before a genesis patch, over a record and over none.
    assert_eq!(
        store
            .replace_collection(NAME, base(&record), Keep, vec![])
            .await
            .unwrap(),
        Applied
    );
    assert_eq!(collection(store, NAME).await, (Some((4, 4)), [None; 4]));
    assert_record(store, NAME, &record, "the record as it was").await;
    store.delete_version(NAME).await.unwrap();
    store
        .put_mutation_macs(NAME, 0, &[mac(1, 1)])
        .await
        .unwrap();
    assert_eq!(
        store
            .replace_collection(NAME, base(&record), Keep, vec![])
            .await
            .unwrap(),
        Conflict { stored: None }
    );
    assert_eq!(
        collection(store, NAME).await,
        (None, [Some(1), None, None, None])
    );
    assert_eq!(
        store
            .replace_collection(NAME, None, Keep, vec![])
            .await
            .unwrap(),
        Applied
    );
    assert_eq!(
        collection(store, NAME).await,
        (None, [None; 4]),
        "still no record"
    );

    assert_eq!(
        collection(store, OTHER).await,
        (Some((7, 7)), [Some(71), None, None, None]),
        "another collection is untouched"
    );
}

/// A collection stood down and rebuilt to the version a write was built on,
/// with another ltHash (`12(H) -> none -> 12(H')`, a diverged copy repaired):
/// both writes built on the record before the rebuild conflict, report the
/// rebuilt base and write nothing, so the repair stays; built on the rebuilt
/// record, the patch applies.
pub async fn assert_rebuild_to_the_same_version_conflicts(store: &impl AppSyncStore) {
    let diverged = HashState {
        mac_mismatch_fatal: true,
        ..state(12)
    };
    store
        .commit_patch(NAME, diverged.clone(), &[], &[mac(1, 121)])
        .await
        .unwrap();
    let built_on = base(&diverged);
    assert_eq!(
        store
            .replace_collection(NAME, built_on, Remove, vec![])
            .await
            .unwrap(),
        Applied,
        "the stand-down"
    );
    let repaired = rebuilt(12);
    assert_eq!(
        store
            .replace_collection(NAME, None, Set(repaired.clone()), vec![mac(2, 122)])
            .await
            .unwrap(),
        Applied,
        "the rebuild"
    );
    let after = (Some((12, repaired.hash[0])), [None, Some(122), None, None]);
    assert_eq!(collection(store, NAME).await, after);

    let late_patch = HashState {
        mac_mismatch_fatal: true,
        ..state(13)
    };
    assert_eq!(
        store
            .commit_patch_if(
                NAME,
                built_on,
                late_patch.clone(),
                vec![vec![2; 32]],
                vec![mac(3, 133)]
            )
            .await
            .unwrap(),
        Conflict {
            stored: base(&repaired)
        },
        "a patch built before the rebuild"
    );
    assert_eq!(
        store
            .commit_patch_if(NAME, built_on, diverged.clone(), vec![], vec![])
            .await
            .unwrap(),
        Conflict {
            stored: base(&repaired)
        },
        "a record change built before the rebuild"
    );
    for (mode, record) in [("set", Set(state(13))), ("keep", Keep), ("remove", Remove)] {
        assert_eq!(
            store
                .replace_collection(NAME, built_on, record, vec![mac(4, 134)])
                .await
                .unwrap(),
            Conflict {
                stored: base(&repaired)
            },
            "{mode} built before the rebuild"
        );
    }
    assert_eq!(
        collection(store, NAME).await,
        after,
        "the rebuild stays whole"
    );
    assert_record(store, NAME, &repaired, "the repair stays").await;

    assert_eq!(
        store
            .commit_patch_if(
                NAME,
                base(&repaired),
                state(13),
                vec![vec![2; 32]],
                vec![mac(3, 133)]
            )
            .await
            .unwrap(),
        Applied,
        "a patch built on the rebuilt record"
    );
    assert_eq!(
        collection(store, NAME).await,
        (Some((13, 13)), [None, None, Some(133), None])
    );
}

/// Two writes built on the same record: whichever the store takes first
/// applies, and the other finds the record it wrote. Neither is lost half way,
/// so the collection is exactly the winner's.
pub async fn assert_one_write_per_base(store: &impl AppSyncStore) {
    store
        .commit_patch(NAME, state(1), &[], &[mac(1, 11)])
        .await
        .unwrap();
    let (patched, replaced) = tokio::join!(
        store.commit_patch_if(
            NAME,
            base(&state(1)),
            state(2),
            vec![vec![1; 32]],
            vec![mac(2, 22)]
        ),
        store.replace_collection(NAME, base(&state(1)), Set(state(3)), vec![mac(3, 33)]),
    );
    match (patched.unwrap(), replaced.unwrap()) {
        (Applied, Conflict { stored }) if stored == base(&state(2)) => assert_eq!(
            collection(store, NAME).await,
            (Some((2, 2)), [None, Some(22), None, None])
        ),
        (Conflict { stored }, Applied) if stored == base(&state(3)) => assert_eq!(
            collection(store, NAME).await,
            (Some((3, 3)), [None, None, Some(33), None])
        ),
        outcomes => panic!("exactly one write applies on a base: {outcomes:?}"),
    }
}
