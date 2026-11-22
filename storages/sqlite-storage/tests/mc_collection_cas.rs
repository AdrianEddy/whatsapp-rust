//! WF14: the SQLite store compares a collection's stored record (version and
//! ltHash) and writes in one immediate transaction (the shared contract in
//! `wacore/tests/support/mc_collection_cas_contract.rs`, here with a second
//! device whose rows stay untouched): a statement that fails part-way rolls
//! the whole write back, comparison included, a kept record takes no statement
//! at all, and a record that doesn't decode is no record, as `get_version`
//! answers it.
#![cfg(not(target_family = "wasm"))]
#[path = "../../../wacore/tests/support/mc_collection_cas_contract.rs"]
mod contract;
#[path = "support/storage_fixture.rs"]
mod fixture;

use contract::{NAME, base, collection, mac, state};
use diesel::connection::SimpleConnection;
use wacore::store::error::StoreError;
use wacore::store::traits::{AppSyncStore, CollectionRecord, CollectionWrite};
use whatsapp_rust_sqlite_storage::{SqliteDatabase, SqliteStore};

/// A file database with device 1 provisioned, and a second device beside it.
async fn open(fixture: &fixture::Fixture) -> (SqliteDatabase, SqliteStore, SqliteStore) {
    let db = SqliteDatabase::open(&fixture.url(), Default::default())
        .await
        .unwrap();
    let store = db.provision_device(1).await.unwrap();
    let other = db.create_device().await.unwrap();
    (db, store, other)
}

async fn sql(db: &SqliteDatabase, statement: String) {
    db.shared()
        .run(move |conn| {
            conn.batch_execute(&statement)
                .map_err(|e| StoreError::Database(Box::new(e)))
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn sqlite_conditional_commit_writes_only_on_its_base() {
    let fixture = fixture::Fixture::new();
    let (_db, store, other) = open(&fixture).await;
    contract::assert_conditional_commit_contract(&store).await;
    assert_eq!(collection(&other, NAME).await, (None, [None; 4]));
}

#[tokio::test]
async fn sqlite_replace_collection_writes_only_on_its_base() {
    let fixture = fixture::Fixture::new();
    let (_db, store, other) = open(&fixture).await;
    contract::assert_replace_collection_contract(&store).await;
    assert_eq!(collection(&other, NAME).await, (None, [None; 4]));
}

#[tokio::test]
async fn sqlite_kept_record_replaces_only_the_rows() {
    let fixture = fixture::Fixture::new();
    let (_db, store, other) = open(&fixture).await;
    contract::assert_kept_record_contract(&store).await;
    assert_eq!(collection(&other, NAME).await, (None, [None; 4]));
}

#[tokio::test]
async fn sqlite_rebuild_to_the_same_version_conflicts() {
    let fixture = fixture::Fixture::new();
    let (_db, store, other) = open(&fixture).await;
    contract::assert_rebuild_to_the_same_version_conflicts(&store).await;
    assert_eq!(collection(&other, NAME).await, (None, [None; 4]));
}

#[tokio::test]
async fn sqlite_two_writes_on_one_base_apply_once() {
    let fixture = fixture::Fixture::new();
    let (_db, store, _other) = open(&fixture).await;
    contract::assert_one_write_per_base(&store).await;
}

#[derive(Clone, Copy, Debug)]
enum Write {
    /// `commit_patch_if`: the version, MAC 1 removed, MAC 2 added.
    Patch,
    /// `replace_collection` setting a record: every row cleared, MAC 2 put,
    /// the version written.
    Replace,
    /// `replace_collection` keeping the record: every row cleared, MAC 2 put.
    Keep,
    /// `replace_collection` removing the record: every row cleared, the record
    /// deleted.
    StandDown,
}

impl Write {
    /// The write, on the base of `state(1)`.
    async fn run(self, store: &SqliteStore) -> wacore::store::error::Result<CollectionWrite> {
        let built_on = base(&state(1));
        match self {
            Write::Patch => {
                store
                    .commit_patch_if(
                        NAME,
                        built_on,
                        state(2),
                        vec![vec![1; 32]],
                        vec![mac(2, 22)],
                    )
                    .await
            }
            Write::Replace => {
                store
                    .replace_collection(
                        NAME,
                        built_on,
                        CollectionRecord::Set(state(2)),
                        vec![mac(2, 22)],
                    )
                    .await
            }
            Write::Keep => {
                store
                    .replace_collection(NAME, built_on, CollectionRecord::Keep, vec![mac(2, 22)])
                    .await
            }
            Write::StandDown => {
                store
                    .replace_collection(NAME, built_on, CollectionRecord::Remove, vec![])
                    .await
            }
        }
    }
}

/// Each statement a conditional write makes, failed by a trigger: the write
/// fails, and the collection on both devices is as it was.
#[tokio::test]
async fn sqlite_conditional_writes_are_one_transaction() {
    for (statement, write) in [
        ("INSERT ON app_state_versions", Write::Patch),
        ("DELETE ON app_state_mutation_macs", Write::Patch),
        ("INSERT ON app_state_mutation_macs", Write::Patch),
        ("DELETE ON app_state_mutation_macs", Write::Replace),
        ("INSERT ON app_state_mutation_macs", Write::Replace),
        ("INSERT ON app_state_versions", Write::Replace),
        ("DELETE ON app_state_mutation_macs", Write::Keep),
        ("INSERT ON app_state_mutation_macs", Write::Keep),
        ("DELETE ON app_state_mutation_macs", Write::StandDown),
        ("DELETE ON app_state_versions", Write::StandDown),
    ] {
        let fixture = fixture::Fixture::new();
        let (db, store, other) = open(&fixture).await;
        for scope in [&store, &other] {
            scope
                .commit_patch(NAME, state(1), &[], &[mac(1, 11)])
                .await
                .unwrap();
        }
        let before = (Some((1, 1)), [Some(11), None, None, None]);
        sql(
            &db,
            format!(
                "CREATE TRIGGER fail_write BEFORE {statement} BEGIN \
                 SELECT RAISE(ABORT, 'synthetic write failure'); END;"
            ),
        )
        .await;
        let error = write
            .run(&store)
            .await
            .expect_err("the trigger fails the write");
        let source = std::error::Error::source(&error).expect("a database error keeps its cause");
        assert!(
            source.to_string().contains("synthetic write failure"),
            "{statement}, {write:?}: {source}"
        );
        for scope in [&store, &other] {
            assert_eq!(
                collection(scope, NAME).await,
                before,
                "{statement}, {write:?}: rolled back whole"
            );
        }
        sql(&db, "DROP TRIGGER fail_write;".to_owned()).await;
        assert_eq!(
            write.run(&store).await.unwrap(),
            CollectionWrite::Applied,
            "{statement}, {write:?}"
        );
        let after = match write {
            Write::Patch | Write::Replace => (Some((2, 2)), [None, Some(22), None, None]),
            Write::Keep => (Some((1, 1)), [None, Some(22), None, None]),
            Write::StandDown => (None, [None; 4]),
        };
        assert_eq!(
            collection(&store, NAME).await,
            after,
            "{statement}, {write:?}"
        );
        assert_eq!(
            collection(&other, NAME).await,
            before,
            "{statement}, {write:?}"
        );
    }
}

/// A kept record takes no statement on the version table, so it cannot roll
/// back what another writer set on the same base: with every write to that
/// table failed by a trigger, the rows are still replaced, and the record is
/// the one the comparison read.
#[tokio::test]
async fn sqlite_a_kept_record_takes_no_version_statement() {
    let fixture = fixture::Fixture::new();
    let (db, store, _other) = open(&fixture).await;
    store
        .commit_patch(NAME, state(1), &[], &[mac(1, 11)])
        .await
        .unwrap();
    for statement in ["INSERT", "UPDATE", "DELETE"] {
        sql(
            &db,
            format!(
                "CREATE TRIGGER fail_{statement} BEFORE {statement} ON app_state_versions BEGIN \
                 SELECT RAISE(ABORT, 'a version statement'); END;"
            ),
        )
        .await;
    }
    assert_eq!(
        Write::Keep.run(&store).await.unwrap(),
        CollectionWrite::Applied
    );
    assert_eq!(
        collection(&store, NAME).await,
        (Some((1, 1)), [None, Some(22), None, None])
    );
    contract::assert_record(&store, NAME, &state(1), "the record as it was").await;
}

/// A record that doesn't decode reads as no record, so a write on the base
/// `get_version` gave (`None`) applies over it, and one on a record doesn't.
#[tokio::test]
async fn sqlite_an_undecodable_record_is_no_record() {
    let fixture = fixture::Fixture::new();
    let (db, store, _other) = open(&fixture).await;
    sql(
        &db,
        format!(
            "INSERT INTO app_state_versions (name, state_data, device_id) \
             VALUES ('{NAME}', X'FF', 1);"
        ),
    )
    .await;
    assert!(store.get_version(NAME).await.unwrap().is_none());
    assert_eq!(
        store
            .commit_patch_if(NAME, base(&state(0)), state(1), vec![], vec![])
            .await
            .unwrap(),
        CollectionWrite::Conflict { stored: None }
    );
    assert_eq!(
        store
            .replace_collection(
                NAME,
                None,
                CollectionRecord::Set(state(1)),
                vec![mac(1, 11)]
            )
            .await
            .unwrap(),
        CollectionWrite::Applied
    );
    assert_eq!(
        collection(&store, NAME).await,
        (Some((1, 1)), [Some(11), None, None, None])
    );
}
