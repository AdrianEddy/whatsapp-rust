//! WF14: `InMemoryBackend` compares a collection's stored record and writes
//! under its one lock (the shared contract in
//! `support/mc_collection_cas_contract.rs`); and the trait's default bodies,
//! which compare and then write in separate calls, answer the same contract
//! call by call (they are unfenced, so not the concurrent case).

#[path = "support/mc_collection_cas_contract.rs"]
mod contract;

use async_trait::async_trait;
use std::collections::HashMap;
use wacore::appstate::{hash::HashState, processor::AppStateMutationMAC};
use wacore::store::InMemoryBackend;
use wacore::store::error::Result;
use wacore::store::traits::{AppStateSyncKey, AppSyncStore};

#[tokio::test]
async fn memory_conditional_commit_writes_only_on_its_base() {
    contract::assert_conditional_commit_contract(&InMemoryBackend::new()).await;
}

#[tokio::test]
async fn memory_replace_collection_writes_only_on_its_base() {
    contract::assert_replace_collection_contract(&InMemoryBackend::new()).await;
}

#[tokio::test]
async fn memory_kept_record_replaces_only_the_rows() {
    contract::assert_kept_record_contract(&InMemoryBackend::new()).await;
}

#[tokio::test]
async fn memory_rebuild_to_the_same_version_conflicts() {
    contract::assert_rebuild_to_the_same_version_conflicts(&InMemoryBackend::new()).await;
}

#[tokio::test]
async fn memory_two_writes_on_one_base_apply_once() {
    contract::assert_one_write_per_base(&InMemoryBackend::new()).await;
}

/// `InMemoryBackend`'s required methods alone: `commit_patch_if` and
/// `replace_collection` are the trait's defaults.
struct Defaults(InMemoryBackend);

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl AppSyncStore for Defaults {
    async fn get_sync_key(&self, key_id: &[u8]) -> Result<Option<AppStateSyncKey>> {
        self.0.get_sync_key(key_id).await
    }

    async fn set_sync_key(&self, key_id: &[u8], key: AppStateSyncKey) -> Result<()> {
        self.0.set_sync_key(key_id, key).await
    }

    async fn get_version(&self, name: &str) -> Result<Option<HashState>> {
        self.0.get_version(name).await
    }

    async fn delete_version(&self, name: &str) -> Result<()> {
        self.0.delete_version(name).await
    }

    async fn set_version(&self, name: &str, state: HashState) -> Result<()> {
        self.0.set_version(name, state).await
    }

    async fn put_mutation_macs(
        &self,
        name: &str,
        version: u64,
        mutations: &[AppStateMutationMAC],
    ) -> Result<()> {
        self.0.put_mutation_macs(name, version, mutations).await
    }

    async fn get_mutation_mac(&self, name: &str, index_mac: &[u8]) -> Result<Option<Vec<u8>>> {
        self.0.get_mutation_mac(name, index_mac).await
    }

    async fn get_mutation_macs(
        &self,
        name: &str,
        index_macs: &[[u8; 32]],
    ) -> Result<HashMap<[u8; 32], Vec<u8>>> {
        self.0.get_mutation_macs(name, index_macs).await
    }

    async fn delete_mutation_macs(&self, name: &str, index_macs: &[Vec<u8>]) -> Result<()> {
        self.0.delete_mutation_macs(name, index_macs).await
    }

    async fn commit_patch(
        &self,
        name: &str,
        state: HashState,
        removed_index_macs: &[Vec<u8>],
        added: &[AppStateMutationMAC],
    ) -> Result<()> {
        self.0
            .commit_patch(name, state, removed_index_macs, added)
            .await
    }

    async fn clear_mutation_macs(&self, name: &str) -> Result<()> {
        self.0.clear_mutation_macs(name).await
    }

    async fn get_latest_sync_key_id(&self) -> Result<Option<Vec<u8>>> {
        self.0.get_latest_sync_key_id().await
    }
}

#[tokio::test]
async fn default_conditional_writes_answer_the_contract() {
    contract::assert_conditional_commit_contract(&Defaults(InMemoryBackend::new())).await;
    contract::assert_replace_collection_contract(&Defaults(InMemoryBackend::new())).await;
    contract::assert_kept_record_contract(&Defaults(InMemoryBackend::new())).await;
    contract::assert_rebuild_to_the_same_version_conflicts(&Defaults(InMemoryBackend::new())).await;
}
