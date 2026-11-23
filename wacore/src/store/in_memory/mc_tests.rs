//! WF20: each collection's MAC rows are a map of their own. Replacing or
//! clearing one takes its rows out whole and leaves every other collection's
//! where they were, and a collection without rows holds nothing.

use super::*;

fn mac(index: u8, value: u8) -> AppStateMutationMAC {
    AppStateMutationMAC {
        index_mac: vec![index; 32],
        value_mac: vec![value; 32],
    }
}

/// The collections that hold a map, and how many rows each has.
async fn held(backend: &InMemoryBackend) -> Vec<(String, usize)> {
    let state = backend.state.lock().await;
    let mut held: Vec<_> = state
        .mutation_macs
        .iter()
        .map(|(name, macs)| (name.to_string(), macs.len()))
        .collect();
    held.sort();
    held
}

fn rows(of: &[(&str, usize)]) -> Vec<(String, usize)> {
    of.iter()
        .map(|(name, rows)| (name.to_string(), *rows))
        .collect()
}

#[tokio::test]
async fn a_collection_without_rows_holds_no_map() {
    let backend = InMemoryBackend::new();
    let state = HashState::default();

    backend.put_mutation_macs("regular", 1, &[]).await.unwrap();
    let applied = backend
        .replace_collection("regular", None, CollectionRecord::Keep, Vec::new())
        .await
        .unwrap();
    assert_eq!(applied, CollectionWrite::Applied);
    assert_eq!(held(&backend).await, rows(&[]), "nothing was put");

    backend
        .put_mutation_macs("regular", 1, &[mac(1, 1), mac(2, 2)])
        .await
        .unwrap();
    backend
        .delete_mutation_macs("regular", &[vec![1; 32], vec![9; 32]])
        .await
        .unwrap();
    assert_eq!(held(&backend).await, rows(&[("regular", 1)]));
    backend
        .delete_mutation_macs("regular", &[vec![2; 32]])
        .await
        .unwrap();
    assert_eq!(held(&backend).await, rows(&[]), "its last row is gone");

    // A patch that removes every row it found, and one that adds the next.
    backend
        .commit_patch("regular", state.clone(), &[], &[mac(1, 1)])
        .await
        .unwrap();
    backend
        .commit_patch("regular", state.clone(), &[vec![1; 32]], &[])
        .await
        .unwrap();
    assert_eq!(held(&backend).await, rows(&[]));
    backend
        .commit_patch("regular", state, &[vec![1; 32]], &[mac(1, 3)])
        .await
        .unwrap();
    assert_eq!(held(&backend).await, rows(&[("regular", 1)]));

    backend.clear_mutation_macs("regular").await.unwrap();
    assert_eq!(held(&backend).await, rows(&[]));
    backend.clear_mutation_macs("regular").await.unwrap();
    assert_eq!(
        backend.resource_report().await.pages,
        Some(1),
        "the version record alone"
    );
}

#[tokio::test]
async fn replacing_a_collection_leaves_the_others_where_they_were() {
    let backend = InMemoryBackend::new();
    for (name, value) in [("regular", 1), ("regular_low", 2), ("critical_block", 3)] {
        let macs: Vec<_> = (0..4).map(|index| mac(index, value)).collect();
        backend.put_mutation_macs(name, 1, &macs).await.unwrap();
    }
    async fn buffers(backend: &InMemoryBackend, name: &str) -> Vec<(*const u8, *const u8)> {
        let state = backend.state.lock().await;
        let mut buffers: Vec<_> = state.mutation_macs[name]
            .iter()
            .map(|(index_mac, value_mac)| (index_mac.as_ptr(), value_mac.as_ptr()))
            .collect();
        buffers.sort();
        buffers
    }
    let low = buffers(&backend, "regular_low").await;
    let critical = buffers(&backend, "critical_block").await;

    // A replacement: exactly its rows, whatever the collection held.
    let replacement = vec![mac(0, 9), mac(7, 9)];
    let applied = backend
        .replace_collection(
            "regular",
            None,
            CollectionRecord::Set(HashState::default()),
            replacement,
        )
        .await
        .unwrap();
    assert_eq!(applied, CollectionWrite::Applied);
    assert_eq!(
        held(&backend).await,
        rows(&[("critical_block", 4), ("regular", 2), ("regular_low", 4)])
    );
    assert_eq!(
        backend.get_mutation_mac("regular", &[0; 32]).await.unwrap(),
        Some(vec![9; 32])
    );
    assert_eq!(
        backend.get_mutation_mac("regular", &[1; 32]).await.unwrap(),
        None
    );

    backend.clear_mutation_macs("critical_block").await.unwrap();
    assert_eq!(
        held(&backend).await,
        rows(&[("regular", 2), ("regular_low", 4)])
    );
    assert_eq!(buffers(&backend, "regular_low").await, low);
    assert_ne!(low, critical);
}

/// The rows a conditional write takes are stored as they came: no copy of a
/// snapshot's MAC set is made under the lock.
#[tokio::test]
async fn a_replacements_rows_are_moved_in() {
    let backend = InMemoryBackend::new();
    let row = mac(1, 2);
    let expected = (row.index_mac.as_ptr(), row.value_mac.as_ptr());
    let applied = backend
        .replace_collection(
            "regular",
            None,
            CollectionRecord::Set(HashState::default()),
            vec![row],
        )
        .await
        .unwrap();
    assert_eq!(applied, CollectionWrite::Applied);
    let state = backend.state.lock().await;
    let (index_mac, value_mac) = state.mutation_macs["regular"]
        .iter()
        .next()
        .expect("the row is stored");
    assert_eq!((index_mac.as_ptr(), value_mac.as_ptr()), expected);
}
