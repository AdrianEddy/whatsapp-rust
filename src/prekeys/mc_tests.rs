//! WF25: the ADV bootstrap's scope refuses work once its connection ends, or
//! another replaces it, as the typed `ClientError::NotConnected` a caller can
//! read without matching text.

use super::*;
use crate::client::ClientError;

fn not_connected(error: &anyhow::Error) -> bool {
    matches!(
        error.downcast_ref::<ClientError>(),
        Some(ClientError::NotConnected)
    )
}

#[test]
fn a_bootstrap_whose_connection_changed_is_not_connected() {
    let shutdown = wacore::runtime::ShutdownNotifier::new().subscribe();
    let generation = portable_atomic::AtomicU64::new(7);
    assert!(ensure_adv_bootstrap_scope(&generation, 7, &shutdown).is_ok());

    generation.store(8, Ordering::Release);
    let error = ensure_adv_bootstrap_scope(&generation, 7, &shutdown).unwrap_err();
    assert!(not_connected(&error), "{error:#}");
    assert_eq!(error.to_string(), "connection changed during ADV bootstrap");
}

#[test]
fn a_bootstrap_whose_connection_ended_is_not_connected() {
    let notifier = wacore::runtime::ShutdownNotifier::new();
    let shutdown = notifier.subscribe();
    let generation = portable_atomic::AtomicU64::new(7);
    notifier.notify();
    let error = ensure_adv_bootstrap_scope(&generation, 7, &shutdown).unwrap_err();
    assert!(not_connected(&error), "{error:#}");
}
