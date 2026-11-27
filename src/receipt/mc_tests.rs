//! WF25: a read or played receipt that couldn't be written fails with the
//! write's own error in its chain, which a caller reads by type, not as text.

use super::*;
use crate::client::ClientError;
use crate::test_utils::create_iq_test_client;

/// Whether `error`'s chain holds the client's typed error.
fn typed(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| cause.is::<ClientError>())
}

#[tokio::test]
async fn a_read_receipt_that_isnt_written_keeps_its_write_error() {
    let (client, transport) = create_iq_test_client().await;
    let chat: Jid = "15550000002@s.whatsapp.net".parse().unwrap();
    transport.fail_next_sends(1);
    let error = client
        .mark_as_read(&chat, None, &["3EB0WF25READ"])
        .await
        .unwrap_err();
    assert!(typed(&error), "{error:#}");
    assert_eq!(error.to_string(), "Failed to send read receipt");
}

#[tokio::test]
async fn a_played_receipt_that_isnt_written_keeps_its_write_error() {
    let (client, transport) = create_iq_test_client().await;
    let chat: Jid = "15550000002@s.whatsapp.net".parse().unwrap();
    transport.fail_next_sends(1);
    let error = client
        .mark_as_played(&chat, None, &["3EB0WF25PLAYED"])
        .await
        .unwrap_err();
    assert!(typed(&error), "{error:#}");
    assert_eq!(error.to_string(), "Failed to send played receipt");
}
