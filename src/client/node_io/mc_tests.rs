//! WF23: `Event::ServerAck` keeps the acked stanza's `type`, so the ack of a
//! read receipt is told from the ack of the delivery receipt of the same id; a
//! message's ack reads as before.

use super::*;
use crate::test_utils::{TestEventCollector, create_test_client, node_to_owned_ref};
use crate::types::events::{Event, EventHandler, ServerAck};
use wacore_binary::builder::NodeBuilder;

/// The `ServerAck` the client dispatches for each of `acks`, in order.
async fn server_acks(acks: &[Node]) -> Vec<ServerAck> {
    let client = create_test_client().await;
    let collector = Arc::new(TestEventCollector::default());
    client
        .subscribe_handler(collector.clone() as Arc<dyn EventHandler>)
        .detach();
    for ack in acks {
        client.handle_ack_response_arc(&node_to_owned_ref(ack));
    }
    collector
        .events()
        .iter()
        .filter_map(|event| match &**event {
            Event::ServerAck(ack) => Some(ack.clone()),
            _ => None,
        })
        .collect()
}

/// A receipt's ack: its class, its id, and its `type` when it has one.
fn receipt_ack(id: &str, kind: Option<&str>) -> Node {
    let ack = NodeBuilder::new("ack")
        .attr("id", id)
        .attr("class", "receipt")
        .attr("from", "15550000002@s.whatsapp.net");
    match kind {
        Some(kind) => ack.attr("type", kind),
        None => ack,
    }
    .build()
}

/// The read receipt's ack and the delivery receipt's, of one message id: the
/// first carries `read`, the second no type.
#[tokio::test]
async fn a_receipts_ack_carries_its_type() {
    let acks = server_acks(&[
        receipt_ack("3EB0WF23", Some("read")),
        receipt_ack("3EB0WF23", None),
        receipt_ack("3EB0WF23", Some("read-self")),
    ])
    .await;
    let seen: Vec<_> = acks
        .iter()
        .map(|ack| (ack.id.as_str(), ack.class.as_deref(), ack.r#type.as_deref()))
        .collect();
    assert_eq!(
        seen,
        vec![
            ("3EB0WF23", Some("receipt"), Some("read")),
            ("3EB0WF23", Some("receipt"), None),
            ("3EB0WF23", Some("receipt"), Some("read-self")),
        ]
    );
}

/// A message's ack has no `type`, and its class, sender, time and error read as
/// they did.
#[tokio::test]
async fn a_messages_ack_is_unchanged() {
    let acks = server_acks(&[NodeBuilder::new("ack")
        .attr("id", "3EB0WF23MSG")
        .attr("class", "message")
        .attr("from", "15550000002@s.whatsapp.net")
        .attr("t", "1720000000")
        .build()])
    .await;
    let [ack] = acks.as_slice() else {
        panic!("one ack: {acks:?}");
    };
    assert_eq!(ack.id, "3EB0WF23MSG");
    assert_eq!(ack.class.as_deref(), Some("message"));
    assert_eq!(ack.r#type, None);
    assert_eq!(
        ack.from.as_ref().map(ToString::to_string).as_deref(),
        Some("15550000002@s.whatsapp.net")
    );
    assert_eq!(
        ack.timestamp.map(|time| time.timestamp()),
        Some(1_720_000_000)
    );
    assert_eq!(ack.error, None);
}
