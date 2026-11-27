//! WF26: a 1:1 send is fenced to the connection it began on, as a group send
//! is. One whose connection ends while it waits for that connection's offline
//! drain (it holds a session already, so nothing else stops it) writes nothing
//! on the next connection, and ends with the typed `ClientError::NotConnected`.
//! One that passed its fence goes on the socket it read before the check, so a
//! reconnect after the check can't move it to the next connection either.

use super::*;
use crate::client::{Client, ClientError, NodeFilter};
use std::sync::atomic::Ordering;

#[tokio::test]
async fn a_one_to_one_whose_connection_changes_before_its_write_writes_nothing() {
    const ID: &str = "3EB0WF26FENCE";
    let client = crate::test_utils::create_test_client_with_name("wf26_dm_fence").await;
    let (peer_pn, _peer_lid) = seed_dm_wire_namespace_state(&client).await;
    // The connection's offline drain is still running: the send waits for its
    // end before it checks its sessions.
    client
        .offline_sync_completed
        .store(false, Ordering::Release);
    let mut written = client.wait_for_sent_node(NodeFilter::tag("message").attr("id", ID));
    let send = tokio::spawn({
        let client = client.clone();
        async move {
            let mut message = wa::Message::default();
            message.conversation = Some("hi".into());
            client
                .send_message_impl(
                    peer_pn,
                    &message,
                    SendPipelineOptions {
                        request_id: Some(ID),
                        ..Default::default()
                    },
                )
                .await
        }
    });
    crate::test_utils::wait_for_notifier_listeners(&client.offline_sync_notifier, 1).await;
    // The connection ends while the send waits, and the next one begins.
    client.notify_connection_shutdown();
    client.connection_generation.fetch_add(1, Ordering::AcqRel);
    let error = send
        .await
        .expect("the send's task")
        .expect_err("a send whose connection changed fails");
    assert!(
        matches!(
            error.downcast_ref::<ClientError>(),
            Some(ClientError::NotConnected)
        ),
        "{error:#}"
    );
    assert!(
        written.try_recv().expect("the waiter is live").is_none(),
        "the stanza was written on the next connection"
    );
}

/// A reconnect run by a waker, in a reconnect's order: the generation moves,
/// then the next connection's socket is published.
struct Reconnect {
    client: std::sync::Weak<Client>,
    socket: std::sync::Mutex<Option<Arc<crate::socket::NoiseSocket>>>,
}

impl std::task::Wake for Reconnect {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        let socket = self.socket.lock().unwrap().take();
        if let (Some(client), Some(socket)) = (self.client.upgrade(), socket) {
            client.connection_generation.fetch_add(1, Ordering::AcqRel);
            *client.noise_socket.lock().unwrap() = Some(socket);
        }
    }
}

/// A reconnect that lands after the fence's check, here inside the write
/// itself, leaves the 1:1 on the socket the send read before the check.
#[tokio::test]
async fn a_one_to_one_past_its_fence_is_written_on_the_connection_it_began_on() {
    const ID: &str = "3EB0WF26SOCKET";
    let (client, first) = crate::test_utils::create_iq_test_client().await;
    let (peer_pn, _peer_lid) = seed_dm_wire_namespace_state(&client).await;
    let next = Arc::new(crate::transport::mock::CapturingMockTransport::new());
    let reconnect = Arc::new(Reconnect {
        client: Arc::downgrade(&client),
        socket: std::sync::Mutex::new(Some(Arc::new(crate::socket::NoiseSocket::new(
            client.runtime.clone(),
            next.clone(),
            wacore::handshake::NoiseCipher::new(&[0u8; 32]).expect("32-byte key"),
            wacore::handshake::NoiseCipher::new(&[0u8; 32]).expect("32-byte key"),
        )))),
    });
    // The waiter's waker runs as the write marshals the stanza, after the
    // fence: that is where the reconnect lands.
    let mut written = client.wait_for_sent_node(NodeFilter::tag("message").attr("id", ID));
    let waker = std::task::Waker::from(Arc::clone(&reconnect));
    assert!(
        Future::poll(
            std::pin::Pin::new(&mut written),
            &mut std::task::Context::from_waker(&waker),
        )
        .is_pending()
    );
    let before = first.sent().len();
    let mut message = wa::Message::default();
    message.conversation = Some("hi".into());
    client
        .send_message_impl(
            peer_pn,
            &message,
            SendPipelineOptions {
                request_id: Some(ID),
                ..Default::default()
            },
        )
        .await
        .expect("the 1:1 is written");
    assert!(
        reconnect.socket.lock().unwrap().is_none(),
        "the reconnect ran during the write"
    );
    let is_the_message = |stanza: Arc<wacore_binary::OwnedNodeRef>| {
        stanza.get().tag == "message"
            && stanza.get().attrs().optional_string("id").as_deref() == Some(ID)
    };
    let mut on_its_connection = 0;
    for index in before..first.sent().len() {
        if is_the_message(crate::test_utils::decode_sent_iq(&first, index).await) {
            on_its_connection += 1;
        }
    }
    assert_eq!(
        on_its_connection, 1,
        "the 1:1 went on the socket it read before its fence"
    );
    for index in 0..next.sent().len() {
        assert!(
            !is_the_message(crate::test_utils::decode_sent_iq(&next, index).await),
            "the 1:1 was written on the next connection"
        );
    }
}
