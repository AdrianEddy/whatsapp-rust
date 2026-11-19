//! `from_upgraded_stream` frames a stream whose WebSocket upgrade the host
//! completed itself (MultiChat's `mc-net` dials, runs TLS and writes the
//! upgrade). Runs with the default features and with `--no-default-features`,
//! which builds no TLS stack.

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_websockets::{CloseCode, Message, ServerBuilder};
use wacore::net::TransportEvent;
use whatsapp_rust_tokio_transport::from_upgraded_stream;

/// RFC 6455 §1.3's sample key and the accept value it yields, so the host's
/// check of `Sec-WebSocket-Accept` needs no SHA-1 of its own.
const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
const ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
const ORIGIN: &str = "https://web.whatsapp.com";

/// The host's half of the upgrade: its own request, then the `101` head read a
/// byte at a time, so the stream it hands over starts at the first frame.
async fn upgrade(tcp: &mut TcpStream) {
    let host = tcp.peer_addr().unwrap();
    let request = format!(
        "GET /ws/chat HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
         Origin: {ORIGIN}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {KEY}\r\n\r\n"
    );
    tcp.write_all(request.as_bytes()).await.unwrap();

    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(tcp.read_u8().await.unwrap());
    }
    let head = String::from_utf8(head).unwrap();
    let mut lines = head.split("\r\n");
    assert!(lines.next().unwrap().starts_with("HTTP/1.1 101 "), "{head}");
    let accept = lines
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("sec-websocket-accept"))
        .map(|(_, value)| value.trim());
    assert_eq!(accept, Some(ACCEPT), "{head}");
}

#[tokio::test]
async fn from_upgraded_stream_exchanges_binary_frames() {
    // Each way, one frame under the read path's adoption threshold and one far
    // above it, which spans many socket reads.
    let large: Vec<u8> = (0..70_000u32).map(|i| (i % 251) as u8).collect();
    let to_client = [
        Bytes::from_static(b"server frame"),
        Bytes::from(large.clone()),
    ];
    let to_server = [
        Bytes::from(large.into_iter().rev().collect::<Vec<u8>>()),
        Bytes::from_static(b"client frame"),
    ];

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = async {
        let (tcp, _) = listener.accept().await.unwrap();
        let (request, mut ws) = ServerBuilder::new().accept(tcp).await.unwrap();
        // The upgrade the server answered is the host's, not one of the transport's.
        assert_eq!(request.uri().path(), "/ws/chat");
        assert_eq!(request.headers()["origin"], ORIGIN);
        // Sent straight after the `101` head.
        for payload in &to_client {
            ws.send(Message::binary(payload.clone())).await.unwrap();
        }
        // A server refuses unmasked frames, so these arriving shows the client role.
        for payload in &to_server {
            let message = ws.next().await.unwrap().unwrap();
            assert!(message.is_binary());
            assert_eq!(&message.as_payload()[..], &payload[..]);
        }
        let close = ws.next().await.unwrap().unwrap();
        assert_eq!(
            close.as_close().map(|(code, _)| code),
            Some(CloseCode::NORMAL_CLOSURE)
        );
    };

    let client = async {
        let mut tcp = TcpStream::connect(addr).await.unwrap();
        upgrade(&mut tcp).await;
        let (transport, events) = from_upgraded_stream(tcp);
        assert!(matches!(
            events.recv().await.unwrap(),
            TransportEvent::Connected
        ));
        for payload in &to_client {
            match events.recv().await.unwrap() {
                TransportEvent::DataReceived(data) => assert_eq!(data, *payload),
                other => panic!("expected a binary frame, got {other:?}"),
            }
        }
        for payload in &to_server {
            transport.send(payload.clone()).await.unwrap();
        }
        transport.disconnect().await;
        assert!(matches!(
            events.recv().await.unwrap(),
            TransportEvent::Disconnected(_)
        ));
    };

    tokio::join!(server, client);
}
