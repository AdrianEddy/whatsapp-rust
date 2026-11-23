use anyhow::Result;
pub use wacore::types::events::OfflineSyncPreview;

/// The host's admission of a connection's offline backlog, before any of it is
/// asked for or handled.
///
/// Awaited once per connection, after `<success>`, when the server announces
/// the backlog (`<ib><offline_preview>`): a host that records it is catching up
/// commits that here, and nothing of the backlog runs ahead of the record.
/// `preview` carries the announced counts, the ones
/// [`Event::OfflineSyncPreview`](wacore::types::events::Event::OfflineSyncPreview)
/// carries after the call returns. A connection the server announces nothing on
/// is asked too, with `None`, when its backlog ends (`<ib><offline>`) or its
/// first offline stanza arrives. The one exception is a connection on which
/// none of the three comes before the client ends the drain by itself, after a
/// minute in which the server sent nothing of it: that connection isn't asked,
/// and what reaches it later is handled as live.
///
/// Until it returns `Ok`, the client sends no `<ib><offline_batch>`, and what
/// the server sends meanwhile waits in wire order: the preview, the first
/// stanzas of the backlog, which the server pushes unasked, its end marker, and
/// the live stanzas between them, so none overtakes another of its chat. No
/// hook, event or acknowledgement of theirs comes first, so
/// [`Event::OfflineSyncCompleted`](wacore::types::events::Event::OfflineSyncCompleted)
/// and [`Event::Connected`](wacore::types::events::Event::Connected) (the bot's
/// `on_connected`), which wait for the drain's end, come after it; the limit the
/// client puts on a drain that never ends (a minute of the server's silence)
/// starts once it has returned. What the connection itself needs goes on: IQ
/// answers and requests, acks, keepalives, and what ends the stream. What waits
/// is bounded at 256 stanzas or 4 MiB, checked between the transport's reads:
/// the read that crosses a bound is kept whole (a WebSocket transport's read is
/// one message, at most 64 MiB with tokio-websockets' defaults), a stanza
/// larger than the room left included, and then the client stops reading the
/// socket until the call returns. Nothing else bounds the call: a host that
/// never returns holds the backlog for as long as the connection lasts, and
/// once reading has stopped, its keepalive's pongs go unread and the keepalive
/// ends it.
///
/// `Err` ends the connection: nothing of the backlog is handled or acknowledged,
/// so the server delivers it again on the next one,
/// [`Event::Disconnected`](wacore::types::events::Event::Disconnected) says
/// [`OfflineAdmissionRefused`](wacore::net::DisconnectReason::OfflineAdmissionRefused),
/// and the client reconnects with its ordinary backoff where the host's settings
/// let it. The next connection asks again.
///
/// A connection that ends while the call runs (a shutdown, a reconnect, the
/// server) drops it: treat a dropped call as an indeterminate commit, and make
/// each call safe to repeat. Calls of two connections don't overlap. Awaiting
/// the client from inside it is allowed (the read loop goes on), except for what
/// waits for the drain's end, which waits for this call.
///
/// Without one installed nothing is held back, at no cost per stanza.
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
pub trait OfflineAdmissionHook: wacore::sync_marker::MaybeSendSync {
    /// Commit what the host records of the catch-up before returning `Ok(())`.
    async fn on_offline_backlog(&self, preview: Option<&OfflineSyncPreview>) -> Result<()>;
}
