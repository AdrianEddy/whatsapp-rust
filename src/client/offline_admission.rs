//! The gate [`OfflineAdmissionHook`] puts before a connection's offline backlog.
//!
//! The host's call is polled by the read loop beside its reads, never awaited
//! in it: a loop parked on a commit answers no IQ and reads no pong, so a hook
//! that asks the server anything would deadlock and a slow one would trip the
//! keepalive (the reason `complete_offline_sync` runs its finisher off the
//! loop). What the admission covers is kept back here in wire order instead,
//! and handed to the loop once the call returns. One gate per read loop, so per
//! connection.
//!
//! The ask, the answer and the client's own end of the drain are moves of one
//! connection's [`Admission`](super::offline_resume::Admission): a gate that
//! finds the drain ended asks nothing and opens for good.

use std::future::poll_fn;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::task::Poll;

use wacore::runtime::BoxFuture;
use wacore::stanza::wire_tags::StanzaTag;
use wacore_binary::{NodeRef, OwnedNodeRef};

use super::Client;
use crate::OfflineAdmissionHook;
use crate::handlers::ib;

/// How much is kept back before the loop stops reading. The server pushes a
/// primer of about five stanzas and waits for the first batch request, so only
/// live traffic under a host that takes its time reaches either bound. Checked
/// between the transport's reads ([`OfflineGate::reads`]), so the read that
/// crosses one is kept whole, a stanza larger than the room left included:
/// what is held can exceed a bound by that one read.
const HELD_STANZAS: usize = 256;
const HELD_BYTES: usize = 4 * 1024 * 1024;

pub(super) struct OfflineGate<'a> {
    client: &'a Client,
    state: State,
}

enum State {
    /// Nothing is held back: no hook, or this connection's backlog is admitted.
    Open,
    /// The hook, not asked on this connection yet.
    Armed(Arc<dyn OfflineAdmissionHook>),
    /// The host's call for connection `generation`, and what waits for it, in
    /// wire order.
    Asked {
        generation: u64,
        call: BoxFuture<'static, anyhow::Result<()>>,
        held: Vec<OwnedNodeRef>,
        held_bytes: usize,
    },
}

impl<'a> OfflineGate<'a> {
    pub(super) fn new(client: &'a Client) -> Self {
        let state = match &client.offline_admission_hook {
            Some(hook) => State::Armed(Arc::clone(hook)),
            None => State::Open,
        };
        Self { client, state }
    }

    /// `node`, unless it is kept back. The stanza that shows the connection has
    /// reached its backlog asks the host and is the first kept.
    pub(super) fn pass(&mut self, node: OwnedNodeRef) -> Option<OwnedNodeRef> {
        match &mut self.state {
            State::Open => return Some(node),
            // Before `<success>` there is no session, so no backlog either.
            State::Armed(_) if !self.client.is_logged_in() || !reaches_backlog(node.get()) => {
                return Some(node);
            }
            State::Armed(hook) => {
                let hook = Arc::clone(hook);
                // The generation `<success>` fixed, which the client's own end
                // of this connection's drain is recorded under.
                let generation = self.client.connection_generation.load(Ordering::Acquire);
                if !self.client.offline_batch.ask_admission(generation) {
                    // The client has ended the drain by itself: what comes now
                    // is live, and nothing is held back any more.
                    self.state = State::Open;
                    return Some(node);
                }
                let preview = node
                    .get()
                    .get_optional_child("offline_preview")
                    .map(ib::offline_preview);
                self.state = State::Asked {
                    generation,
                    call: Box::pin(async move { hook.on_offline_backlog(preview.as_ref()).await }),
                    held_bytes: node.backing_bytes().len(),
                    held: vec![node],
                };
            }
            State::Asked {
                held, held_bytes, ..
            } => {
                if !waits(node.get()) {
                    return Some(node);
                }
                *held_bytes += node.backing_bytes().len();
                held.push(node);
            }
        }
        None
    }

    /// Whether the loop may read more from the socket.
    pub(super) fn reads(&self) -> bool {
        match &self.state {
            State::Asked {
                held, held_bytes, ..
            } => held.len() < HELD_STANZAS && *held_bytes < HELD_BYTES,
            State::Open | State::Armed(_) => true,
        }
    }

    /// The host's verdict on a call in flight, with what waited for it; pending
    /// while there is none. Cancel-safe: the call stays in the gate.
    pub(super) async fn verdict(&mut self) -> anyhow::Result<Vec<OwnedNodeRef>> {
        let verdict = poll_fn(|cx| match &mut self.state {
            State::Asked { call, .. } => call.as_mut().poll(cx),
            State::Open | State::Armed(_) => Poll::Pending,
        })
        .await;
        let State::Asked {
            generation, held, ..
        } = std::mem::replace(&mut self.state, State::Open)
        else {
            unreachable!("only a call in flight answers");
        };
        self.client.offline_batch.answer_admission(generation);
        verdict.map(|()| held)
    }
}

impl Drop for OfflineGate<'_> {
    fn drop(&mut self) {
        if let State::Asked { generation, .. } = self.state {
            self.client.offline_batch.answer_admission(generation);
        }
    }
}

/// Whether `node` shows the connection has reached its offline backlog: the
/// server's preview of it, its end marker, or a stanza of it.
fn reaches_backlog(node: &NodeRef<'_>) -> bool {
    node.get_attr("offline").is_some() || frames_backlog(node)
}

/// Whether `node` announces or ends the offline backlog.
fn frames_backlog(node: &NodeRef<'_>) -> bool {
    node.tag.as_ref() == StanzaTag::InfoBanner.as_str()
        && (node.get_optional_child("offline_preview").is_some()
            || node.get_optional_child("offline").is_some())
}

/// Whether `node` waits for the admission: everything but what the connection
/// itself runs on. Live traffic waits with the backlog it is interleaved with,
/// so a chat's stanzas stay in order.
fn waits(node: &NodeRef<'_>) -> bool {
    match StanzaTag::try_from(node.tag.as_ref()) {
        Ok(
            StanzaTag::Success
            | StanzaTag::Failure
            | StanzaTag::StreamError
            | StanzaTag::XmlStreamEnd
            | StanzaTag::Iq
            | StanzaTag::Ack,
        ) => false,
        Ok(StanzaTag::InfoBanner) => frames_backlog(node),
        _ => true,
    }
}

#[cfg(test)]
mod mc_tests;
