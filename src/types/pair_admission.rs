use wacore_binary::Jid;

/// What a verified `pair-success` names, before the device is paired with it.
#[non_exhaustive]
#[derive(Clone, Copy, Debug)]
pub struct PairCandidate<'a> {
    /// The companion the account gave this device: its phone number and device.
    pub id: &'a Jid,
    /// The same companion's LID; empty when the server names none.
    pub lid: &'a Jid,
    /// A business account's name, empty otherwise.
    pub business_name: &'a str,
    /// What the phone runs, as the server names it.
    pub platform: &'a str,
}

/// Result of [`PairAdmission::decide`].
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairDecision {
    Accept,
    /// Refuse the account: the server is told the pairing failed, so the phone's
    /// pairing fails too and the account lists no companion, and nothing is
    /// written here.
    Refuse,
}

/// Synchronous, operator-owned check of the account a phone pairs this device
/// with, while the pairing can still be refused (whatsmeow's `PrePairCallback`).
///
/// Asked for every `pair-success` whose signed identity verifies, a QR scan's
/// and a pair code's alike, before the identity is committed and before the
/// client signs it: past that point the server lists the companion, and only
/// the phone or the device itself can remove it. A forged `pair-success` is
/// refused without asking.
///
/// On [`PairDecision::Refuse`] the client answers the server as it answers a
/// `pair-success` it can't complete (500 `internal-error`) and writes nothing.
/// It leaves the connection, the device and the pairing in progress as they
/// were: a QR's codes keep rotating, a pair code stays pending, and a later
/// `pair-success` is put to the policy again. Then it dispatches
/// [`Event::PairError`](wacore::types::events::Event::PairError) with
/// [`PairErrorReason::LocalRefusal`](wacore::types::events::PairErrorReason::LocalRefusal).
/// What the server allows after a refused `pair-success` hasn't been observed
/// (whatsmeow ends the connection there). A host done with the attempt shuts
/// the client down.
///
/// Make a fast local decision without I/O or blocking: the pairing is held
/// meanwhile. Configure through `ClientBuilder::with_pair_admission` or
/// `BotBuilder::with_pair_admission`. Without a policy every verified account
/// is accepted. A panic propagates through the task handling the stanza.
pub trait PairAdmission: wacore::sync_marker::MaybeSendSync {
    fn decide(&self, candidate: &PairCandidate<'_>) -> PairDecision;
}
