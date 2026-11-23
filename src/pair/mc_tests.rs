//! WF17: the account a `pair-success` names is put to the host before the
//! device is paired with it. A refusal tells the server the pairing failed and
//! leaves the device, its store and the pairing in progress as they were; an
//! acceptance pairs as a client without the check does.

use super::tests::signed_pair_success;
use super::*;
use crate::client::Client;
use crate::store::persistence_manager::PersistenceManager;
use crate::test_utils::{MockHttpClient, TestEventCollector, decrypt_wire_frames};
use crate::transport::mock::{CapturingMockTransport, CapturingMockTransportFactory};
use crate::{PairAdmission, PairCandidate, PairDecision};
use std::sync::Mutex;
use std::time::Duration;
use wacore::handshake::NoiseCipher;
use wacore::pair_code::PairCodeState;
use wacore::store::in_memory::InMemoryBackend;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::{Node, NodeContent, OwnedNodeRef};

const ID: &str = "15550001111:1@s.whatsapp.net";
const LID: &str = "100000000000001:1@lid";
const BUSINESS: &str = "Synthetic Trading";
const PLATFORM: &str = "android";

/// A policy with one verdict, and what it was shown: the companion's JID, its
/// LID, the business name and the platform.
struct Policy {
    decision: PairDecision,
    shown: Mutex<Vec<[String; 4]>>,
}

impl Policy {
    fn new(decision: PairDecision) -> Arc<Self> {
        Arc::new(Self {
            decision,
            shown: Mutex::default(),
        })
    }

    fn shown(&self) -> Vec<[String; 4]> {
        self.shown.lock().unwrap().clone()
    }
}

impl PairAdmission for Policy {
    fn decide(&self, candidate: &PairCandidate<'_>) -> PairDecision {
        self.shown.lock().unwrap().push([
            candidate.id.to_string(),
            candidate.lid.to_string(),
            candidate.business_name.to_owned(),
            candidate.platform.to_owned(),
        ]);
        self.decision
    }
}

/// A client waiting to be paired, over a store of its own.
struct Pairing {
    client: Arc<Client>,
    transport: Arc<CapturingMockTransport>,
    backend: Arc<InMemoryBackend>,
    events: Arc<TestEventCollector>,
}

impl Pairing {
    async fn new(policy: Option<Arc<dyn PairAdmission>>) -> Self {
        let backend = Arc::new(InMemoryBackend::new());
        let persistence = PersistenceManager::new(backend.clone())
            .await
            .expect("persistence manager should initialize");
        let mut builder = Client::builder()
            .with_runtime(crate::runtime_impl::TokioRuntime)
            .with_persistence_manager(Arc::new(persistence))
            .with_transport_factory(CapturingMockTransportFactory::new())
            .with_http_client(MockHttpClient);
        if let Some(policy) = policy {
            builder = builder.with_pair_admission_arc(policy);
        }
        let client = builder
            .build()
            .await
            .expect("test client should build")
            .into_client();
        let transport = Arc::new(CapturingMockTransport::new());
        let cipher = || NoiseCipher::new(&[0u8; 32]).expect("32-byte key");
        let socket = crate::socket::NoiseSocket::new(
            client.runtime.clone(),
            transport.clone(),
            cipher(),
            cipher(),
        );
        *client.noise_socket.lock().unwrap() = Some(Arc::new(socket));
        client.set_connected_for_test(true);
        client.set_driver_running_for_test(true, Ordering::Release);
        let events = Arc::new(TestEventCollector::default());
        client.subscribe_handler(events.clone()).detach();
        Self {
            client,
            transport,
            backend,
            events,
        }
    }

    /// The server's `pair-success`, signed for this device, as a business
    /// account's phone gives it.
    fn success(&self) -> Node {
        let mut iq = signed_pair_success(&self.client);
        let Some(NodeContent::Nodes(children)) = &mut iq.content else {
            unreachable!("the fixture holds a pair-success")
        };
        let success = &mut children[0];
        let identity = success
            .get_optional_child("device-identity")
            .expect("the fixture is signed")
            .clone();
        *success = NodeBuilder::new("pair-success")
            .children([
                identity,
                NodeBuilder::new("device")
                    .attr("jid", ID)
                    .attr("lid", LID)
                    .build(),
                NodeBuilder::new("biz").attr("name", BUSINESS).build(),
                NodeBuilder::new("platform").attr("name", PLATFORM).build(),
            ])
            .build();
        iq
    }

    async fn pair(&self, iq: &Node) {
        assert!(handle_iq(&self.client, &iq.as_node_ref()).await);
    }

    /// The answers the client wrote, decoded.
    fn answers(&self) -> Vec<OwnedNodeRef> {
        decrypt_wire_frames(&self.transport.sent(), &[0u8; 32])
            .into_iter()
            .map(|frame| {
                let node = wacore_binary::util::unpack(&frame).expect("unpack");
                OwnedNodeRef::new(node.into_owned()).expect("decode")
            })
            .filter(|node| node.tag() == "iq")
            .collect()
    }

    fn errors(&self) -> Vec<PairError> {
        self.events
            .events()
            .iter()
            .filter_map(|event| match &**event {
                Event::PairError(error) => Some(error.clone()),
                _ => None,
            })
            .collect()
    }

    fn paired(&self) -> bool {
        self.events
            .events()
            .iter()
            .any(|event| matches!(&**event, Event::PairSuccess(_)))
    }
}

fn shown() -> Vec<[String; 4]> {
    vec![[ID, LID, BUSINESS, PLATFORM].map(str::to_owned)]
}

#[tokio::test]
async fn a_refused_account_leaves_no_identity_and_no_companion() {
    let policy = Policy::new(PairDecision::Refuse);
    let pairing = Pairing::new(Some(policy.clone())).await;
    let before = pairing.client.persistence_manager.get_device_snapshot();
    let (stop, stopped) = async_channel::bounded(1);
    *pairing.client.pairing_cancellation_tx.lock().await = Some(stop);

    pairing.pair(&pairing.success()).await;
    assert_eq!(policy.shown(), shown());

    // The server is told the pairing failed: nothing is signed for it.
    let answers = pairing.answers();
    assert_eq!(answers.len(), 1, "one answer");
    let answer = answers[0].get();
    assert_eq!(
        answer.attrs().optional_string("type").as_deref(),
        Some("error")
    );
    assert_eq!(
        answer.attrs().optional_string("id").as_deref(),
        Some("signed-success")
    );
    let error = answer.get_optional_child("error").expect("an error");
    assert_eq!(
        error.attrs().optional_string("code").as_deref(),
        Some("500")
    );
    assert_eq!(
        error.attrs().optional_string("text").as_deref(),
        Some("internal-error")
    );

    // The host is told whose refusal it is.
    let errors = pairing.errors();
    assert_eq!(errors.len(), 1, "one event");
    assert_eq!(errors[0].reason, PairErrorReason::LocalRefusal);
    assert_eq!(
        [
            errors[0].id.to_string(),
            errors[0].lid.to_string(),
            errors[0].business_name.clone(),
            errors[0].platform.clone(),
        ],
        shown()[0],
    );
    assert!(!pairing.paired());

    // Neither the device nor its store holds anything of the account.
    let flushed = pairing.client.persistence_manager.flush().await;
    flushed.expect("flush");
    let reloaded = PersistenceManager::new(pairing.backend.clone())
        .await
        .expect("reload store");
    for device in [
        pairing.client.persistence_manager.get_device_snapshot(),
        reloaded.get_device_snapshot(),
    ] {
        assert!(device.pn.is_none());
        assert!(device.lid.is_none());
        assert!(device.account.is_none());
        assert!(device.push_name.is_empty());
        assert!(!device.initial_full_sync_owed);
        assert_eq!(device.adv_secret_key, before.adv_secret_key);
    }
    let own = pairing.client.lid_pn_cache.get_current_lid("15550001111");
    assert!(own.await.is_none(), "no mapping of the account is learned");

    // The pairing in progress goes on: its codes keep rotating, and nothing
    // expects the connection to end.
    assert!(stopped.is_empty());
    assert!(
        pairing
            .client
            .pairing_cancellation_tx
            .lock()
            .await
            .is_some()
    );
    assert!(!matches!(
        *pairing.client.pair_code_state.lock().await,
        PairCodeState::Completed
    ));
    assert!(!pairing.client.needs_initial_full_sync.is_armed());
    assert!(
        !pairing
            .client
            .expected_session_disconnect(Ordering::Relaxed)
    );
}

#[tokio::test]
async fn an_accepted_account_pairs_as_without_the_check() {
    let policy = Policy::new(PairDecision::Accept);
    let mut answered = Vec::new();
    for checked in [None, Some(policy.clone() as Arc<dyn PairAdmission>)] {
        let pairing = Pairing::new(checked).await;
        pairing.pair(&pairing.success()).await;
        assert!(pairing.paired());
        assert!(pairing.errors().is_empty());
        let device = pairing.client.persistence_manager.get_device_snapshot();
        assert_eq!(device.pn.as_ref().map(Jid::to_string).as_deref(), Some(ID));
        assert_eq!(
            device.lid.as_ref().map(Jid::to_string).as_deref(),
            Some(LID)
        );
        assert!(device.account.is_some());
        assert_eq!(device.push_name, BUSINESS);
        assert!(device.initial_full_sync_owed);
        assert!(
            pairing
                .client
                .expected_session_disconnect(Ordering::Relaxed)
        );
        let answers = pairing.answers();
        assert_eq!(answers.len(), 1, "one answer");
        let answer = answers[0].get();
        assert!(answer.get_optional_child("pair-device-sign").is_some());
        answered.push(
            answer
                .attrs()
                .optional_string("type")
                .map(|kind| kind.into_owned()),
        );
    }
    assert_eq!(answered[0], answered[1]);
    assert_eq!(policy.shown(), shown());
}

/// A refusal answers one `pair-success`: the next is put to the host too, and
/// pairs when it accepts.
#[tokio::test]
async fn a_later_pair_success_is_asked_again_after_a_refusal() {
    struct Once(Mutex<bool>);
    impl PairAdmission for Once {
        fn decide(&self, _: &PairCandidate<'_>) -> PairDecision {
            let mut refused = self.0.lock().unwrap();
            if std::mem::replace(&mut *refused, true) {
                PairDecision::Accept
            } else {
                PairDecision::Refuse
            }
        }
    }
    let pairing = Pairing::new(Some(Arc::new(Once(Mutex::new(false))))).await;
    let device = || pairing.client.persistence_manager.get_device_snapshot();
    let success = pairing.success();
    pairing.pair(&success).await;
    assert!(device().pn.is_none());
    pairing.pair(&success).await;
    assert!(device().pn.is_some());
    let kinds: Vec<_> = pairing
        .events
        .events()
        .iter()
        .filter_map(|event| match &**event {
            Event::PairError(error) => Some(Some(error.reason)),
            Event::PairSuccess(_) => Some(None),
            _ => None,
        })
        .collect();
    assert_eq!(kinds, [Some(PairErrorReason::LocalRefusal), None]);
}

/// A `pair-success` that does not verify is refused as before, unasked.
#[tokio::test]
async fn a_forged_account_is_not_put_to_the_host() {
    let policy = Policy::new(PairDecision::Accept);
    let pairing = Pairing::new(Some(policy.clone())).await;
    let forged = pairing.success();
    // The secret the identity was signed under is no longer the device's.
    pairing
        .client
        .persistence_manager
        .modify_device(|device| device.adv_secret_key = [0x7f; 32])
        .await;
    pairing.pair(&forged).await;
    assert!(policy.shown().is_empty());
    let errors = pairing.errors();
    assert_eq!(errors.len(), 1, "one event");
    assert_eq!(errors[0].reason, PairErrorReason::Failed);
    let answers = pairing.answers();
    let error = answers[0]
        .get()
        .get_optional_child("error")
        .expect("an error");
    assert_eq!(
        error.attrs().optional_string("code").as_deref(),
        Some("401")
    );
    assert!(
        pairing
            .client
            .persistence_manager
            .get_device_snapshot()
            .pn
            .is_none()
    );
}

/// A refusal decided as the connection ends is neither answered on the next one
/// nor announced.
#[tokio::test(start_paused = true)]
async fn a_refusal_of_a_retired_connection_is_silent() {
    let policy = Policy::new(PairDecision::Refuse);
    let pairing = Pairing::new(Some(policy.clone())).await;
    let iq = pairing.success();
    let node = iq.as_node_ref();
    let shutdown = pairing.client.connection_shutdown_signal();
    let state = pairing.client.pair_code_state.lock().await;
    let pending = handle_iq_scoped(&pairing.client, &node, &shutdown);
    futures::pin_mut!(pending);
    assert!(futures::poll!(&mut pending).is_pending());
    pairing.client.notify_connection_shutdown();
    pairing.client.reset_connection_shutdown();
    drop(state);
    assert!(
        tokio::time::timeout(Duration::from_secs(5), pending)
            .await
            .expect("the stanza is handled")
    );
    assert!(policy.shown().is_empty());
    assert!(pairing.answers().is_empty());
    assert!(pairing.errors().is_empty());
}
