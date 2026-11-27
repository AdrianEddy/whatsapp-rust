use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use wacore::appstate::patch_decode::WAPatchName;
use wacore::messages::DetachedHistorySyncNotification;
pub(crate) use wacore::sync_engine::history::HistoryActivitySnapshot as HistorySyncActivitySnapshot;
use wacore::sync_engine::history::{
    HistoryActivity as HistorySyncActivityState, HistoryGeneration as HistorySyncGeneration,
};

/// Shared accounting for queued/running history-sync work. Payload bytes are
/// logical compressed lengths: this keeps owned downloads comparable with
/// sliced [`bytes::Bytes`], whose larger shared allocation is not observable.
pub(crate) struct HistorySyncActivity {
    state: Mutex<HistorySyncActivityState>,
    idle_notifier: event_listener::Event,
    /// Shared by the worker and explicit host replay, never reset on reconnect.
    pub(crate) processing_permits: Arc<async_lock::Semaphore>,
    /// Replays take this first, leaving global capacity for the sync worker.
    pub(crate) replay_permits: Arc<async_lock::Semaphore>,
    /// The durable keys whose chunk is in flight: a worker task's (queued or
    /// running) or a host replay's, one per key ([`Self::claim`]).
    flights: Mutex<HashMap<crate::HistorySyncKey, Arc<HistoryFlight>>>,
}

/// One durable key's download and parse in flight ([`HistorySyncActivity::claim`]).
pub(crate) struct HistoryFlight {
    ended: event_listener::Event,
    /// How it ended, set once as it ends.
    outcome: std::sync::OnceLock<Result<(), crate::HistoryChunkFailure>>,
}

impl HistoryFlight {
    /// Its outcome, once it has ended: `Ok` when the chunk was captured and
    /// parsed.
    pub(crate) async fn ended(&self) -> Result<(), crate::HistoryChunkFailure> {
        loop {
            let ended = self.ended.listen();
            if let Some(outcome) = self.outcome.get() {
                return *outcome;
            }
            ended.await;
        }
    }
}

/// What claiming a key's chunk gives ([`HistorySyncActivity::claim`]).
pub(crate) enum HistoryClaim {
    /// Nothing held the key: the caller's work is its flight.
    Lead(HistoryFlightLease),
    /// Another's work holds it: wait for that to end instead.
    Join(Arc<HistoryFlight>),
}

/// A key's flight, held by the work that leads it. Its end, through
/// [`Self::finish`] or a drop (a task cancelled or dropped before it finished,
/// which a later try can get past: a network failure), frees the key and tells
/// every joiner how it ended.
pub(crate) struct HistoryFlightLease {
    activity: Arc<HistorySyncActivity>,
    key: crate::HistorySyncKey,
    flight: Arc<HistoryFlight>,
    outcome: Result<(), crate::HistoryChunkFailure>,
}

impl HistoryFlightLease {
    /// A flight that ended before its work did: the next try can get past it.
    const INTERRUPTED: Result<(), crate::HistoryChunkFailure> =
        Err(crate::HistoryChunkFailure::Network);

    pub(crate) fn key(&self) -> &crate::HistorySyncKey {
        &self.key
    }

    /// End the flight with `outcome`.
    pub(crate) fn finish(mut self, outcome: Result<(), crate::HistoryChunkFailure>) {
        self.outcome = outcome;
    }
}

impl Drop for HistoryFlightLease {
    fn drop(&mut self) {
        let _ = self.flight.outcome.set(self.outcome);
        let mut flights = self.activity.flights_guard();
        if flights
            .get(&self.key)
            .is_some_and(|flight| Arc::ptr_eq(flight, &self.flight))
        {
            flights.remove(&self.key);
        }
        drop(flights);
        self.flight.ended.notify(usize::MAX);
    }
}

impl std::fmt::Debug for HistoryFlightLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HistoryFlightLease")
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

impl HistorySyncActivity {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(HistorySyncActivityState::default()),
            idle_notifier: event_listener::Event::new(),
            processing_permits: Arc::new(async_lock::Semaphore::new(2)),
            replay_permits: Arc::new(async_lock::Semaphore::new(1)),
            flights: Mutex::new(HashMap::new()),
        }
    }

    /// Claim `key`'s chunk for the caller's work: the lead, or the flight that
    /// holds it already. One key has one download and parse at a time, so a
    /// worker task that outlives its connection and the host's replay of the
    /// same key on the next one don't both fetch it.
    pub(crate) fn claim(self: &Arc<Self>, key: &crate::HistorySyncKey) -> HistoryClaim {
        let mut flights = self.flights_guard();
        if let Some(flight) = flights.get(key) {
            return HistoryClaim::Join(Arc::clone(flight));
        }
        let flight = Arc::new(HistoryFlight {
            ended: event_listener::Event::new(),
            outcome: std::sync::OnceLock::new(),
        });
        flights.insert(key.clone(), Arc::clone(&flight));
        drop(flights);
        HistoryClaim::Lead(HistoryFlightLease {
            activity: Arc::clone(self),
            key: key.clone(),
            flight,
            outcome: HistoryFlightLease::INTERRUPTED,
        })
    }

    /// How many hold `key`'s flight: the registry, its lead and each joiner.
    #[cfg(test)]
    pub(crate) fn flight_holders(&self, key: &crate::HistorySyncKey) -> usize {
        self.flights_guard().get(key).map_or(0, Arc::strong_count)
    }

    fn flights_guard(&self) -> MutexGuard<'_, HashMap<crate::HistorySyncKey, Arc<HistoryFlight>>> {
        self.flights
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(crate) fn begin(self: &Arc<Self>, payload_bytes: usize) -> HistorySyncTaskTracker {
        let mut state = self.state_guard();
        let generation = state.begin(payload_bytes);
        drop(state);
        HistorySyncTaskTracker {
            inner: Arc::new(HistorySyncTaskTrackerInner {
                activity: Arc::clone(self),
                generation,
                state: Mutex::new(HistorySyncTaskState {
                    payload_bytes,
                    durable: None,
                    processing_permits: None,
                }),
            }),
        }
    }

    pub(crate) fn reset(&self) {
        let mut state = self.state_guard();
        state.reset();
        drop(state);
        self.idle_notifier.notify(usize::MAX);
    }

    pub(crate) fn listen(&self) -> event_listener::EventListener {
        self.idle_notifier.listen()
    }

    #[cfg(test)]
    pub(crate) fn idle_notifier(&self) -> &event_listener::Event {
        &self.idle_notifier
    }

    pub(crate) fn tasks(&self) -> usize {
        self.state_guard().snapshot().tasks
    }

    pub(crate) fn snapshot(&self) -> HistorySyncActivitySnapshot {
        self.state_guard().snapshot()
    }

    fn release(&self, generation: HistorySyncGeneration, payload_bytes: usize) {
        let mut state = self.state_guard();
        let is_idle = state.release(generation, payload_bytes);
        drop(state);
        if is_idle {
            self.idle_notifier.notify(usize::MAX);
        }
    }

    fn state_guard(&self) -> MutexGuard<'_, HistorySyncActivityState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[doc(hidden)]
pub struct HistorySyncTaskTracker {
    // The bounded channel allocates every slot when the Client is built.
    // Keep recovery state out of those empty slots, without changing the
    // public MajorSyncTask variant or its tracker field type.
    inner: Arc<HistorySyncTaskTrackerInner>,
}

struct HistorySyncTaskTrackerInner {
    activity: Arc<HistorySyncActivity>,
    generation: HistorySyncGeneration,
    state: Mutex<HistorySyncTaskState>,
}

struct HistorySyncTaskState {
    payload_bytes: usize,
    // Recovery context follows this one task through the existing public queue
    // shape. It must not be keyed globally by the non-unique stanza ID: the
    // lease holds the key's flight, keyed by the whole key.
    durable: Option<Box<HistoryFlightLease>>,
    // A blocking parser/encoder keeps a lease after its async caller is
    // cancelled. Keep both limits in one lease so a detached replay cannot
    // release its replay slot while still occupying global processing capacity.
    processing_permits: Option<Arc<HistorySyncProcessingPermits>>,
}

pub(crate) struct HistorySyncProcessingPermits {
    _processing: async_lock::SemaphoreGuardArc,
    _replay: Option<async_lock::SemaphoreGuardArc>,
}

impl HistorySyncTaskTracker {
    /// Retain this task's activity and capacity until physical CPU work ends.
    pub(crate) fn blocking_lease(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }

    fn state(&self) -> MutexGuard<'_, HistorySyncTaskState> {
        self.inner
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(crate) fn set_processing_permits(
        &mut self,
        processing: async_lock::SemaphoreGuardArc,
        replay: Option<async_lock::SemaphoreGuardArc>,
    ) {
        self.state().processing_permits = Some(Arc::new(HistorySyncProcessingPermits {
            _processing: processing,
            _replay: replay,
        }));
    }

    pub(crate) fn processing_permits(&self) -> Option<Arc<HistorySyncProcessingPermits>> {
        self.state().processing_permits.clone()
    }

    pub(crate) fn clear_processing_permits(&mut self) {
        self.state().processing_permits = None;
    }

    pub(crate) fn set_durable(&mut self, lease: HistoryFlightLease) {
        self.state().durable = Some(Box::new(lease));
    }

    pub(crate) fn take_durable(&mut self) -> Option<Box<HistoryFlightLease>> {
        self.state().durable.take()
    }

    pub(crate) fn set_payload_bytes(&mut self, payload_bytes: usize) {
        let mut task = self.state();
        let mut state = self.inner.activity.state_guard();
        state.resize(self.inner.generation, task.payload_bytes, payload_bytes);
        task.payload_bytes = payload_bytes;
    }
}

impl std::fmt::Debug for HistorySyncTaskTracker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HistorySyncTaskTracker")
            .field("generation", &self.inner.generation)
            .field("payload_bytes", &self.state().payload_bytes)
            .finish_non_exhaustive()
    }
}

impl Drop for HistorySyncTaskTrackerInner {
    fn drop(&mut self) {
        let state = self
            .state
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        drop(state.processing_permits.take());
        self.activity.release(self.generation, state.payload_bytes);
    }
}

#[derive(Debug)]
pub enum MajorSyncTask {
    HistorySync {
        message_id: String,
        notification: Box<DetachedHistorySyncNotification>,
        tracker: HistorySyncTaskTracker,
    },
    AppStateSync {
        name: WAPatchName,
        full_sync: bool,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_sync_tracker_updates_payload_peaks_and_releases_exactly_once() {
        let activity = Arc::new(HistorySyncActivity::new());
        let mut first = activity.begin(100);
        let second = activity.begin(200);

        first.set_payload_bytes(150);
        assert_eq!(
            activity.snapshot(),
            HistorySyncActivitySnapshot {
                tasks: 2,
                tasks_peak: 2,
                payload_bytes: 350,
                payload_bytes_peak: 350,
            }
        );

        drop(first);
        assert_eq!(activity.tasks(), 1);
        assert_eq!(activity.snapshot().payload_bytes, 200);

        drop(second);
        assert_eq!(
            activity.snapshot(),
            HistorySyncActivitySnapshot {
                tasks: 0,
                tasks_peak: 2,
                payload_bytes: 0,
                payload_bytes_peak: 350,
            }
        );
    }

    #[test]
    fn queued_history_sync_tracker_cannot_release_current_generation() {
        let activity = Arc::new(HistorySyncActivity::new());
        let mut stale_tracker = activity.begin(1024);
        activity.reset();
        let current_tracker = activity.begin(2048);

        stale_tracker.set_payload_bytes(4096);
        drop(stale_tracker);

        assert_eq!(activity.tasks(), 1);
        assert_eq!(activity.snapshot().payload_bytes, 2048);

        drop(current_tracker);
        assert_eq!(activity.tasks(), 0);
        assert_eq!(activity.snapshot().payload_bytes, 0);
    }
}
