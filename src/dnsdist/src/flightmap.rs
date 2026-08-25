// Single-flight map shared by both upstream pools: identical concurrent
// queries collapse into one initiator; latecomers await its outcome.
// The initiator carries a drop-guard so a cancelled handler (client walked
// away mid-query) fails the flight instead of leaving a Pending entry that
// would stall every future identical query until the map entry leaked.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::Notify;

use crate::upstream::UpErr;

enum FlightState {
    Pending,
    Ok(Arc<Vec<u8>>),
    Failed,
}

/// Opaque in-flight handle; joiners await it via `await_flight`.
pub struct Flight {
    state: Mutex<FlightState>,
    notify: Notify,
}

struct Shared {
    map: Mutex<HashMap<Vec<u8>, Arc<Flight>>>,
}

/// Cheap-clonable handle so the initiator guard can reach the map on drop.
#[derive(Clone)]
pub struct FlightMap {
    shared: Arc<Shared>,
}

/// What `enter()` decided for this query.
pub enum Entered {
    /// You are the upstream runner: call `settle()` exactly once.
    Initiator(InitGuard),
    /// An identical query is in flight: `await_flight()` it. On failure you
    /// may re-enter to become the initiator yourself.
    Joiner(Arc<Flight>),
    /// Map at capacity: run without dedup (memory bound wins).
    Bypass,
}

/// Settles the flight as Failed when dropped without `settle()` — the
/// initiator's task was cancelled, so joiners must be freed to retry.
pub struct InitGuard {
    shared: Arc<Shared>,
    key: Vec<u8>,
    flight: Arc<Flight>,
    done: bool,
}

impl InitGuard {
    /// Record the outcome and wake all joiners; removes the map entry.
    /// `ok` is the canonical response body (ID-agnostic: callers patch IDs).
    pub fn settle(mut self, ok: Option<Arc<Vec<u8>>>) {
        {
            let mut st = self.flight.state.lock().unwrap();
            *st = match ok {
                Some(v) => FlightState::Ok(v),
                None => FlightState::Failed,
            };
        }
        self.done = true;
        self.shared.map.lock().unwrap().remove(&self.key);
        self.flight.notify.notify_waiters();
    }
}

impl Drop for InitGuard {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        let pending = matches!(*self.flight.state.lock().unwrap(), FlightState::Pending);
        if pending {
            *self.flight.state.lock().unwrap() = FlightState::Failed;
            self.shared.map.lock().unwrap().remove(&self.key);
            self.flight.notify.notify_waiters();
        }
    }
}

impl FlightMap {
    pub fn new() -> Self {
        FlightMap {
            shared: Arc::new(Shared {
                map: Mutex::new(HashMap::new()),
            }),
        }
    }

    pub fn enter(&self, key: &[u8], cap: usize) -> Entered {
        let mut g = self.shared.map.lock().unwrap();
        if let Some(f) = g.get(key) {
            return Entered::Joiner(f.clone());
        }
        if g.len() >= cap {
            return Entered::Bypass;
        }
        let f = Arc::new(Flight {
            state: Mutex::new(FlightState::Pending),
            notify: Notify::new(),
        });
        g.insert(key.to_vec(), f.clone());
        Entered::Initiator(InitGuard {
            shared: self.shared.clone(),
            key: key.to_vec(),
            flight: f,
            done: false,
        })
    }

    pub fn len(&self) -> usize {
        self.shared.map.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Wait for a joined flight's outcome. `deadline` bounds the wait.
pub async fn await_flight(f: Arc<Flight>, deadline: Instant) -> Result<Arc<Vec<u8>>, UpErr> {
    let mut notified = std::pin::pin!(f.notify.notified());
    loop {
        match &*f.state.lock().unwrap() {
            FlightState::Ok(v) => return Ok(v.clone()),
            FlightState::Failed => return Err(UpErr::Conn("flight failed".into())),
            FlightState::Pending => {}
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or(UpErr::Timeout)?;
        match tokio::time::timeout(remaining, notified.as_mut()).await {
            Ok(_) => continue,
            Err(_) => return Err(UpErr::Timeout),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn key(b: u8) -> Vec<u8> {
        vec![b]
    }

    #[tokio::test]
    async fn second_identical_query_joins_first_flight() {
        let m = FlightMap::new();
        let k = key(1);
        let e1 = m.enter(&k, 16);
        let e2 = m.enter(&k, 16);
        assert!(matches!(e1, Entered::Initiator(_)));
        match e2 {
            Entered::Joiner(_) => {}
            _ => panic!("second enter must be a joiner"),
        }
        assert_eq!(m.len(), 1);
    }

    #[tokio::test]
    async fn settle_wakes_joiners_with_body() {
        let m = FlightMap::new();
        let k = key(2);
        let (guard, joiner) = match (m.enter(&k, 16), m.enter(&k, 16)) {
            (Entered::Initiator(g), Entered::Joiner(f)) => (g, f),
            _ => panic!("shape"),
        };
        let jh = tokio::spawn(async move {
            await_flight(joiner, Instant::now() + Duration::from_secs(2)).await
        });
        tokio::task::yield_now().await;
        guard.settle(Some(Arc::new(vec![7, 7, 7])));
        let got = jh.await.unwrap().unwrap();
        assert_eq!(&*got, &[7, 7, 7]);
        assert!(m.is_empty(), "settled entry removed");
    }

    #[tokio::test]
    async fn dropped_initiator_fails_flight_so_joiner_can_take_over() {
        let m = FlightMap::new();
        let k = key(3);
        let holder = match m.enter(&k, 16) {
            Entered::Initiator(g) => g,
            _ => panic!("shape"),
        };
        let joiner = match m.enter(&k, 16) {
            Entered::Joiner(f) => f,
            _ => panic!("shape"),
        };
        let jh = tokio::spawn(async move {
            await_flight(joiner, Instant::now() + Duration::from_secs(2)).await
        });
        tokio::task::yield_now().await;
        drop(holder); // initiator cancelled without settling
        let r = jh.await.unwrap();
        assert!(r.is_err(), "cancelled initiator must fail joiners");
        assert!(m.is_empty(), "map slot released, next query can initiate");
    }

    #[tokio::test]
    async fn capacity_bypasses_but_still_joins_existing() {
        let m = FlightMap::new();
        let ka = key(4);
        let kb = key(5);
        let _init = match m.enter(&ka, 1) {
            Entered::Initiator(g) => g,
            _ => panic!("shape"),
        };
        assert!(
            matches!(m.enter(&kb, 1), Entered::Bypass),
            "full map: new key bypasses"
        );
        assert!(
            matches!(m.enter(&ka, 1), Entered::Joiner(_)),
            "full map: existing key still joins"
        );
    }

    #[tokio::test]
    async fn joiner_failure_then_reenter_becomes_initiator() {
        let m = FlightMap::new();
        let k = key(6);
        let guard = match m.enter(&k, 16) {
            Entered::Initiator(g) => g,
            _ => panic!("shape"),
        };
        let joiner = match m.enter(&k, 16) {
            Entered::Joiner(f) => f,
            _ => panic!("shape"),
        };
        guard.settle(None); // first upstream round failed
        assert!(await_flight(joiner, Instant::now()).await.is_err());
        match m.enter(&k, 16) {
            Entered::Initiator(_) => {}
            _ => panic!("after failure a fresh enter must initiate again"),
        }
    }
}
