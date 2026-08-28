// Zero-wait MGB1 batch packer — the client-side sibling of the box's
// dnsdist/src/doh.rs Batcher, with the bounds tightened for a stub:
//
//   * arriving queries join whatever is already queued; whoever flips
//     `dispatching` becomes the dispatcher and carries the first batch;
//   * no flush timer: under low load a "batch" is a single query and this
//     degenerates to plain single-query mode (zero added latency);
//   * the ceiling is FIXED at 8 slots per container; AIMD still applies
//     within [1, 8] — double on a clean round trip, halve on any transport
//     failure, floor 1 switches batching off until the sky clears.
//
// Slot order IS answer order: mgb1 containers come back positionally, so the
// dispatcher hands each pending its own slot and patches nothing here.
use crate::upstream::UpErr;
use std::sync::Mutex;
use tokio::sync::oneshot;

/// (receiver for this query, optional drain handed to the dispatcher)
pub type BatchEnter = (
    oneshot::Receiver<Result<Vec<u8>, UpErr>>,
    Option<Vec<Pending>>,
);

/// AIMD bounds for the packer. Start small, grow to the fixed ceiling of 8.
pub const BATCH_MIN: usize = 1;
/// Hard per-container slot ceiling for this client (box allows up to 64).
pub const BATCH_MAX: usize = 8;
const BATCH_INIT: usize = 2;

/// One query waiting for its container to come back.
pub struct Pending {
    pub msg: Vec<u8>,
    pub tx: oneshot::Sender<Result<Vec<u8>, UpErr>>,
}

pub struct Batcher {
    state: Mutex<BatchState>,
}

struct BatchState {
    pending: Vec<Pending>,
    dispatching: bool,
    cap: usize,
}

impl Batcher {
    pub fn new() -> Self {
        Batcher {
            state: Mutex::new(BatchState {
                pending: Vec::new(),
                dispatching: false,
                cap: BATCH_INIT,
            }),
        }
    }

    /// Enqueue this query. The caller that flips `dispatching` becomes the
    /// dispatcher and receives the first batch (older queries first, its own
    /// last). Everyone else just awaits their receiver.
    pub fn enter(&self, msg: Vec<u8>) -> BatchEnter {
        let (tx, rx) = oneshot::channel();
        let mut st = self.state.lock().unwrap();
        if st.dispatching {
            st.pending.push(Pending { msg, tx });
            return (rx, None);
        }
        st.dispatching = true;
        let take = (st.cap - 1).min(st.pending.len());
        let mut batch: Vec<Pending> = st.pending.drain(..take).collect();
        batch.push(Pending { msg, tx });
        (rx, Some(batch))
    }

    /// Dispatcher hand-off after each round trip: next batch to send, or
    /// release the duty when the queue is dry. `ok` drives AIMD.
    pub fn next_batch(&self, ok: bool) -> Option<Vec<Pending>> {
        let mut st = self.state.lock().unwrap();
        if ok {
            if st.cap < BATCH_MAX {
                st.cap = (st.cap * 2).min(BATCH_MAX);
            }
        } else if st.cap > BATCH_MIN {
            st.cap /= 2;
        }
        if st.pending.is_empty() {
            st.dispatching = false;
            None
        } else {
            let n = st.cap.min(st.pending.len());
            Some(st.pending.drain(..n).collect())
        }
    }

    /// Current AIMD window (test introspection).
    #[cfg(test)]
    pub fn cap(&self) -> usize {
        self.state.lock().unwrap().cap
    }

    /// Queue depth while a dispatcher holds the duty (test introspection).
    #[cfg(test)]
    pub fn queued(&self) -> usize {
        self.state.lock().unwrap().pending.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aimd_grows_to_fixed_ceiling_and_floors_at_one() {
        let b = Batcher::new();
        assert_eq!(b.cap(), BATCH_INIT);
        assert_eq!(BATCH_MAX, 8, "spec: fixed batch ceiling of 8");
        b.next_batch(true);
        b.next_batch(true);
        assert_eq!(b.cap(), BATCH_INIT * 4);
        for _ in 0..10 {
            b.next_batch(true);
        }
        assert_eq!(b.cap(), BATCH_MAX, "growth saturates at 8");
        b.next_batch(false);
        b.next_batch(false);
        assert_eq!(b.cap(), BATCH_MAX / 4);
        for _ in 0..20 {
            b.next_batch(false);
        }
        assert_eq!(b.cap(), BATCH_MIN, "shrink floors at single-query mode");
    }

    #[tokio::test]
    async fn dispatcher_duty_hands_off_and_releases() {
        let b = Batcher::new();
        let (_rx, first) = b.enter(b"q1".to_vec());
        assert!(first.is_some(), "first enter must dispatch");
        drop(first);
        // second query while duty held: queued, no drain handed out
        let (_rx2, none) = b.enter(b"q2".to_vec());
        assert!(none.is_none());
        assert_eq!(b.queued(), 1);
        // duty held: the queued q2 is handed over on the next drain
        let handoff = b.next_batch(false);
        assert_eq!(handoff.as_ref().map(|v| v.len()), Some(1));
        // queue dry: duty released
        assert!(b.next_batch(false).is_none());
        // and a fresh enter takes over again
        let (_rx3, again) = b.enter(b"q3".to_vec());
        assert!(again.is_some());
    }

    #[tokio::test]
    async fn drain_never_exceeds_the_ceiling() {
        let b = Batcher::new();
        // saturate growth first so cap sits at BATCH_MAX
        for _ in 0..10 {
            b.next_batch(true);
        }
        let (_rx, _duty) = b.enter(b"head".to_vec());
        // pile up far more than the ceiling while duty is held
        for i in 0..30 {
            b.enter(vec![b'q', i]);
        }
        assert_eq!(b.queued(), 30);
        let total: usize = std::iter::from_fn(|| b.next_batch(true))
            .map(|batch| {
                assert!(batch.len() <= BATCH_MAX, "batch of {}", batch.len());
                batch.len()
            })
            .sum();
        // the head query rode out inside `_duty`; only the 30 queued ones drain
        assert_eq!(total, 30);
        assert!(b.next_batch(true).is_none(), "duty released when dry");
    }

    #[test]
    fn first_batch_is_older_queries_then_the_trigger() {
        let b = Batcher::new();
        for _ in 0..10 {
            b.next_batch(true); // cap → 8
        }
        // simulate a busy instant: queries queue behind a held duty
        let (_r0, none) = {
            // hold duty manually via an initial enter that we drop below
            b.enter(b"seed".to_vec())
        };
        assert!(none.is_some(), "seed query becomes the dispatcher");
        for i in 0..12 {
            b.enter(vec![i as u8]);
        }
        let first = b.next_batch(true).unwrap();
        assert_eq!(
            first.len(),
            BATCH_MAX,
            "dispatcher drains up to cap after growth"
        );
        // oldest queued queries leave first (FIFO)
        assert_eq!(first[0].msg, vec![0u8]);
        assert_eq!(first[1].msg, vec![1u8]);
    }
}
