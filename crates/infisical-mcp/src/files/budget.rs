use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Shared ownership keeps an in-flight transfer charged after it leaves the map.
pub(super) struct ByteBudget {
    limit: usize,
    used: AtomicUsize,
}

impl ByteBudget {
    pub(super) fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            limit,
            used: AtomicUsize::new(0),
        })
    }

    pub(super) fn reserve(self: &Arc<Self>, bytes: usize) -> Option<ByteReservation> {
        self.used
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                used.checked_add(bytes).filter(|total| *total <= self.limit)
            })
            .ok()?;
        Some(ByteReservation {
            budget: Arc::clone(self),
            bytes,
        })
    }
}

pub(super) struct ByteReservation {
    budget: Arc<ByteBudget>,
    bytes: usize,
}

impl ByteReservation {
    /// Only release unused capacity; growing requires a new admission decision.
    pub(super) fn shrink(&mut self, bytes: usize) {
        assert!(bytes <= self.bytes, "byte reservation cannot grow");
        self.budget
            .used
            .fetch_sub(self.bytes - bytes, Ordering::Relaxed);
        self.bytes = bytes;
    }
}

impl Drop for ByteReservation {
    fn drop(&mut self) {
        self.budget.used.fetch_sub(self.bytes, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::ByteBudget;
    use std::sync::{Arc, Barrier};

    #[test]
    fn reservation_lifetime_and_shrink_preserve_capacity() {
        let budget = ByteBudget::new(10);
        let mut first = budget.reserve(8).unwrap();
        assert!(budget.reserve(3).is_none());
        first.shrink(5);
        let second = budget.reserve(5).unwrap();
        assert!(budget.reserve(1).is_none());
        drop(first);
        let replacement = budget.reserve(5).unwrap();
        drop(second);
        drop(replacement);
        assert!(budget.reserve(10).is_some());
    }

    #[test]
    fn concurrent_admission_cannot_overcommit() {
        let budget = ByteBudget::new(7);
        let barrier = Arc::new(Barrier::new(16));
        let attempts: Vec<_> = (0..16)
            .map(|_| {
                let budget = Arc::clone(&budget);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    let reservation = budget.reserve(1);
                    barrier.wait();
                    reservation
                })
            })
            .collect();
        let reservations: Vec<_> = attempts
            .into_iter()
            .filter_map(|attempt| attempt.join().unwrap())
            .collect();
        assert_eq!(reservations.len(), 7);
        assert!(budget.reserve(1).is_none());
        drop(reservations);
        assert!(budget.reserve(7).is_some());
    }

    #[test]
    fn addition_overflow_is_refused_without_losing_the_reservation() {
        let budget = ByteBudget::new(usize::MAX);
        let reservation = budget.reserve(usize::MAX).unwrap();
        assert!(budget.reserve(1).is_none());
        drop(reservation);
        assert!(budget.reserve(usize::MAX).is_some());
    }
}
