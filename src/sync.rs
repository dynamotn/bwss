//! Small helpers for `std::sync` primitives.

use std::sync::{Mutex, MutexGuard, PoisonError};

/// Locks `m`. A panic in another thread while it held the lock does not
/// make the data unusable here: every guarded value stays valid after any
/// single update, so the poisoned guard is taken over.
pub fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}
