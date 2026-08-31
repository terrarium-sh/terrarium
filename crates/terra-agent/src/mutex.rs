use std::sync::{Mutex, MutexGuard, PoisonError};

pub(crate) fn lock_recover<T: ?Sized>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
