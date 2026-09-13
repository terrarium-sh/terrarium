use std::sync::{Mutex, MutexGuard};

pub(crate) fn lock_or_abort<T: ?Sized>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(_) => std::process::abort(),
    }
}
