//! Linux vCPU interrupt and thread-id publication.

#![allow(unsafe_code)]

use std::sync::{Arc, Mutex, OnceLock};

unsafe extern "C" fn kick_handler(_signal: libc::c_int) {}

pub(crate) fn install_kick_handler() -> Result<(), std::io::Error> {
    static RESULT: OnceLock<Result<(), i32>> = OnceLock::new();
    RESULT
        .get_or_init(|| unsafe {
            // SAFETY: SIGUSR1 uses an async-signal-safe no-op handler without SA_RESTART, making
            // KVM_RUN return EINTR instead of terminating the process.
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = kick_handler as *const () as usize;
            if libc::sigemptyset(std::ptr::addr_of_mut!(action.sa_mask)) != 0 {
                return Err(std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EINVAL));
            }
            action.sa_flags = 0;
            if libc::sigaction(
                libc::SIGUSR1,
                std::ptr::addr_of!(action),
                std::ptr::null_mut(),
            ) != 0
            {
                return Err(std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EINVAL));
            }
            Ok(())
        })
        .as_ref()
        .map_err(|errno| std::io::Error::from_raw_os_error(*errno))
        .copied()
}

pub(crate) fn unblock_kick_signal() -> Result<(), std::io::Error> {
    // SAFETY: the mask is local to this runner thread and SIGUSR1 is Terra's KVM kick.
    unsafe {
        let mut signals: libc::sigset_t = std::mem::zeroed();
        if libc::sigemptyset(std::ptr::addr_of_mut!(signals)) != 0
            || libc::sigaddset(std::ptr::addr_of_mut!(signals), libc::SIGUSR1) != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        let error = libc::pthread_sigmask(
            libc::SIG_UNBLOCK,
            std::ptr::addr_of!(signals),
            std::ptr::null_mut(),
        );
        if error != 0 {
            return Err(std::io::Error::from_raw_os_error(error));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn unblock_kick_signal_clears_an_inherited_mask() {
        // SAFETY: this test restores the calling thread's original signal mask.
        unsafe {
            let mut signals: libc::sigset_t = std::mem::zeroed();
            assert_eq!(libc::sigemptyset(std::ptr::addr_of_mut!(signals)), 0);
            assert_eq!(
                libc::sigaddset(std::ptr::addr_of_mut!(signals), libc::SIGUSR1),
                0
            );
            let mut original: libc::sigset_t = std::mem::zeroed();
            assert_eq!(
                libc::pthread_sigmask(
                    libc::SIG_BLOCK,
                    std::ptr::addr_of!(signals),
                    std::ptr::addr_of_mut!(original),
                ),
                0
            );
            super::unblock_kick_signal().expect("unblock SIGUSR1");
            let mut current: libc::sigset_t = std::mem::zeroed();
            assert_eq!(
                libc::pthread_sigmask(
                    libc::SIG_SETMASK,
                    std::ptr::null(),
                    std::ptr::addr_of_mut!(current),
                ),
                0
            );
            assert_eq!(
                libc::sigismember(std::ptr::addr_of!(current), libc::SIGUSR1),
                0
            );
            assert_eq!(
                libc::pthread_sigmask(
                    libc::SIG_SETMASK,
                    std::ptr::addr_of!(original),
                    std::ptr::null_mut(),
                ),
                0
            );
        }
    }
}

fn kick(pthread: usize) {
    if pthread == 0 {
        return;
    }
    // SAFETY: PthreadPublication holds its mutex while reading this live thread id and clears it
    // before the runner can exit, so a reused pthread id cannot be signaled.
    unsafe {
        libc::pthread_kill(pthread as libc::pthread_t, libc::SIGUSR1);
    }
}

pub(crate) fn self_pthread_id() -> usize {
    // SAFETY: reading the current thread id is always valid.
    #[cfg(target_env = "gnu")]
    let id = usize::try_from(unsafe { libc::pthread_self() }).unwrap_or(0);
    #[cfg(not(target_env = "gnu"))]
    let id = unsafe { libc::pthread_self() } as usize;
    id
}

#[derive(Clone)]
pub(crate) struct PthreadPublication(Arc<Mutex<Option<usize>>>);

#[must_use]
pub(crate) struct PublishedPthread(PthreadPublication);

impl PthreadPublication {
    pub(crate) fn new() -> Self {
        Self(Arc::new(Mutex::new(None)))
    }

    pub(crate) fn publish(&self) -> PublishedPthread {
        *self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(self_pthread_id());
        PublishedPthread(self.clone())
    }

    pub(crate) fn clear(&self) {
        *self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }

    pub(crate) fn kick(&self) {
        let publication = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(pthread) = *publication {
            kick(pthread);
        }
    }

    #[cfg(test)]
    pub(crate) fn is_published(&self) -> bool {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_some()
    }
}

impl Drop for PublishedPthread {
    fn drop(&mut self) {
        self.0.clear();
    }
}
