//! Child-process handoff and supervision.

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
pub use unix::{
    VmChildGuard, attach_vm_child, claim_ipc, detach, kill_vm_child, pass_descriptor, pass_ipc,
    supervise_vm_child,
};
#[cfg(windows)]
pub use windows::{
    IPC_HANDLE_VARIABLES, LISTENER_HANDLE_VARIABLES, LOCK_HANDLE_VARIABLE, VmChildGuard,
    attach_vm_child, claim_ipc, claim_socket, detach, handle_variable, inherited_handle,
    initialize_winsock, kill_vm_child, pass_handle, pass_ipc, set_inheritable,
    spawn_without_standard_handles, supervise_vm_child,
};

/// Environment a host sandbox sets on the worker it launches, which the worker reads back.
pub mod sandbox_env {
    pub const ROLE: &str = "TERRA_SANDBOX_ROLE";
    pub const VM_ROLE: &str = "vm";

    /// Whether a host sandbox launched this process as its VM worker.
    #[must_use]
    pub fn is_vm_worker() -> bool {
        std::env::var_os(ROLE).is_some_and(|role| role == VM_ROLE)
    }
}
