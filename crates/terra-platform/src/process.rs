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
    pub const MACOS_ROLE: &str = "TERRA_MACOS_SANDBOX_ROLE";
    pub const WINDOWS_ROLE: &str = "TERRA_WINDOWS_SANDBOX_ROLE";
    pub const WINDOWS_MODE: &str = "TERRA_WINDOWS_SANDBOX_MODE";
    pub const VM_ROLE: &str = "vm";
    pub const APP_CONTAINER_MODE: &str = "app_container";

    /// Whether a macOS or Windows sandbox launched this process as its VM worker.
    #[must_use]
    pub fn is_vm_worker() -> bool {
        let role = if cfg!(target_os = "macos") {
            MACOS_ROLE
        } else if cfg!(windows) {
            WINDOWS_ROLE
        } else {
            return false;
        };
        std::env::var_os(role).is_some_and(|role| role == VM_ROLE)
    }
}
