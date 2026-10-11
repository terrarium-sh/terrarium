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
    initialize_winsock, kill_vm_child, pass_handle, pass_ipc, set_inheritable, supervise_vm_child,
};
