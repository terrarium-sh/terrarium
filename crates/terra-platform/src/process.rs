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
    VmChildGuard, attach_vm_child, claim_ipc, detach, kill_vm_child, pass_ipc, supervise_vm_child,
};
