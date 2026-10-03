//! Linux command confinement and seccomp policy generation.

mod bwrap;
mod fallback_policy;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub(crate) mod generation;
pub(crate) mod seccomp;

pub(crate) use bwrap::{PreparedLaunch, embedded_command, prepare_launch};
pub(crate) const DEFAULT_POLICY: &[u8] = fallback_policy::BPF;

use super::{Access, Grant};
use std::path::Path;

pub(super) fn host_runtime_grants() -> Vec<Grant> {
    let mut grants = vec![Grant::new("/dev/kvm", Access::Device)];
    for path in [
        "/etc/resolv.conf",
        "/etc/hosts",
        "/etc/nsswitch.conf",
        "/etc/localtime",
    ] {
        if Path::new(path).exists() {
            grants.push(Grant::new(path, Access::ReadOnly));
        }
    }
    grants
}
