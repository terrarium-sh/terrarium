//! Linux command confinement.

mod bwrap;
mod fallback_policy;
pub mod seccomp;

pub use bwrap::{PreparedLaunch, embedded_command, prepare_launch};
#[cfg(test)]
pub const DEFAULT_POLICY: &[u8] = fallback_policy::SUPERVISOR;

use super::{Access, Grant, Role};
use std::path::Path;

pub(super) fn role_grants(role: Role) -> Vec<Grant> {
    let paths: &[&str] = match role {
        Role::Supervisor => &[],
        Role::Vm => &["/dev/kvm", "/etc/localtime"],
        Role::Network => &["/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf"],
    };
    let mut grants = Vec::new();
    for path in paths {
        if Path::new(path).exists() {
            grants.push(Grant::new(
                *path,
                if *path == "/dev/kvm" {
                    Access::Device
                } else {
                    Access::ReadOnly
                },
            ));
        }
    }
    grants
}
