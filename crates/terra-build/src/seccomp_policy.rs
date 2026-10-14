//! The checked-in syscall allowlist format: one file per Rust target, one entry per role.

use crate::seccomp::Role;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Where the policy files live, relative to the terra-sandbox crate.
const POLICY_DIRECTORY: &str = "src/linux/policy";

/// One role's allowed syscalls by name, and the `ioctl` requests it may issue.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RolePolicy {
    pub syscalls: BTreeSet<String>,
    pub ioctls: BTreeSet<u32>,
}

/// Every role's policy for one target.
pub type Policy = BTreeMap<Role, RolePolicy>;

/// The policy file for `target`, given the terra-sandbox crate's manifest directory.
#[must_use]
pub fn policy_path(sandbox_manifest_directory: &Path, target: &str) -> PathBuf {
    sandbox_manifest_directory
        .join(POLICY_DIRECTORY)
        .join(format!("{target}.json"))
}

pub fn read_policy(path: &Path, target: &str) -> Result<Policy, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| format!("reading {}: {error}; run `make policy`", path.display()))?;
    parse_policy(&text, target).map_err(|error| format!("{}: {error}", path.display()))
}

pub fn parse_policy(text: &str, target: &str) -> Result<Policy, String> {
    let document: serde_json::Value =
        serde_json::from_str(text).map_err(|error| error.to_string())?;
    if document["target"] != target {
        return Err(format!("policy is not for {target}"));
    }
    Role::ALL
        .iter()
        .map(|&role| {
            let entry = &document["roles"][role.name()];
            let syscalls = entry["syscalls"]
                .as_array()
                .ok_or_else(|| format!("{} lists no syscalls", role.name()))?
                .iter()
                .map(|name| name.as_str().map(str::to_owned))
                .collect::<Option<BTreeSet<_>>>()
                .ok_or_else(|| format!("{} syscall names must be strings", role.name()))?;
            let ioctls = entry["ioctls"]
                .as_array()
                .ok_or_else(|| format!("{} lists no ioctls", role.name()))?
                .iter()
                .map(|request| {
                    request
                        .as_str()
                        .and_then(|request| request.strip_prefix("0x"))
                        .and_then(|request| u32::from_str_radix(request, 16).ok())
                })
                .collect::<Option<BTreeSet<_>>>()
                .ok_or_else(|| format!("{} ioctl requests must be 0x-prefixed hex", role.name()))?;
            Ok((role, RolePolicy { syscalls, ioctls }))
        })
        .collect()
}

/// Renders `policy` deterministically, so regeneration diffs cleanly.
#[must_use]
pub fn render_policy(target: &str, policy: &Policy) -> String {
    let roles: serde_json::Map<_, _> = policy
        .iter()
        .map(|(role, policy)| {
            let ioctls: Vec<_> = policy
                .ioctls
                .iter()
                .map(|request| format!("{request:#010x}"))
                .collect();
            (
                role.name().to_owned(),
                serde_json::json!({"syscalls": policy.syscalls, "ioctls": ioctls}),
            )
        })
        .collect();
    let document = serde_json::json!({
        "generated_by": "make policy",
        "target": target,
        "roles": roles,
    });
    let mut text = serde_json::to_string_pretty(&document).unwrap_or_default();
    text.push('\n');
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rendered_policy_round_trips_and_names_its_target() {
        let policy = Policy::from([
            (
                Role::Supervisor,
                RolePolicy {
                    syscalls: ["read", "ioctl"].map(str::to_owned).into(),
                    ioctls: [0x5413].into(),
                },
            ),
            (Role::Vm, RolePolicy::default()),
            (
                Role::Network,
                RolePolicy {
                    syscalls: ["write".to_owned()].into(),
                    ioctls: BTreeSet::new(),
                },
            ),
        ]);
        let text = render_policy("x86_64-unknown-linux-musl", &policy);
        assert!(text.contains("\"0x00005413\""));
        assert_eq!(
            parse_policy(&text, "x86_64-unknown-linux-musl").unwrap(),
            policy
        );
        assert!(parse_policy(&text, "aarch64-unknown-linux-musl").is_err());
    }
}
