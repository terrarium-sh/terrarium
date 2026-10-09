use std::collections::{BTreeMap, BTreeSet};

use super::Workload;
use anyhow::{Context, Result, bail, ensure};
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};
use serde::Deserialize;
use serde_json::{Value, json};
use terra_sandbox::Role;

enum Architecture {
    X86_64,
    Aarch64,
}

fn resolve_architecture(target: &str) -> Result<Architecture> {
    match target {
        "x86_64-unknown-linux-musl" | "x86_64-unknown-linux-gnu" => Ok(Architecture::X86_64),
        "aarch64-unknown-linux-musl" | "aarch64-unknown-linux-gnu" => Ok(Architecture::Aarch64),
        _ => bail!("unsupported seccomp policy target: {target}"),
    }
}

impl Architecture {
    fn resolve_syscall_name(&self, number: u32) -> Result<&'static str> {
        let number = usize::try_from(number)?;
        match self {
            Self::X86_64 => syscalls::x86_64::Sysno::new(number).map(|syscall| syscall.name()),
            Self::Aarch64 => syscalls::aarch64::Sysno::new(number).map(|syscall| {
                if syscall == syscalls::aarch64::Sysno::fstatat {
                    "newfstatat"
                } else {
                    syscall.name()
                }
            }),
        }
        .with_context(|| format!("unknown target syscall number: {number}"))
    }

    fn resolve_syscall_number(&self, name: &str) -> Result<u32> {
        let number = match self {
            Self::X86_64 => name
                .parse::<syscalls::x86_64::Sysno>()
                .map(|syscall| syscall.id()),
            Self::Aarch64 => {
                let name = if name == "newfstatat" {
                    "fstatat"
                } else {
                    name
                };
                name.parse::<syscalls::aarch64::Sysno>()
                    .map(|syscall| syscall.id())
            }
        }
        .ok()
        .with_context(|| format!("unknown target syscall: {name}"))?;
        Ok(u32::try_from(number)?)
    }

    fn resolve_compiler_target(&self) -> TargetArch {
        match self {
            Self::X86_64 => TargetArch::x86_64,
            Self::Aarch64 => TargetArch::aarch64,
        }
    }
}

pub(super) const SUPPLEMENT_VERSION: u32 = 1;

#[derive(Deserialize)]
struct Supplement {
    version: u32,
    rules: Vec<SupplementRule>,
}

#[derive(Deserialize)]
struct SupplementRule {
    syscall: String,
    targets: Vec<String>,
    reason: String,
    source: String,
    requests: Option<Vec<u32>>,
    roles: Vec<Role>,
}

fn read_supplement() -> Result<Supplement> {
    let supplement: Supplement = serde_json::from_str(include_str!(
        "../../../../../scripts/seccomp/seccomp-supplements.json"
    ))
    .context("reading bundled seccomp supplements")?;
    ensure!(
        supplement.version == SUPPLEMENT_VERSION,
        "unsupported seccomp supplement version"
    );
    for rule in &supplement.rules {
        ensure!(
            !rule.reason.trim().is_empty()
                && !rule.source.trim().is_empty()
                && !rule.targets.is_empty()
                && !rule.roles.is_empty(),
            "supplement lacks review provenance"
        );
        if rule.syscall == "ioctl" {
            ensure!(
                rule.requests
                    .as_ref()
                    .is_some_and(|requests| !requests.is_empty()),
                "supplemental ioctl requires a nonempty request allowlist"
            );
        } else {
            ensure!(
                rule.requests.is_none(),
                "request restrictions only apply to ioctl"
            );
        }
        for target in &rule.targets {
            resolve_architecture(target)?.resolve_syscall_number(&rule.syscall)?;
        }
    }
    Ok(supplement)
}

pub(super) fn build_policy(
    calls: &BTreeMap<u32, BTreeSet<u32>>,
    ioctls: &BTreeMap<u32, BTreeSet<u32>>,
    target: &str,
    workload: &Workload<'_>,
    role: Role,
) -> Result<Value> {
    let architecture = resolve_architecture(target)?;
    let supplement = read_supplement()?;
    let mut provenance = BTreeMap::<&str, Vec<Value>>::new();
    for (&number, processes) in calls {
        ensure!(
            !processes.is_empty(),
            "observed syscall has no traced process"
        );
        let name = architecture.resolve_syscall_name(number)?;
        if role_denies_syscall(role, name) {
            continue;
        }
        provenance
            .entry(name)
            .or_default()
            .push(json!({"kind": "observed", "processes": processes.len()}));
    }
    let ioctl_number = architecture.resolve_syscall_number("ioctl")?;
    ensure!(
        ioctls.is_empty() || calls.contains_key(&ioctl_number),
        "observed ioctl requests lack an observed ioctl syscall"
    );
    ensure!(
        ioctls.values().all(|processes| !processes.is_empty()),
        "observed ioctl request has no traced process"
    );
    let mut requests: BTreeSet<u32> = ioctls.keys().copied().collect();
    for rule in &supplement.rules {
        if !rule.targets.iter().any(|rule_target| rule_target == target)
            || !rule.roles.contains(&role)
        {
            continue;
        }
        let mut source = json!({
            "kind": "supplement", "reason": rule.reason, "source": rule.source,
        });
        if let Some(extra_requests) = &rule.requests {
            requests.extend(extra_requests);
            source["requests"] = json!(extra_requests);
        }
        provenance.entry(&rule.syscall).or_default().push(source);
    }
    let rules: Vec<Value> = provenance
        .into_iter()
        .map(|(name, sources)| {
            let mut syscall_rule = json!({"syscall": name, "provenance": sources});
            if name == "ioctl" {
                syscall_rule["requests"] = json!(requests);
            }
            if name == "socket"
                && let Some(families) = socket_families(role)
            {
                syscall_rule["families"] = json!(families);
            }
            if name == "sendto" && role == Role::Vm {
                syscall_rule["connected_only"] = json!(true);
            }
            if name == "prctl" && role != Role::Supervisor {
                syscall_rule["preserve_parent_death"] = json!(true);
            }
            syscall_rule
        })
        .collect();
    Ok(json!({
        "format_version": 1,
        "role": role,
        "target": target,
        "default_action": "kill_process",
        "supplement_version": supplement.version,
        "rules": rules,
        "workload_coverage": {
            "scope": workload.scope,
            "traced": [workload.name],
            "enforced_only": workload.enforced_only,
        },
    }))
}

/// `AF_UNIX` for the VM; only IP for the broker, whose host network namespace would otherwise
/// expose abstract Unix sockets (such as the user's X11 display) and host netlink.
const fn socket_families(role: Role) -> Option<&'static [u32]> {
    match role {
        Role::Supervisor => None,
        Role::Vm => Some(&[1]),
        Role::Network => Some(&[2, 10]),
    }
}

fn role_denies_syscall(role: Role, syscall: &str) -> bool {
    match role {
        Role::Supervisor => false,
        Role::Vm => matches!(
            syscall,
            "connect"
                | "sendmsg"
                | "sendmmsg"
                | "setsid"
                | "setpgid"
                | "io_uring_setup"
                | "io_uring_enter"
                | "io_uring_register"
        ),
        Role::Network => matches!(
            syscall,
            "setsid" | "setpgid" | "io_uring_setup" | "io_uring_enter" | "io_uring_register"
        ),
    }
}

#[derive(Deserialize)]
struct PolicyRule {
    syscall: String,
    requests: Option<Vec<u32>>,
    families: Option<Vec<u32>>,
    #[serde(default)]
    connected_only: bool,
    #[serde(default)]
    preserve_parent_death: bool,
}

pub(super) fn compile_bpf(policy: &Value) -> Result<Vec<u8>> {
    ensure!(
        policy["format_version"] == 1,
        "unsupported seccomp policy format"
    );
    ensure!(
        policy["default_action"] == "kill_process",
        "seccomp default must kill the process"
    );
    ensure!(
        policy["supplement_version"] == SUPPLEMENT_VERSION,
        "unsupported seccomp supplement version"
    );
    let target = policy["target"]
        .as_str()
        .context("policy target is missing")?;
    let architecture = resolve_architecture(target)?;
    let rules: Vec<PolicyRule> =
        serde_json::from_value(policy["rules"].clone()).context("reading seccomp policy rules")?;
    ensure!(!rules.is_empty(), "seccomp policy has no rules");
    let mut filter_rules = BTreeMap::new();
    for rule in rules {
        let number = architecture.resolve_syscall_number(&rule.syscall)?;
        ensure!(
            !filter_rules.contains_key(&i64::from(number)),
            "policy repeats syscall {}",
            rule.syscall
        );
        let syscall_rules = compile_syscall_rules(rule)?;
        filter_rules.insert(i64::from(number), syscall_rules);
    }
    let filter = SeccompFilter::new(
        filter_rules,
        SeccompAction::KillProcess,
        SeccompAction::Allow,
        architecture.resolve_compiler_target(),
    )
    .context("building seccomp filter")?;
    let instructions = BpfProgram::try_from(filter).context("compiling seccomp filter")?;
    Ok(terra_sandbox::seccomp::encode_bpf(&instructions))
}

fn compile_syscall_rules(rule: PolicyRule) -> Result<Vec<SeccompRule>> {
    ensure!(
        !rule.connected_only || rule.syscall == "sendto",
        "connected-only restrictions apply to sendto"
    );
    ensure!(
        !rule.preserve_parent_death || rule.syscall == "prctl",
        "parent-death restrictions apply to prctl"
    );
    let syscall_rules = if rule.syscall == "ioctl" {
        ensure!(
            rule.families.is_none(),
            "socket family restrictions only apply to socket"
        );
        let allowlist = rule
            .requests
            .context("ioctl requires a request allowlist")?;
        ensure!(
            !allowlist.is_empty(),
            "ioctl requires a nonempty request allowlist"
        );
        let requests: BTreeSet<_> = allowlist.into_iter().collect();
        requests
            .into_iter()
            .map(compile_ioctl_rule)
            .collect::<Result<Vec<_>>>()?
    } else if rule.syscall == "socket"
        && let Some(families) = &rule.families
    {
        ensure!(
            rule.requests.is_none() && !families.is_empty(),
            "invalid socket family allowlist"
        );
        families
            .iter()
            .map(|family| {
                Ok(SeccompRule::new(vec![SeccompCondition::new(
                    0,
                    SeccompCmpArgLen::Dword,
                    SeccompCmpOp::Eq,
                    u64::from(*family),
                )?])?)
            })
            .collect::<Result<Vec<_>>>()?
    } else if rule.connected_only {
        ensure!(
            rule.requests.is_none() && rule.families.is_none(),
            "invalid sendto restrictions"
        );
        vec![SeccompRule::new(vec![
            SeccompCondition::new(4, SeccompCmpArgLen::Qword, SeccompCmpOp::Eq, 0)?,
            SeccompCondition::new(5, SeccompCmpArgLen::Qword, SeccompCmpOp::Eq, 0)?,
        ])?]
    } else if rule.preserve_parent_death {
        ensure!(
            rule.requests.is_none() && rule.families.is_none(),
            "invalid prctl restrictions"
        );
        vec![SeccompRule::new(vec![SeccompCondition::new(
            0,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::Ne,
            1,
        )?])?]
    } else {
        ensure!(
            rule.requests.is_none() && rule.families.is_none(),
            "request restrictions only apply to ioctl"
        );
        Vec::new()
    };
    Ok(syscall_rules)
}

/// Terminal-injection requests: a worker shares the host session, so `/dev/tty` would reach the user's shell.
const TERMINAL_INJECTION_IOCTLS: [u32; 2] = [0x5412, 0x541c];

fn compile_ioctl_rule(request: u32) -> Result<SeccompRule> {
    ensure!(
        !TERMINAL_INJECTION_IOCTLS.contains(&request),
        "seccomp policy allows terminal-injection ioctl {request:#x} (TIOCSTI/TIOCLINUX); remove it"
    );
    Ok(SeccompRule::new(vec![SeccompCondition::new(
        1,
        SeccompCmpArgLen::Dword,
        SeccompCmpOp::Eq,
        u64::from(request),
    )?])?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A traced, supplemented or hand-written bundle can never allow injecting
    /// input into the host terminal the workers share.
    #[test]
    fn terminal_injection_ioctls_never_compile() {
        for request in TERMINAL_INJECTION_IOCTLS {
            let error = compile_ioctl_rule(request).unwrap_err().to_string();
            assert!(error.contains("terminal-injection"), "{error}");
        }
        compile_ioctl_rule(0xae01).unwrap();
    }

    const KILL_PROCESS: u32 = 0x8000_0000;
    const ALLOW: u32 = 0x7fff_0000;

    fn host_workload() -> Workload<'static> {
        Workload {
            name: "self_test.host_components",
            scope: "host_components",
            vm_validated: false,
            enforced_only: &[],
        }
    }

    fn evaluate_filter(filter: &[u8], number: u32, audit: u32, request: u64) -> Result<u32> {
        evaluate_filter_arguments(filter, number, audit, [0, request, 0, 0, 0, 0])
    }

    fn evaluate_filter_arguments(
        filter: &[u8],
        number: u32,
        audit: u32,
        arguments: [u64; 6],
    ) -> Result<u32> {
        let mut data = [0_u8; 64];
        data[..4].copy_from_slice(&number.to_le_bytes());
        data[4..8].copy_from_slice(&audit.to_le_bytes());
        for (index, argument) in arguments.into_iter().enumerate() {
            data[16 + index * 8..24 + index * 8].copy_from_slice(&argument.to_le_bytes());
        }
        let mut accumulator = 0;
        let mut index = 0;
        for _ in 0..filter.len() / 8 {
            let instruction = filter
                .get(index * 8..index * 8 + 8)
                .context("BPF jumps outside filter")?;
            let code = u16::from_le_bytes(instruction[..2].try_into()?);
            let value = u32::from_le_bytes(instruction[4..].try_into()?);
            let yes = usize::from(instruction[2]);
            let no = usize::from(instruction[3]);
            index += 1;
            match code {
                0x20 => {
                    let offset = usize::try_from(value)?;
                    accumulator = u32::from_le_bytes(data[offset..offset + 4].try_into()?);
                }
                0x05 => index += usize::try_from(value)?,
                0x15 => index += if accumulator == value { yes } else { no },
                0x06 => return Ok(value),
                _ => bail!("unsupported BPF instruction: {code:#x}"),
            }
        }
        bail!("BPF did not return an action")
    }

    #[test]
    fn role_policies_keep_network_sockets_and_kvm_operations_separate() -> Result<()> {
        for target in ["x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl"] {
            let architecture = resolve_architecture(target)?;
            let audit = match architecture {
                Architecture::X86_64 => 0xc000_003e,
                Architecture::Aarch64 => 0xc000_00b7,
            };
            let socket = architecture.resolve_syscall_number("socket")?;
            let ioctl = architecture.resolve_syscall_number("ioctl")?;
            let calls = BTreeMap::from([(socket, BTreeSet::from([12]))]);
            let vm = build_policy(&calls, &BTreeMap::new(), target, &host_workload(), Role::Vm)?;
            let network = build_policy(
                &calls,
                &BTreeMap::new(),
                target,
                &host_workload(),
                Role::Network,
            )?;
            let vm_filter = compile_bpf(&vm)?;
            let network_filter = compile_bpf(&network)?;
            for family in [0, 1, 2, 10, 16, u32::MAX] {
                assert_eq!(
                    evaluate_filter_arguments(
                        &vm_filter,
                        socket,
                        audit,
                        [u64::from(family), 0, 0, 0, 0, 0],
                    )?,
                    if family == 1 { ALLOW } else { KILL_PROCESS }
                );
                assert_eq!(
                    evaluate_filter_arguments(
                        &network_filter,
                        socket,
                        audit,
                        [u64::from(family), 0, 0, 0, 0, 0],
                    )?,
                    if matches!(family, 2 | 10) {
                        ALLOW
                    } else {
                        KILL_PROCESS
                    }
                );
            }
            assert_eq!(evaluate_filter(&vm_filter, ioctl, audit, 0xae01)?, ALLOW);
            assert_eq!(
                evaluate_filter(&network_filter, ioctl, audit, 0xae01)?,
                KILL_PROCESS
            );
            assert!(
                network["rules"]
                    .as_array()
                    .context("missing network rules")?
                    .iter()
                    .all(|rule| rule["syscall"] != "fallocate")
            );
        }
        Ok(())
    }

    #[test]
    fn worker_policies_deny_pathname_networking_and_lifetime_evasion() -> Result<()> {
        for target in ["x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl"] {
            let architecture = resolve_architecture(target)?;
            let audit = match architecture {
                Architecture::X86_64 => 0xc000_003e,
                Architecture::Aarch64 => 0xc000_00b7,
            };
            let forbidden = [
                ("connect", true, false),
                ("sendmsg", true, false),
                ("sendmmsg", true, false),
                ("setsid", true, true),
                ("setpgid", true, true),
                ("io_uring_setup", true, true),
                ("io_uring_enter", true, true),
                ("io_uring_register", true, true),
            ];
            let calls = forbidden
                .into_iter()
                .map(|(name, _, _)| name)
                .chain(["sendto", "prctl", "read"])
                .map(|name| {
                    Ok((
                        architecture.resolve_syscall_number(name)?,
                        BTreeSet::from([12]),
                    ))
                })
                .collect::<Result<BTreeMap<_, _>>>()?;
            for role in Role::ALL {
                let document =
                    build_policy(&calls, &BTreeMap::new(), target, &host_workload(), role)?;
                let filter = compile_bpf(&document)?;
                for (name, vm_denied, network_denied) in forbidden {
                    let denied = match role {
                        Role::Supervisor => false,
                        Role::Vm => vm_denied,
                        Role::Network => network_denied,
                    };
                    assert_eq!(
                        evaluate_filter(
                            &filter,
                            architecture.resolve_syscall_number(name)?,
                            audit,
                            0
                        )?,
                        if denied { KILL_PROCESS } else { ALLOW }
                    );
                }
                let sendto = architecture.resolve_syscall_number("sendto")?;
                for (address, length) in
                    [(0_u64, 0_u64), (1, 0), (1 << 32, 0), (0, 1), (0, 1 << 32)]
                {
                    assert_eq!(
                        evaluate_filter_arguments(
                            &filter,
                            sendto,
                            audit,
                            [0, 0, 0, 0, address, length]
                        )?,
                        if role == Role::Vm && (address != 0 || length != 0) {
                            KILL_PROCESS
                        } else {
                            ALLOW
                        }
                    );
                }
                let prctl = architecture.resolve_syscall_number("prctl")?;
                for option in [0, 1, 15, 40, u32::MAX] {
                    assert_eq!(
                        evaluate_filter_arguments(
                            &filter,
                            prctl,
                            audit,
                            [u64::from(option), 0, 0, 0, 0, 0]
                        )?,
                        if role != Role::Supervisor && option == 1 {
                            KILL_PROCESS
                        } else {
                            ALLOW
                        }
                    );
                }
            }
        }
        Ok(())
    }

    fn make_policy(target: &str, requests: &[u32]) -> Value {
        json!({
            "format_version": 1,
            "supplement_version": SUPPLEMENT_VERSION,
            "default_action": "kill_process",
            "target": target,
            "rules": [
                {"syscall": "read"},
                {"syscall": "exit_group"},
                {"syscall": "ioctl", "requests": requests},
            ],
        })
    }

    #[test]
    fn bpf_enforces_architecture_syscalls_and_masked_ioctl_requests() -> Result<()> {
        for target in ["x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl"] {
            let architecture = resolve_architecture(target)?;
            let audit = match architecture {
                Architecture::X86_64 => 0xc000_003e,
                Architecture::Aarch64 => 0xc000_00b7,
            };
            let read_number = architecture.resolve_syscall_number("read")?;
            let exit_number = architecture.resolve_syscall_number("exit_group")?;
            let ioctl_number = architecture.resolve_syscall_number("ioctl")?;
            let requests = [0, 0x89ab_cdef, u32::MAX];
            let filter = compile_bpf(&make_policy(target, &requests))?;
            for number in (0..512).chain([u32::MAX, 0x4000_0000, 0x4000_0000 | read_number]) {
                for request in [
                    0_u64,
                    1,
                    0x89ab_cdef,
                    0xffff_ffff,
                    0x1234_5678_89ab_cdef,
                    0xffff_ffff_0000_0001,
                ] {
                    let is_allowed = number == read_number
                        || number == exit_number
                        || number == ioctl_number
                            && requests.contains(&u32::try_from(request & 0xffff_ffff)?);
                    assert_eq!(
                        evaluate_filter(&filter, number, audit, request)?,
                        if is_allowed { ALLOW } else { KILL_PROCESS },
                        "{target} syscall {number}, ioctl request {request:#x}"
                    );
                    for wrong_audit in [0, 0x4000_0003, audit ^ 1] {
                        assert_eq!(
                            evaluate_filter(&filter, number, wrong_audit, request)?,
                            KILL_PROCESS
                        );
                    }
                }
            }
        }
        Ok(())
    }

    #[test]
    fn supplements_keep_review_provenance_and_workload_coverage() -> Result<()> {
        for target in [
            "x86_64-unknown-linux-musl",
            "aarch64-unknown-linux-musl",
            "x86_64-unknown-linux-gnu",
            "aarch64-unknown-linux-gnu",
        ] {
            let architecture = resolve_architecture(target)?;
            let calls = BTreeMap::from([
                (
                    architecture.resolve_syscall_number("read")?,
                    BTreeSet::from([12, 34]),
                ),
                (
                    architecture.resolve_syscall_number("ioctl")?,
                    BTreeSet::from([12]),
                ),
            ]);
            let ioctls = BTreeMap::from([(0x89ab_cdef, BTreeSet::from([12]))]);
            let validations = [crate::sandbox::policy::Validation {
                name: "self_test.built_in_guest",
                reason: "Validate guest execution without broadening the host policy.",
            }];
            let workload = Workload {
                enforced_only: &validations,
                ..host_workload()
            };
            let policy = build_policy(&calls, &ioctls, target, &workload, Role::Vm)?;
            assert_eq!(policy["workload_coverage"]["scope"], "host_components");
            assert_eq!(
                policy["workload_coverage"]["traced"],
                json!(["self_test.host_components"])
            );
            assert_eq!(
                policy["workload_coverage"]["enforced_only"][0]["name"],
                "self_test.built_in_guest"
            );
            let rules = policy["rules"].as_array().context("missing rules")?;
            let mut previous_name = "";
            for rule in rules {
                let name = rule["syscall"].as_str().context("missing syscall")?;
                assert!(name > previous_name);
                previous_name = name;
                let sources = rule["provenance"]
                    .as_array()
                    .context("missing provenance")?;
                assert_ne!(sources.as_slice(), [] as [serde_json::Value; 0]);
                for source in sources {
                    if source["kind"] == "supplement" {
                        assert_ne!(source["reason"].as_str().context("missing reason")?, "");
                        assert_ne!(source["source"].as_str().context("missing source")?, "");
                    }
                }
                if name == "read" {
                    assert_eq!(sources, &[json!({"kind": "observed", "processes": 2})]);
                }
                if name == "ioctl" {
                    assert!(
                        rule["requests"]
                            .as_array()
                            .context("missing requests")?
                            .contains(&json!(0x89ab_cdef_u32))
                    );
                }
            }
            compile_bpf(&policy)?;
            let foreground = build_policy(
                &calls,
                &ioctls,
                target,
                &Workload {
                    name: "workload.foreground",
                    scope: "guest",
                    vm_validated: true,
                    enforced_only: &[],
                },
                Role::Vm,
            )?;
            assert_eq!(foreground["workload_coverage"]["scope"], "guest");
            assert_eq!(
                foreground["workload_coverage"]["traced"],
                json!(["workload.foreground"])
            );
            assert_eq!(foreground["workload_coverage"]["enforced_only"], json!([]));
        }
        Ok(())
    }

    #[test]
    fn syscall_library_matches_native_libc_numbers() -> Result<()> {
        let architecture = resolve_architecture(env!("TERRA_BUILD_TARGET"))?;
        for (name, number) in [
            ("read", libc::SYS_read),
            ("ioctl", libc::SYS_ioctl),
            ("clone", libc::SYS_clone),
            ("execve", libc::SYS_execve),
            ("rt_sigreturn", libc::SYS_rt_sigreturn),
            ("sched_yield", libc::SYS_sched_yield),
            ("exit_group", libc::SYS_exit_group),
            ("newfstatat", libc::SYS_newfstatat),
        ] {
            assert_eq!(
                architecture.resolve_syscall_number(name)?,
                u32::try_from(number)?
            );
            assert_eq!(
                architecture.resolve_syscall_name(u32::try_from(number)?)?,
                name
            );
        }
        Ok(())
    }

    #[test]
    fn stat_syscall_keeps_canonical_policy_name_on_both_architectures() -> Result<()> {
        for target in ["x86_64-unknown-linux-musl", "aarch64-unknown-linux-musl"] {
            let architecture = resolve_architecture(target)?;
            let number = u32::try_from(match architecture {
                Architecture::X86_64 => syscalls::x86_64::Sysno::newfstatat.id(),
                Architecture::Aarch64 => syscalls::aarch64::Sysno::fstatat.id(),
            })?;
            assert_eq!(architecture.resolve_syscall_number("newfstatat")?, number);
            assert_eq!(architecture.resolve_syscall_name(number)?, "newfstatat");
            let policy = build_policy(
                &BTreeMap::from([(number, BTreeSet::from([12]))]),
                &BTreeMap::new(),
                target,
                &host_workload(),
                Role::Vm,
            )?;
            let rules = policy["rules"].as_array().context("missing rules")?;
            assert!(rules.iter().any(|rule| rule["syscall"] == "newfstatat"));
            assert!(rules.iter().all(|rule| rule["syscall"] != "fstatat"));
            compile_bpf(&policy)?;
        }
        Ok(())
    }

    #[test]
    fn compiler_rejects_invalid_policy_and_instruction_overflow() -> Result<()> {
        let target = "x86_64-unknown-linux-musl";
        let requests: Vec<u32> = (0..815).collect();
        let filter = compile_bpf(&make_policy(target, &requests))?;
        assert!(filter.len() / 8 < 4096);
        assert!(compile_bpf(&make_policy(target, &(0..816).collect::<Vec<_>>())).is_err());
        for rules in [
            json!([]),
            json!([{"syscall": "not_a_syscall"}]),
            json!([{"syscall": "read"}, {"syscall": "read"}]),
            json!([{"syscall": "read", "requests": [1]}]),
            json!([{"syscall": "ioctl"}]),
            json!([{"syscall": "ioctl", "requests": []}]),
            json!([{"syscall": "ioctl", "requests": [-1]}]),
            json!([{"syscall": "ioctl", "requests": [0x1_0000_0000_u64]}]),
            json!([{"syscall": "read", "families": [1]}]),
            json!([{"syscall": "socket", "families": []}]),
            json!([{"syscall": "socket", "families": [-1]}]),
            json!([{"syscall": "socket", "families": [0x1_0000_0000_u64]}]),
            json!([{"syscall": "ioctl", "requests": [1], "families": [1]}]),
            json!([{"syscall": "read", "connected_only": true}]),
            json!([{"syscall": "read", "preserve_parent_death": true}]),
        ] {
            let mut policy = make_policy(target, &[1]);
            policy["rules"] = rules;
            assert!(compile_bpf(&policy).is_err());
        }
        for (field, value) in [
            ("format_version", json!(2)),
            ("supplement_version", json!(2)),
            ("default_action", json!("allow")),
            ("target", json!("x86_64-pc-windows-msvc")),
        ] {
            let mut policy = make_policy(target, &[1]);
            policy[field] = value;
            assert!(compile_bpf(&policy).is_err());
        }
        let calls = BTreeMap::from([(u32::MAX, BTreeSet::from([12]))]);
        assert!(
            build_policy(&calls, &BTreeMap::new(), target, &host_workload(), Role::Vm).is_err()
        );
        Ok(())
    }
}
