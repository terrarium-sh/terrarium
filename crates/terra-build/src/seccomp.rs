//! The seccomp filters terra embeds, compiled for any supported Linux target.

/// The kernel's limit: 4096 instructions of 8 bytes.
pub const MAX_FILTER_BYTES: usize = 4096 * 8;
const LOAD_WORD: u16 = 0x20;
const AND: u16 = 0x54;
const JUMP_EQUAL: u16 = 0x15;
const JUMP_BITS_SET: u16 = 0x45;
const RETURN: u16 = 0x06;
const KILL_PROCESS: u32 = 0x8000_0000;
const DENY_EPERM: u32 = 0x0005_0001;
const ALLOW: u32 = 0x7fff_0000;
const X32_SYSCALL_BIT: u32 = 0x4000_0000;
const SYSCALL_NUMBER: u32 = 0;
const AUDIT_ARCH: u32 = 4;
const FIRST_ARGUMENT: u32 = 16;
const SECOND_ARGUMENT: u32 = 24;
const PR_SET_PDEATHSIG: u32 = 1;
const AF_UNIX: u32 = 1;
const AF_INET: u32 = 2;
const AF_INET6: u32 = 10;
const KVM_IOCTL_TYPE: u32 = 0xae00;
const TIOCSTI: u32 = 0x5412;
const TIOCLINUX: u32 = 0x541c;

const DENIED_SYSCALLS: [&str; 12] = [
    "ptrace",
    "bpf",
    "perf_event_open",
    "kexec_load",
    "kexec_file_load",
    "init_module",
    "finit_module",
    "delete_module",
    "reboot",
    "add_key",
    "request_key",
    "keyctl",
];
const WORKER_DENIED_SYSCALLS: [&str; 5] = [
    "setsid",
    "setpgid",
    "io_uring_setup",
    "io_uring_enter",
    "io_uring_register",
];
const VM_DENIED_SYSCALLS: [&str; 3] = ["connect", "sendmsg", "sendmmsg"];
/// The supervisor binds every published listener before starting the broker.
const NETWORK_DENIED_SYSCALLS: [&str; 1] = ["listen"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Architecture {
    X86_64,
    Aarch64,
}

impl Architecture {
    /// Takes Cargo's `CARGO_CFG_TARGET_ARCH` and `CARGO_CFG_TARGET_ENDIAN` spellings.
    pub fn from_target(arch: &str, endian: &str) -> Result<Self, String> {
        if endian != "little" {
            return Err("VM execution requires a little-endian Linux target".into());
        }
        match arch {
            "x86_64" => Ok(Self::X86_64),
            "aarch64" => Ok(Self::Aarch64),
            _ => Err("VM execution requires Linux x86_64 or aarch64".into()),
        }
    }

    fn audit_arch(self) -> u32 {
        match self {
            Self::X86_64 => 0xc000_003e,
            Self::Aarch64 => 0xc000_00b7,
        }
    }

    /// The architecture a Rust target triple such as `x86_64-unknown-linux-musl` names.
    pub fn from_triple(triple: &str) -> Result<Self, String> {
        Self::from_target(triple.split('-').next().unwrap_or_default(), "little")
    }

    pub fn resolve_syscall_number(self, name: &str) -> Result<u32, String> {
        let number = match self {
            Self::X86_64 => name
                .parse::<syscalls::x86_64::Sysno>()
                .map(|syscall| syscall.id()),
            Self::Aarch64 => name
                .parse::<syscalls::aarch64::Sysno>()
                .map(|syscall| syscall.id()),
        }
        .map_err(|()| format!("unknown target syscall: {name}"))?;
        u32::try_from(number).map_err(|error| error.to_string())
    }

    #[must_use]
    pub fn name_syscall(self, number: u32) -> Option<&'static str> {
        let number = usize::try_from(number).ok()?;
        match self {
            Self::X86_64 => syscalls::x86_64::Sysno::new(number).map(|syscall| syscall.name()),
            Self::Aarch64 => syscalls::aarch64::Sysno::new(number).map(|syscall| syscall.name()),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    Supervisor,
    Vm,
    Network,
}

impl Role {
    pub const ALL: [Self; 3] = [Self::Supervisor, Self::Vm, Self::Network];

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Supervisor => "supervisor",
            Self::Vm => "vm",
            Self::Network => "network",
        }
    }
}

struct Filter {
    architecture: Architecture,
    bpf: Vec<u8>,
}

impl Filter {
    /// Starts a filter that kills any other architecture's or x32 syscall and loads the number.
    fn new(architecture: Architecture) -> Self {
        let mut filter = Self {
            architecture,
            bpf: Vec::new(),
        };
        filter.append(LOAD_WORD, 0, 0, AUDIT_ARCH);
        filter.append(JUMP_EQUAL, 1, 0, architecture.audit_arch());
        filter.append(RETURN, 0, 0, KILL_PROCESS);
        filter.append(LOAD_WORD, 0, 0, SYSCALL_NUMBER);
        if architecture == Architecture::X86_64 {
            filter.append(JUMP_BITS_SET, 0, 1, X32_SYSCALL_BIT);
            filter.append(RETURN, 0, 0, KILL_PROCESS);
        }
        filter
    }

    fn append(&mut self, code: u16, jump_true: u8, jump_false: u8, value: u32) {
        self.bpf.extend_from_slice(&code.to_le_bytes());
        self.bpf.extend_from_slice(&[jump_true, jump_false]);
        self.bpf.extend_from_slice(&value.to_le_bytes());
    }

    fn append_denied_syscalls(&mut self, names: &[&str]) -> Result<(), String> {
        for name in names {
            let syscall = self.architecture.resolve_syscall_number(name)?;
            self.append(JUMP_EQUAL, 0, 1, syscall);
            self.append(RETURN, 0, 0, DENY_EPERM);
        }
        Ok(())
    }
}

/// Returns the role's filter, which denies dangerous interfaces and enforces argument rules, as
/// little-endian `sock_filter` instructions.
pub fn compile_role_filter(architecture: Architecture, role: Role) -> Result<Vec<u8>, String> {
    let mut filter = Filter::new(architecture);
    filter.append_denied_syscalls(&DENIED_SYSCALLS)?;
    append_terminal_injection_rules(&mut filter)?;
    match role {
        Role::Supervisor => {}
        Role::Vm => {
            append_worker_rules(&mut filter)?;
            append_vm_rules(&mut filter)?;
        }
        Role::Network => {
            append_worker_rules(&mut filter)?;
            append_network_rules(&mut filter)?;
        }
    }
    filter.append(RETURN, 0, 0, ALLOW);
    Ok(filter.bpf)
}

/// Returns an allowlist that kills the process on any syscall, or `ioctl` request, `policy`
/// does not list. Argument rules stay in [`compile_role_filter`], which every role also installs.
pub fn compile_allowlist(
    architecture: Architecture,
    policy: &crate::seccomp_policy::RolePolicy,
) -> Result<Vec<u8>, String> {
    let mut filter = Filter::new(architecture);
    let ioctl = architecture.resolve_syscall_number("ioctl")?;
    // `ioctl` comes first: it carries `KVM_RUN`, the VM's hottest syscall, and argument rules
    // keep the kernel from caching its verdict.
    if policy.syscalls.contains("ioctl") {
        // Past the argument load, one compare and return per request, and the final kill.
        let skip = u8::try_from(2 * policy.ioctls.len() + 2)
            .map_err(|_| "too many ioctl requests for one filter".to_owned())?;
        filter.append(JUMP_EQUAL, 0, skip, ioctl);
        filter.append(LOAD_WORD, 0, 0, SECOND_ARGUMENT);
        for request in &policy.ioctls {
            filter.append(JUMP_EQUAL, 0, 1, *request);
            filter.append(RETURN, 0, 0, ALLOW);
        }
        filter.append(RETURN, 0, 0, KILL_PROCESS);
    } else if !policy.ioctls.is_empty() {
        return Err("ioctl requests listed without the ioctl syscall".into());
    }
    // The kernel itself issues `restart_syscall` to resume an interrupted sleep.
    let always_allowed = ["restart_syscall"];
    for name in policy
        .syscalls
        .iter()
        .map(String::as_str)
        .chain(always_allowed)
    {
        let syscall = architecture.resolve_syscall_number(name)?;
        if syscall != ioctl {
            filter.append(JUMP_EQUAL, 0, 1, syscall);
            filter.append(RETURN, 0, 0, ALLOW);
        }
    }
    filter.append(RETURN, 0, 0, KILL_PROCESS);
    if filter.bpf.len() > MAX_FILTER_BYTES {
        return Err("allowlist exceeds the kernel's 4096 BPF instructions".into());
    }
    Ok(filter.bpf)
}

/// Denies `TIOCSTI` and `TIOCLINUX`: a worker shares the host session (no `setsid`), so through
/// `/dev/tty` a compromised process could otherwise type commands into the user's shell.
fn append_terminal_injection_rules(filter: &mut Filter) -> Result<(), String> {
    let ioctl = filter.architecture.resolve_syscall_number("ioctl")?;
    filter.append(JUMP_EQUAL, 0, 4, ioctl);
    filter.append(LOAD_WORD, 0, 0, SECOND_ARGUMENT);
    filter.append(JUMP_EQUAL, 1, 0, TIOCSTI);
    filter.append(JUMP_EQUAL, 0, 1, TIOCLINUX);
    filter.append(RETURN, 0, 0, DENY_EPERM);
    filter.append(LOAD_WORD, 0, 0, SYSCALL_NUMBER);
    Ok(())
}

fn append_worker_rules(filter: &mut Filter) -> Result<(), String> {
    filter.append_denied_syscalls(&WORKER_DENIED_SYSCALLS)?;
    let prctl = filter.architecture.resolve_syscall_number("prctl")?;
    filter.append(JUMP_EQUAL, 0, 4, prctl);
    filter.append(LOAD_WORD, 0, 0, FIRST_ARGUMENT);
    filter.append(JUMP_EQUAL, 0, 1, PR_SET_PDEATHSIG);
    filter.append(RETURN, 0, 0, DENY_EPERM);
    filter.append(LOAD_WORD, 0, 0, SYSCALL_NUMBER);
    Ok(())
}

/// Denies outgoing sockets: `sendto` with a destination address and any non-Unix `socket`.
fn append_vm_rules(filter: &mut Filter) -> Result<(), String> {
    filter.append_denied_syscalls(&VM_DENIED_SYSCALLS)?;
    let sendto = filter.architecture.resolve_syscall_number("sendto")?;
    filter.append(JUMP_EQUAL, 0, 13, sendto);
    for destination_word in [48, 52, 56, 60] {
        filter.append(LOAD_WORD, 0, 0, destination_word);
        filter.append(JUMP_EQUAL, 1, 0, 0);
        filter.append(RETURN, 0, 0, DENY_EPERM);
    }
    filter.append(LOAD_WORD, 0, 0, SYSCALL_NUMBER);
    let socket = filter.architecture.resolve_syscall_number("socket")?;
    filter.append(JUMP_EQUAL, 0, 3, socket);
    filter.append(LOAD_WORD, 0, 0, FIRST_ARGUMENT);
    filter.append(JUMP_EQUAL, 1, 0, AF_UNIX);
    filter.append(RETURN, 0, 0, DENY_EPERM);
    Ok(())
}

/// Limits `socket` to IP: the broker shares the host network namespace, where `AF_UNIX` would reach
/// abstract sockets such as the user's X11 display.
fn append_network_rules(filter: &mut Filter) -> Result<(), String> {
    filter.append_denied_syscalls(&NETWORK_DENIED_SYSCALLS)?;
    let socket = filter.architecture.resolve_syscall_number("socket")?;
    filter.append(JUMP_EQUAL, 0, 5, socket);
    filter.append(LOAD_WORD, 0, 0, FIRST_ARGUMENT);
    filter.append(JUMP_EQUAL, 2, 0, AF_INET);
    filter.append(JUMP_EQUAL, 1, 0, AF_INET6);
    filter.append(RETURN, 0, 0, DENY_EPERM);
    filter.append(RETURN, 0, 0, ALLOW);
    let ioctl = filter.architecture.resolve_syscall_number("ioctl")?;
    filter.append(JUMP_EQUAL, 0, 4, ioctl);
    filter.append(LOAD_WORD, 0, 0, SECOND_ARGUMENT);
    filter.append(AND, 0, 0, 0xff00);
    filter.append(JUMP_EQUAL, 0, 1, KVM_IOCTL_TYPE);
    filter.append(RETURN, 0, 0, DENY_EPERM);
    Ok(())
}
