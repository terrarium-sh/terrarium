use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::process::{CommandExt as _, ExitStatusExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, ExitStatus};

use anyhow::{Context as _, Result, ensure};
use serde::{Deserialize, Serialize};
use terra_sandbox::Role;

#[derive(Default, Deserialize, Serialize)]
pub(super) struct Trace {
    pub calls: BTreeMap<u32, BTreeSet<u32>>,
    pub ioctls: BTreeMap<u32, BTreeSet<u32>>,
    pub exec_count: usize,
    pub process_count: usize,
    #[serde(default)]
    pub roles: BTreeMap<Role, RoleTrace>,
}

#[derive(Default, Deserialize, Serialize)]
pub(super) struct RoleTrace {
    pub calls: BTreeMap<u32, BTreeSet<u32>>,
    pub ioctls: BTreeMap<u32, BTreeSet<u32>>,
    pub exec_count: usize,
}

#[repr(C)]
#[derive(Default)]
struct SyscallEntry {
    operation: u8,
    padding: [u8; 3],
    architecture: u32,
    instruction_pointer: u64,
    stack_pointer: u64,
    number: u64,
    arguments: [u64; 6],
}

struct Tracer {
    active_processes: BTreeSet<libc::pid_t>,
    initial_stops: BTreeSet<libc::pid_t>,
    seen_processes: BTreeSet<libc::pid_t>,
    executable: PathBuf,
    roles: BTreeMap<libc::pid_t, Option<Role>>,
    trace: Trace,
}

pub(super) fn run(command: &mut Command, output: &Path) -> Result<ExitCode> {
    let executable = std::fs::canonicalize(command.get_program())
        .context("resolving executable for syscall tracing")?;
    enable_child_tracing(command);
    let child = command.spawn().context("starting syscall trace")?;
    let root_pid = libc::pid_t::try_from(child.id())?;
    let mut tracer = Tracer {
        active_processes: BTreeSet::from([root_pid]),
        initial_stops: BTreeSet::new(),
        seen_processes: BTreeSet::from([root_pid]),
        executable,
        roles: BTreeMap::from([(root_pid, None)]),
        trace: Trace::default(),
    };
    let (_, initial_status) = wait_process(root_pid)?;
    ensure!(
        libc::WIFSTOPPED(initial_status) && libc::WSTOPSIG(initial_status) == libc::SIGTRAP,
        "executable did not stop at the initial exec boundary"
    );
    let options = libc::PTRACE_O_TRACESYSGOOD
        | libc::PTRACE_O_TRACEFORK
        | libc::PTRACE_O_TRACEVFORK
        | libc::PTRACE_O_TRACECLONE
        | libc::PTRACE_O_TRACEEXEC
        | libc::PTRACE_O_EXITKILL;
    trace_request(
        libc::PTRACE_SETOPTIONS,
        root_pid,
        0,
        usize::try_from(options)?,
    )?;
    tracer.trace.exec_count = 1;
    tracer.classify_exec(root_pid)?;
    tracer.record_call(root_pid, u32::try_from(libc::SYS_execve)?, None);
    resume_process(root_pid, 0)?;
    let status = tracer.collect(root_pid)?;
    tracer.trace.process_count = tracer.seen_processes.len();
    std::fs::write(output, serde_json::to_vec_pretty(&tracer.trace)?)
        .with_context(|| format!("writing syscall trace {}", output.display()))?;
    let code = status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0));
    Ok(ExitCode::from(crate::exit_status_byte(code)))
}

impl Tracer {
    fn collect(&mut self, root_pid: libc::pid_t) -> Result<ExitStatus> {
        let mut root_status = None;
        while !self.active_processes.is_empty() {
            let (pid, status) = wait_process(-1)?;
            if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
                self.active_processes.remove(&pid);
                self.initial_stops.remove(&pid);
                if pid == root_pid {
                    root_status = Some(ExitStatus::from_raw(status));
                }
                continue;
            }
            ensure!(
                libc::WIFSTOPPED(status),
                "unexpected syscall trace wait status"
            );
            let signal = libc::WSTOPSIG(status);
            let event = status >> 16;
            let is_new_process = self.seen_processes.insert(pid);
            self.active_processes.insert(pid);
            if signal == (libc::SIGTRAP | 0x80) {
                self.record_syscall(pid)?;
                resume_process(pid, 0)?;
            } else if signal == libc::SIGTRAP && event != 0 {
                self.record_event(pid, event)?;
                resume_process(pid, 0)?;
            } else if signal == libc::SIGSTOP && (self.initial_stops.remove(&pid) || is_new_process)
            {
                resume_process(pid, 0)?;
            } else {
                resume_process(pid, signal)?;
            }
        }
        root_status.context("syscall trace did not capture the workload exit status")
    }

    fn record_event(&mut self, pid: libc::pid_t, event: i32) -> Result<()> {
        let mut event_pid: libc::c_ulong = 0;
        trace_request(
            libc::PTRACE_GETEVENTMSG,
            pid,
            0,
            (&raw mut event_pid) as usize,
        )?;
        let event_pid = libc::pid_t::try_from(event_pid)?;
        if event == libc::PTRACE_EVENT_FORK
            || event == libc::PTRACE_EVENT_VFORK
            || event == libc::PTRACE_EVENT_CLONE
        {
            self.active_processes.insert(event_pid);
            self.roles
                .insert(event_pid, self.roles.get(&pid).copied().flatten());
            if self.seen_processes.insert(event_pid) {
                self.initial_stops.insert(event_pid);
            }
        } else if event == libc::PTRACE_EVENT_EXEC {
            // A nonleader thread takes the process leader's PID when exec replaces the thread group.
            if event_pid != pid {
                self.active_processes.remove(&event_pid);
                self.initial_stops.remove(&event_pid);
                if let Some(role) = self.roles.remove(&event_pid) {
                    self.roles.insert(pid, role);
                }
            }
            self.classify_exec(pid)?;
            self.trace.exec_count += 1;
        } else {
            anyhow::bail!("unexpected ptrace event {event}");
        }
        Ok(())
    }

    fn classify_exec(&mut self, pid: libc::pid_t) -> Result<()> {
        if std::fs::read_link(format!("/proc/{pid}/exe"))? != self.executable {
            return Ok(());
        }
        let arguments = std::fs::read(format!("/proc/{pid}/cmdline"))?;
        let entrypoint = arguments.split(|byte| *byte == 0).nth(1);
        let identified = identify_entrypoint_role(entrypoint);
        let inherited = self.roles.get(&pid).copied().flatten();
        let role = inherit_exec_role(identified, inherited);
        self.roles.insert(pid, role);
        if let Some(role) = role.filter(|role| Some(*role) == identified) {
            self.trace.roles.entry(role).or_default().exec_count += 1;
        }
        Ok(())
    }

    fn record_syscall(&mut self, pid: libc::pid_t) -> Result<()> {
        const GET_SYSCALL_INFO: libc::c_uint = 0x420e;
        #[cfg(target_arch = "x86_64")]
        const NATIVE_ARCHITECTURE: u32 = 0xc000_003e;
        #[cfg(target_arch = "aarch64")]
        const NATIVE_ARCHITECTURE: u32 = 0xc000_00b7;
        let mut entry = SyscallEntry::default();
        let available = trace_request(
            GET_SYSCALL_INFO,
            pid,
            size_of::<SyscallEntry>(),
            (&raw mut entry) as usize,
        )
        .context("reading syscall entry; tracing requires Linux 5.3 or newer")?;
        if entry.operation != 1 {
            return Ok(());
        }
        ensure!(
            usize::try_from(available)? >= size_of::<SyscallEntry>(),
            "kernel returned an incomplete syscall entry"
        );
        ensure!(
            entry.architecture == NATIVE_ARCHITECTURE,
            "workload used an unsupported syscall architecture"
        );
        let number = u32::try_from(entry.number)?;
        #[cfg(target_arch = "x86_64")]
        ensure!(
            number & 0x4000_0000 == 0,
            "workload used the x32 syscall ABI"
        );
        let request = (entry.number == u64::try_from(libc::SYS_ioctl)?)
            .then(|| u32::try_from(entry.arguments[1] & u64::from(u32::MAX)))
            .transpose()?;
        self.record_call(pid, number, request);
        Ok(())
    }

    fn record_call(&mut self, pid: libc::pid_t, number: u32, request: Option<u32>) {
        if let Some(role) = self.roles.get(&pid).copied().flatten() {
            let observed = self.trace.roles.entry(role).or_default();
            observed
                .calls
                .entry(number)
                .or_default()
                .insert(pid.unsigned_abs());
            if let Some(request) = request {
                observed
                    .ioctls
                    .entry(request)
                    .or_default()
                    .insert(pid.unsigned_abs());
            }
        }
        let pid = pid.unsigned_abs();
        self.trace.calls.entry(number).or_default().insert(pid);
        if let Some(request) = request {
            self.trace.ioctls.entry(request).or_default().insert(pid);
        }
    }
}

fn identify_entrypoint_role(entrypoint: Option<&[u8]>) -> Option<Role> {
    use crate::vm::{boot, supervisor};

    let entrypoint = std::ffi::OsStr::from_bytes(entrypoint?);
    if entrypoint == supervisor::SUPERVISOR_ARG {
        Some(Role::Supervisor)
    } else if [
        boot::VM_PROCESS_FLAG_ARG,
        supervisor::VM_SELF_TEST_ARG,
        supervisor::VM_NATIVE_PROBE_ARG,
    ]
    .contains(&entrypoint.to_str()?)
    {
        Some(Role::Vm)
    } else if [
        supervisor::NETWORK_ARG,
        supervisor::NETWORK_NATIVE_PROBE_ARG,
    ]
    .contains(&entrypoint.to_str()?)
    {
        Some(Role::Network)
    } else {
        None
    }
}

fn inherit_exec_role(identified: Option<Role>, inherited: Option<Role>) -> Option<Role> {
    match inherited {
        Some(Role::Vm | Role::Network) => inherited,
        Some(Role::Supervisor) | None => identified.or(inherited),
    }
}

impl Drop for Tracer {
    fn drop(&mut self) {
        if self.active_processes.is_empty() {
            return;
        }
        for &pid in &self.active_processes {
            kill_process(pid);
        }
        while let Ok((pid, status)) = wait_process(-1) {
            if libc::WIFSTOPPED(status) {
                kill_process(pid);
                let _ = resume_process(pid, libc::SIGKILL);
            }
        }
    }
}

#[allow(unsafe_code)]
fn enable_child_tracing(command: &mut Command) {
    // SAFETY: The child callback invokes only ptrace and obtains errno on failure, without allocating or locking.
    unsafe {
        command.pre_exec(|| trace_request(libc::PTRACE_TRACEME, 0, 0, 0).map(|_| ()));
    }
}

#[allow(unsafe_code)]
fn trace_request(
    request: impl Into<libc::c_long>,
    pid: libc::pid_t,
    address: usize,
    data: usize,
) -> io::Result<libc::c_long> {
    let request = request.into();
    // SAFETY: ptrace interprets the arguments according to request; output pointers refer to live caller buffers.
    let result = unsafe { libc::syscall(libc::SYS_ptrace, request, pid, address, data) };
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

fn resume_process(pid: libc::pid_t, signal: i32) -> io::Result<()> {
    trace_request(
        libc::PTRACE_SYSCALL,
        pid,
        0,
        usize::try_from(signal).map_err(io::Error::other)?,
    )
    .map(|_| ())
}

#[allow(unsafe_code)]
fn wait_process(pid: libc::pid_t) -> io::Result<(libc::pid_t, i32)> {
    loop {
        let mut status = 0;
        // SAFETY: status is writable and waitpid is restricted to children owned by the calling tracing thread.
        let result =
            unsafe { libc::waitpid(pid, &raw mut status, libc::__WALL | libc::__WNOTHREAD) };
        if result >= 0 {
            return Ok((result, status));
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

#[allow(unsafe_code)]
fn kill_process(pid: libc::pid_t) {
    // SAFETY: kill receives a positive child PID and a valid signal.
    unsafe { libc::kill(pid, libc::SIGKILL) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Stdio;
    use std::sync::atomic::{AtomicBool, Ordering};

    const CHILD_MODE: &str = "TERRA_NATIVE_SYSCALL_TRACE_TEST";
    const CHILD_TEST: &str = "sandbox::generation::trace::tests::native_child";
    const IOCTL_REQUEST: u32 = 0x1234_5678;
    static SIGNAL_DELIVERED: AtomicBool = AtomicBool::new(false);

    #[test]
    fn verified_entrypoints_classify_workers_without_relabelling_confined_descendants() {
        use crate::vm::{boot, supervisor};

        for (entrypoint, role) in [
            (supervisor::SUPERVISOR_ARG, Role::Supervisor),
            (boot::VM_PROCESS_FLAG_ARG, Role::Vm),
            (supervisor::VM_SELF_TEST_ARG, Role::Vm),
            (supervisor::VM_NATIVE_PROBE_ARG, Role::Vm),
            (supervisor::NETWORK_ARG, Role::Network),
            (supervisor::NETWORK_NATIVE_PROBE_ARG, Role::Network),
        ] {
            assert_eq!(
                identify_entrypoint_role(Some(entrypoint.as_bytes())),
                Some(role)
            );
            assert_eq!(inherit_exec_role(Some(role), None), Some(role));
            assert_eq!(
                inherit_exec_role(Some(role), Some(Role::Supervisor)),
                Some(role)
            );
            for confined in [Role::Vm, Role::Network] {
                assert_eq!(
                    inherit_exec_role(Some(role), Some(confined)),
                    Some(confined)
                );
            }
        }
        for entrypoint in [
            None,
            Some(b"self-test".as_slice()),
            Some(b"__network_fake"),
            Some(b"\xff"),
        ] {
            assert_eq!(identify_entrypoint_role(entrypoint), None);
            assert_eq!(inherit_exec_role(None, None), None);
            for inherited in Role::ALL {
                assert_eq!(inherit_exec_role(None, Some(inherited)), Some(inherited));
            }
        }
    }

    fn child_command(mode: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", CHILD_TEST])
            .env(CHILD_MODE, mode)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command
    }

    #[test]
    fn traces_threads_forks_execs_and_ioctl_low_word() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("trace.json");
        let result = run(&mut child_command("tree"), &output).unwrap();
        assert_eq!(result, ExitCode::SUCCESS);
        let trace: Trace = serde_json::from_slice(&std::fs::read(output).unwrap()).unwrap();
        assert_eq!(trace.exec_count, 2);
        assert!(trace.process_count >= 6);
        assert_eq!(trace.ioctls[&IOCTL_REQUEST].len(), 3);
        assert!(trace.calls[&u32::try_from(libc::SYS_ioctl).unwrap()].len() >= 3);
    }

    #[test]
    fn captures_exit_failure_and_delivers_signals() {
        let directory = tempfile::tempdir().unwrap();
        for (mode, expected) in [("failure", 37), ("terminated", 143), ("signal", 0)] {
            let output = directory.path().join(mode);
            assert_eq!(
                run(&mut child_command(mode), &output).unwrap(),
                ExitCode::from(expected)
            );
            let trace: Trace = serde_json::from_slice(&std::fs::read(output).unwrap()).unwrap();
            assert!(!trace.calls.is_empty());
        }
    }

    #[test]
    fn follows_exec_from_a_nonleader_thread() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("trace.json");
        assert_eq!(
            run(&mut child_command("exec"), &output).unwrap(),
            ExitCode::SUCCESS
        );
        let trace: Trace = serde_json::from_slice(&std::fs::read(output).unwrap()).unwrap();
        assert_eq!(trace.exec_count, 2);
        assert_eq!(trace.ioctls[&IOCTL_REQUEST].len(), 1);
    }

    #[test]
    fn waits_for_descendants_after_the_root_exits() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("trace.json");
        assert_eq!(
            run(&mut child_command("orphan"), &output).unwrap(),
            ExitCode::SUCCESS
        );
        let trace: Trace = serde_json::from_slice(&std::fs::read(output).unwrap()).unwrap();
        assert_eq!(trace.ioctls[&IOCTL_REQUEST].len(), 1);
    }

    #[test]
    #[allow(unsafe_code)]
    fn native_child() {
        let Ok(mode) = std::env::var(CHILD_MODE) else {
            return;
        };
        match mode.as_str() {
            "leaf" => issue_ioctl(),
            "tree" => {
                std::thread::spawn(issue_ioctl).join().unwrap();
                // SAFETY: The fork child calls only async-signal-safe ioctl and _exit; the parent waits for its own child.
                unsafe {
                    let child = libc::fork();
                    assert!(child >= 0);
                    if child == 0 {
                        libc::syscall(libc::SYS_ioctl, -1, u64::from(IOCTL_REQUEST), 0);
                        libc::_exit(0);
                    }
                    let mut status = 0;
                    assert_eq!(libc::waitpid(child, &raw mut status, 0), child);
                    assert_eq!(status, 0);
                }
                assert!(child_command("leaf").status().unwrap().success());
            }
            "exec" => {
                std::thread::spawn(|| {
                    let error = child_command("leaf").exec();
                    panic!("exec failed: {error}");
                })
                .join()
                .unwrap();
            }
            "orphan" => {
                // SAFETY: The fork child calls only async-signal-safe nanosleep, ioctl, and _exit.
                unsafe {
                    let child = libc::fork();
                    assert!(child >= 0);
                    if child == 0 {
                        let delay = libc::timespec {
                            tv_sec: 0,
                            tv_nsec: 100_000_000,
                        };
                        libc::nanosleep(&raw const delay, std::ptr::null_mut());
                        libc::syscall(libc::SYS_ioctl, -1, u64::from(IOCTL_REQUEST), 0);
                        libc::_exit(0);
                    }
                }
            }
            "failure" => std::process::exit(37),
            "terminated" => {
                // SAFETY: SIGTERM is a valid signal and this child is expected to terminate.
                unsafe { libc::raise(libc::SIGTERM) };
                panic!("SIGTERM was suppressed");
            }
            "signal" => {
                // SAFETY: The handler has the required signal ABI and uses only an atomic operation.
                unsafe {
                    libc::signal(
                        libc::SIGUSR1,
                        receive_signal as *const () as libc::sighandler_t,
                    );
                    libc::raise(libc::SIGUSR1);
                }
                assert!(SIGNAL_DELIVERED.load(Ordering::Relaxed));
            }
            other => panic!("unknown trace test mode {other}"),
        }
    }

    extern "C" fn receive_signal(_signal: libc::c_int) {
        SIGNAL_DELIVERED.store(true, Ordering::Relaxed);
    }

    #[allow(unsafe_code)]
    fn issue_ioctl() {
        // SAFETY: The invalid descriptor makes ioctl fail without dereferencing its unused argument.
        unsafe {
            libc::syscall(
                libc::SYS_ioctl,
                -1,
                0xabcd_9876_0000_0000_u64 | u64::from(IOCTL_REQUEST),
                0,
            );
        }
    }
}
