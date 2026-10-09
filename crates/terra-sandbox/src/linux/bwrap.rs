//! Bubblewrap confinement and child identity handoff.

use super::seccomp;
use crate::{Access, Grant, Launch, Role, SpawnedLaunch};
use anyhow::{Context, Result, ensure};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::Write;
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::Path;
use std::process::Command;
use std::sync::OnceLock;
use std::time::Duration;

const BWRAP: &[u8] = include_bytes!(env!("TERRA_BWRAP_BIN"));
static EMBEDDED_BWRAP: OnceLock<std::result::Result<OwnedFd, String>> = OnceLock::new();
const SECCOMP_FD: RawFd = 5;
const INFO_FD: RawFd = 6;
const WORKER_FLOOR_FD: RawFd = 10;

pub struct PreparedLaunch {
    pub command: Command,
    inherited_files: Vec<File>,
    identity: File,
}

impl PreparedLaunch {
    pub fn spawn(self, identity_timeout: Duration) -> Result<SpawnedLaunch> {
        let Self {
            mut command,
            inherited_files,
            identity,
        } = self;
        let spawned = command.spawn();
        drop((command, inherited_files));
        let mut child = spawned.context("starting Bubblewrap sandbox")?;
        match read_child_pid(identity, identity_timeout) {
            Ok(pid) => Ok(SpawnedLaunch { child, pid }),
            Err(error) => {
                let _ = terra_platform::process::kill_vm_child(&mut child);
                let _ = child.kill();
                let _ = child.wait();
                Err(error)
            }
        }
    }
}

fn create_embedded_bwrap() -> std::result::Result<OwnedFd, String> {
    use rustix::fs::{MemfdFlags, SealFlags, fcntl_add_seals, memfd_create};

    let flags = MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING;
    let fd = match memfd_create("terra-bwrap", flags | MemfdFlags::EXEC) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::INVAL) => memfd_create("terra-bwrap", flags)
            .map_err(|error| format!("creating Bubblewrap memfd: {error}"))?,
        Err(error) => return Err(format!("creating Bubblewrap memfd: {error}")),
    };
    let mut file = std::fs::File::from(fd);
    file.write_all(BWRAP)
        .map_err(|error| format!("writing embedded Bubblewrap: {error}"))?;
    fcntl_add_seals(
        &file,
        SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL,
    )
    .map_err(|error| format!("sealing embedded Bubblewrap: {error}"))?;
    rustix::io::fcntl_dupfd_cloexec(&file, 16)
        .map_err(|error| format!("reserving Bubblewrap descriptor: {error}"))
}

pub fn embedded_command() -> Result<Command> {
    let fd = EMBEDDED_BWRAP
        .get_or_init(create_embedded_bwrap)
        .as_ref()
        .map_err(|message| anyhow::anyhow!("{message}"))?
        .as_raw_fd();
    Ok(Command::new(format!("/proc/self/fd/{fd}")))
}

pub fn prepare_launch(launch: Launch<'_>) -> Result<PreparedLaunch> {
    let Launch {
        role,
        command,
        mut grants,
        die_with_parent,
        policy,
        staging_directory: _,
    } = launch;
    let executable = Path::new(command.get_program());
    ensure!(
        executable.is_absolute(),
        "the sandbox executable path must be absolute"
    );
    ensure_static_executable(executable)?;
    let directory = command.get_current_dir().unwrap_or(Path::new("/"));
    ensure!(
        directory.is_absolute(),
        "the sandbox working directory must be absolute"
    );
    for grant in &grants {
        ensure!(
            grant.path.is_absolute(),
            "sandbox grant {} is not absolute",
            grant.path.display()
        );
    }

    let mut cmd = embedded_command()?;
    restrict_environment(&mut cmd, &command);
    cmd.args([
        "--unshare-user",
        "--unshare-ipc",
        "--unshare-pid",
        "--unshare-uts",
        "--as-pid-1",
        "--disable-userns",
        "--cap-drop",
        "ALL",
        "--proc",
        "/proc",
    ]);
    match role {
        Role::Supervisor | Role::Vm => {
            cmd.args(["--dev", "/dev", "--tmpfs", "/tmp"]);
        }
        Role::Network => {
            cmd.args(["--dir", "/dev"]);
        }
    }
    if die_with_parent {
        cmd.arg("--die-with-parent");
    }
    if role == Role::Vm {
        cmd.arg("--unshare-net");
    }

    grants.sort_by_key(|grant| grant.path.components().count());
    append_mounts(&mut cmd, grants)?;
    let mut inherited_files = Vec::new();
    let worker_floor = match role {
        Role::Supervisor => None,
        Role::Vm => Some(super::fallback_policy::VM),
        Role::Network => Some(super::fallback_policy::NETWORK),
    };
    for (descriptor, policy) in [(WORKER_FLOOR_FD, worker_floor), (SECCOMP_FD, policy)] {
        let Some(policy) = policy else { continue };
        seccomp::validate_bpf(policy)?;
        let mut file = tempfile::tempfile().context("opening private seccomp policy")?;
        file.write_all(policy)?;
        file.rewind()?;
        let inherited = terra_platform::process::pass_descriptor(&mut cmd, &file, descriptor)?;
        inherited_files.push(inherited);
        cmd.arg("--add-seccomp-fd").arg(descriptor.to_string());
    }
    let (reader, writer) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)?;
    inherited_files.push(terra_platform::process::pass_descriptor(
        &mut cmd,
        &File::from(writer),
        INFO_FD,
    )?);
    cmd.arg("--info-fd").arg(INFO_FD.to_string());
    cmd.arg("--chdir")
        .arg(directory)
        .arg("--")
        .arg(executable)
        .args(command.get_args());
    Ok(PreparedLaunch {
        command: cmd,
        inherited_files,
        identity: File::from(reader),
    })
}

fn restrict_environment(command: &mut Command, grants: &Command) {
    command.env_clear();
    for (name, value) in grants.get_envs() {
        if let Some(value) = value {
            command.env(name, value);
        }
    }
}

#[allow(unsafe_code)]
fn append_mounts(cmd: &mut Command, mounts: Vec<Grant>) -> Result<()> {
    use std::os::unix::process::CommandExt;

    let mut directories = BTreeSet::new();
    for mount in &mounts {
        for ancestor in mount.path.ancestors().skip(1) {
            if ancestor != Path::new("/") {
                directories.insert(ancestor.to_path_buf());
            }
        }
    }
    let mut directories = directories.into_iter().collect::<Vec<_>>();
    directories.sort_by_key(|path| path.components().count());
    for directory in directories {
        cmd.arg("--dir").arg(directory);
    }
    let mut directories = Vec::new();
    for mount in mounts {
        if let Some(directory) = mount.directory {
            let directory = rustix::io::fcntl_dupfd_cloexec(&directory, 16)?;
            let option = match mount.access {
                Access::ReadOnly => "--ro-bind-fd",
                Access::ReadWrite => "--bind-fd",
                Access::Device => anyhow::bail!("device grants require a path"),
            };
            cmd.arg(option).arg(directory.as_raw_fd().to_string());
            directories.push(directory);
        } else {
            cmd.arg(match mount.access {
                Access::ReadOnly => "--ro-bind",
                Access::ReadWrite => "--bind",
                Access::Device => "--dev-bind",
            })
            .arg(&mount.path);
        }
        cmd.arg(&mount.path);
    }
    // SAFETY: fcntl is async-signal-safe; the closure owns the descriptors until spawn.
    unsafe {
        cmd.pre_exec(move || {
            for directory in &directories {
                rustix::io::fcntl_setfd(directory, rustix::io::FdFlags::empty())?;
            }
            Ok(())
        });
    }
    Ok(())
}

fn ensure_static_executable(path: &Path) -> Result<()> {
    let mut file = std::fs::File::open(path)
        .with_context(|| format!("opening sandbox executable {}", path.display()))?;
    let mut header = [0_u8; 64];
    file.read_exact(&mut header)
        .with_context(|| format!("reading ELF header of {}", path.display()))?;
    ensure!(
        &header[..6] == b"\x7fELF\x02\x01",
        "Bubblewrap requires a static 64-bit little-endian Linux executable"
    );
    let program_offset = u64::from_le_bytes(header[32..40].try_into()?);
    let program_size = u64::from(u16::from_le_bytes(header[54..56].try_into()?));
    let program_count = u64::from(u16::from_le_bytes(header[56..58].try_into()?));
    ensure!(
        program_size >= 4
            && program_offset
                .checked_add(program_size.saturating_mul(program_count))
                .is_some_and(|end| end <= file.metadata().map_or(0, |metadata| metadata.len())),
        "sandbox executable has invalid ELF program headers"
    );
    for index in 0..program_count {
        file.seek(SeekFrom::Start(program_offset + index * program_size))?;
        let mut program_type = [0_u8; 4];
        file.read_exact(&mut program_type)?;
        ensure!(
            u32::from_le_bytes(program_type) != 3,
            "Bubblewrap requires a static Linux executable; this executable needs a dynamic loader"
        );
    }
    Ok(())
}

fn read_child_pid(reader: File, timeout: Duration) -> Result<u32> {
    #[derive(serde::Deserialize)]
    struct ChildInfo {
        #[serde(rename = "child-pid")]
        child_pid: u32,
    }
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("sandbox-identity".into())
        .spawn(move || {
            let mut bytes = Vec::new();
            let result = reader
                .take(4097)
                .read_to_end(&mut bytes)
                .context("reading Bubblewrap child identity")
                .and_then(|_| {
                    ensure!(
                        bytes.len() <= 4096,
                        "Bubblewrap identity exceeds 4096 bytes"
                    );
                    let info = serde_json::from_slice::<ChildInfo>(&bytes)
                        .context("decoding Bubblewrap child identity")?;
                    ensure!(
                        info.child_pid > 0,
                        "Bubblewrap returned an invalid child PID"
                    );
                    Ok(info.child_pid)
                });
            let _ = sender.send(result);
        })
        .context("starting Bubblewrap identity reader")?;
    receiver
        .recv_timeout(timeout)
        .context("waiting for Bubblewrap child identity")?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn jail_environment_keeps_only_explicit_grants() {
        let mut grants = Command::new("/workload");
        grants.env("GRANTED", "value").env_remove("PROHIBITED");
        let mut probe = Command::new("/usr/bin/env");
        probe.env("HOST_SECRET", "secret");
        restrict_environment(&mut probe, &grants);
        let output = probe.output().unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"GRANTED=value\n");
    }

    fn write_static_elf(directory: &Path) -> PathBuf {
        let path = directory.join("static-executable");
        let mut elf = [0_u8; 64];
        elf[..6].copy_from_slice(b"\x7fELF\x02\x01");
        elf[32..40].copy_from_slice(&64_u64.to_le_bytes());
        elf[54..56].copy_from_slice(&4_u16.to_le_bytes());
        std::fs::write(&path, elf).unwrap();
        path
    }

    #[test]
    fn embedded_bwrap_is_sealed_static_and_runs_without_path() {
        let mut command = embedded_command().unwrap();
        ensure_static_executable(Path::new(command.get_program())).unwrap();
        let fd = EMBEDDED_BWRAP.get().unwrap().as_ref().unwrap();
        assert!(fd.as_raw_fd() >= 16);
        assert!(
            rustix::io::fcntl_getfd(fd)
                .unwrap()
                .contains(rustix::io::FdFlags::CLOEXEC)
        );
        assert!(
            rustix::fs::fcntl_get_seals(fd)
                .unwrap()
                .contains(rustix::fs::SealFlags::WRITE | rustix::fs::SealFlags::SEAL)
        );
        let output = command.arg("--version").env("PATH", "").output().unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).starts_with("bubblewrap "));
    }

    #[test]
    fn grants_are_ordered_and_restrictions_precede_literal_workload_arguments() {
        let root = tempfile::tempdir().unwrap();
        let box_dir = root.path().join("box");
        let share = root.path().join("share");
        let nested = share.join("nested");
        std::fs::create_dir_all(&box_dir).unwrap();
        std::fs::create_dir_all(&nested).unwrap();
        let recipe = box_dir.join("protected-file");
        std::fs::write(&recipe, "{}").unwrap();
        let executable = write_static_elf(root.path());
        let mut command = Command::new(&executable);
        command.args(["a b", "--seccomp", "$HOME"]);
        let mut parent = Grant::new(&share, Access::ReadWrite);
        parent.directory = Some(terra_platform::filesystem::open_share_root(&share).unwrap());
        let mut child = Grant::new(&nested, Access::ReadOnly);
        child.directory = Some(terra_platform::filesystem::open_share_root(&nested).unwrap());
        let launch = prepare_launch(Launch {
            role: Role::Vm,
            command,
            grants: vec![child, parent, Grant::new(&recipe, Access::ReadOnly)],
            die_with_parent: true,
            policy: Some(super::super::DEFAULT_POLICY),
            staging_directory: &std::env::temp_dir(),
        })
        .unwrap();
        let args = launch
            .command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        let parent = args
            .windows(3)
            .position(|args| args[0] == "--bind-fd" && args[2] == share.to_str().unwrap())
            .unwrap();
        let child = args
            .windows(3)
            .position(|args| args[0] == "--ro-bind-fd" && args[2] == nested.to_str().unwrap())
            .unwrap();
        let metadata = args
            .windows(3)
            .position(|args| {
                args == [
                    "--ro-bind",
                    recipe.to_str().unwrap(),
                    recipe.to_str().unwrap(),
                ]
            })
            .unwrap();
        assert!(parent < child && child < metadata);
        assert!(
            args.windows(2)
                .any(|args| args == ["--add-seccomp-fd", "5"])
        );
        assert!(
            args.windows(2)
                .any(|args| args == ["--add-seccomp-fd", "10"])
        );
        assert!(args.windows(2).any(|args| args == ["--info-fd", "6"]));
        assert!(args.iter().any(|arg| arg == "--unshare-pid"));
        assert!(!args.iter().any(|arg| arg == "--new-session"));
        assert!(args.iter().any(|arg| arg == "--unshare-net"));
        assert!(args.iter().any(|arg| arg == "--die-with-parent"));
        assert_eq!(
            &args[args.len() - 4..],
            [executable.to_str().unwrap(), "a b", "--seccomp", "$HOME"]
        );
        let mut dynamic = std::fs::read(&executable).unwrap();
        dynamic[56..58].copy_from_slice(&1_u16.to_le_bytes());
        dynamic.extend_from_slice(&3_u32.to_le_bytes());
        std::fs::write(&executable, dynamic).unwrap();
        assert!(ensure_static_executable(&executable).is_err());
    }

    #[test]
    fn broker_namespace_keeps_host_network_without_vm_devices_or_scratch() {
        let root = tempfile::tempdir().unwrap();
        let executable = write_static_elf(root.path());
        let command = Command::new(&executable);
        let mut grants = super::super::role_grants(Role::Network);
        assert!(grants.iter().all(|grant| grant.access == Access::ReadOnly));
        assert!(
            grants
                .iter()
                .all(|grant| grant.path != Path::new("/dev/kvm"))
        );
        grants.push(Grant::new(&executable, Access::ReadOnly));
        let launch = prepare_launch(Launch {
            role: Role::Network,
            command,
            grants,
            die_with_parent: true,
            policy: None,
            staging_directory: &std::env::temp_dir(),
        })
        .unwrap();
        let arguments = launch.command.get_args().collect::<Vec<_>>();
        for required in [
            "--unshare-user",
            "--unshare-pid",
            "--unshare-ipc",
            "--unshare-uts",
            "--disable-userns",
        ] {
            assert!(arguments.contains(&std::ffi::OsStr::new(required)));
        }
        for denied in [
            "--unshare-net",
            "--dev",
            "--tmpfs",
            "--dev-bind",
            "--bind",
            "--bind-fd",
        ] {
            assert!(!arguments.contains(&std::ffi::OsStr::new(denied)));
        }
    }

    #[test]
    fn share_descriptors_survive_exec_and_path_redirection() {
        let root = tempfile::tempdir().unwrap();
        let approved = root.path().join("approved");
        let private = root.path().join("private");
        std::fs::create_dir(&approved).unwrap();
        std::fs::create_dir(&private).unwrap();
        std::fs::write(approved.join("marker"), b"approved").unwrap();
        std::fs::write(private.join("marker"), b"private").unwrap();
        for readonly in [false, true] {
            let mut mount = Grant::new(
                &approved,
                if readonly {
                    Access::ReadOnly
                } else {
                    Access::ReadWrite
                },
            );
            mount.directory = Some(terra_platform::filesystem::open_share_root(&approved).unwrap());
            let mut cmd = Command::new("/bin/sh");
            cmd.args(["-c", "cat /proc/self/fd/$SHARE_FD/marker", "sh"]);
            append_mounts(&mut cmd, vec![mount]).unwrap();
            let args = cmd.get_args().collect::<Vec<_>>();
            let fd = args[args.len() - 2].to_owned();
            assert!(fd.to_str().unwrap().parse::<RawFd>().unwrap() >= 16);
            cmd.env("SHARE_FD", fd);
            std::fs::rename(&approved, root.path().join("moved")).unwrap();
            std::os::unix::fs::symlink("private", &approved).unwrap();
            let output = cmd.output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(output.stdout, b"approved");
            std::fs::remove_file(&approved).unwrap();
            std::fs::rename(root.path().join("moved"), &approved).unwrap();
        }
    }

    #[test]
    fn child_identity_is_bounded_validated_and_times_out() {
        for bytes in [b"{}".as_slice(), b"{\"child-pid\":0}", &[b' '; 4097]] {
            let mut info = tempfile::tempfile().unwrap();
            info.write_all(bytes).unwrap();
            info.rewind().unwrap();
            assert!(read_child_pid(info, Duration::from_secs(1)).is_err());
        }
        let mut info = tempfile::tempfile().unwrap();
        info.write_all(b"{\"child-pid\":42}").unwrap();
        info.rewind().unwrap();
        assert_eq!(read_child_pid(info, Duration::from_secs(1)).unwrap(), 42);
        let (reader, writer) = rustix::pipe::pipe().unwrap();
        assert!(read_child_pid(File::from(reader), Duration::from_millis(10)).is_err());
        drop(writer);
    }

    #[test]
    fn failed_identity_kills_an_unsupervised_launch_without_waiting_for_its_exit() {
        let mut command = Command::new("/bin/sleep");
        command.arg("5");
        let launch = PreparedLaunch {
            command,
            inherited_files: Vec::new(),
            identity: tempfile::tempfile().unwrap(),
        };
        let started = std::time::Instant::now();
        assert!(launch.spawn(Duration::from_secs(1)).is_err());
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    #[ignore = "requires Linux user namespaces and Zig for a static native probe"]
    #[allow(
        clippy::too_many_lines,
        reason = "both role launches share the authority witnesses"
    )]
    fn isolated_vm_networking_preserves_ipc_and_independent_broker_authority() -> Result<()> {
        use std::os::unix::net::{UnixDatagram, UnixListener, UnixStream};
        use std::process::Stdio;

        let root = tempfile::tempdir()?;
        let probe = root.path().join("network-boundary-probe");
        let source =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/assets/network_boundary_probe.c");
        ensure!(
            Command::new("zig")
                .args([
                    "cc",
                    "-target",
                    &format!("{}-linux-musl", std::env::consts::ARCH),
                    "-static",
                    "-O2",
                    "-Wall",
                    "-Wextra",
                    "-Werror"
                ])
                .arg(source)
                .arg("-o")
                .arg(&probe)
                .status()?
                .success(),
            "compiling network boundary probe"
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let host_sockets = root.path().join("host-sockets");
        std::fs::create_dir(&host_sockets)?;
        let stream_path = host_sockets.join("stream");
        let datagram_path = host_sockets.join("datagram");
        let stream_listener = UnixListener::bind(&stream_path)?;
        stream_listener.set_nonblocking(true)?;
        let datagram_listener = UnixDatagram::bind(&datagram_path)?;
        datagram_listener.set_read_timeout(Some(Duration::from_secs(1)))?;
        let has_kvm = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kvm")
            .is_ok();
        for (role, name, expected) in [(Role::Vm, "vm", b'V'), (Role::Network, "network", b'B')] {
            let (mut parent, endpoint) = UnixStream::pair()?;
            parent.set_read_timeout(Some(Duration::from_secs(10)))?;
            let mut command = Command::new(&probe);
            command
                .args([
                    name,
                    &listener.local_addr()?.port().to_string(),
                    if has_kvm { "1" } else { "0" },
                ])
                .arg(&stream_path)
                .arg(&datagram_path);
            let mut grants = super::super::role_grants(role);
            grants.push(Grant::new(&probe, Access::ReadOnly));
            grants.push(Grant::new(&host_sockets, Access::ReadOnly));
            let mut launch = prepare_launch(Launch {
                role,
                command,
                grants,
                die_with_parent: true,
                policy: None,
                staging_directory: &std::env::temp_dir(),
            })?;
            launch.command.stdin(Stdio::null());
            let inherited = terra_platform::process::pass_descriptor(
                &mut launch.command,
                &File::from(OwnedFd::from(endpoint)),
                7,
            )?;
            let mut child = launch.spawn(Duration::from_secs(10))?.child;
            drop(inherited);
            let mut byte = [0];
            let result = parent.read_exact(&mut byte);
            drop(parent);
            if result.is_err() {
                let _ = child.kill();
            }
            let status = child.wait()?;
            result?;
            ensure!(
                byte == [expected] && status.success(),
                "network boundary probe failed: {status}"
            );
        }
        let (mut external, _) = listener.accept()?;
        let mut byte = [0];
        external.read_exact(&mut byte)?;
        ensure!(byte == *b"N", "broker host connection failed");
        ensure!(
            listener.accept().is_err(),
            "isolated worker reached host endpoint"
        );
        ensure!(
            stream_listener.accept().is_err(),
            "a worker reached a mounted host Unix socket"
        );
        ensure!(
            datagram_listener.recv(&mut byte).is_err(),
            "a worker sent a host Unix datagram"
        );
        Ok(())
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[allow(clippy::too_many_lines)]
    #[test]
    #[ignore = "requires Linux KVM and Zig to run a static native jail probe"]
    /// Native networking reaches host loopback while the filesystem remains
    /// confined and the seccomp filter survives exec.
    fn production_jail_restricts_native_probe() {
        use std::process::Stdio;
        use std::time::{Duration, Instant};

        let root = tempfile::tempdir().unwrap();
        let probe = root.path().join("native-probe");
        let target = format!("{}-linux-musl", std::env::consts::ARCH);
        let assets = std::env::var_os("TERRA_TEST_ASSETS").map_or_else(
            || Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/assets"),
            PathBuf::from,
        );
        let source = assets.join("bwrap_jail_probe.c");
        let compiled = Command::new("zig")
            .args([
                "cc", "-target", &target, "-static", "-O2", "-Wall", "-Wextra", "-Werror",
            ])
            .arg(source)
            .arg("-o")
            .arg(&probe)
            .env("ZIG_GLOBAL_CACHE_DIR", root.path().join("zig-global"))
            .env("ZIG_LOCAL_CACHE_DIR", root.path().join("zig-local"))
            .status()
            .expect("compiling static native jail probe with Zig");
        assert!(
            compiled.success(),
            "compiling native jail probe failed: {compiled}"
        );

        let project = root.path().join("project");
        let box_dir = root.path().join("box");
        let other_box = root.path().join("other-box");
        let share = root.path().join("share");
        for dir in [&project, &box_dir, &other_box, &share] {
            std::fs::create_dir_all(dir).unwrap();
        }
        let sentinel = root.path().join("ungranted-sentinel");
        let other_pin = other_box.join("recipe.yaml");
        let share_file = share.join("readonly-file");
        let recipe = box_dir.join("recipe.yaml");
        let pinned_paths = box_dir.join("pinned-paths.yaml");
        let host_pid = box_dir.join("host.pid");
        for path in [
            &sentinel,
            &other_pin,
            &share_file,
            &recipe,
            &pinned_paths,
            &host_pid,
        ] {
            std::fs::write(path, b"unchanged").unwrap();
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port().to_string();
        let mut command = Command::new(&probe);
        command.args([
            sentinel.as_os_str(),
            other_pin.as_os_str(),
            share_file.as_os_str(),
            recipe.as_os_str(),
            pinned_paths.as_os_str(),
            host_pid.as_os_str(),
            std::ffi::OsStr::new(&port),
        ]);
        let mut filter = Vec::new();
        let getpid = u32::try_from(libc::SYS_getpid).unwrap();
        for (code, jump_true, jump_false, value) in [
            (0x20_u16, 0_u8, 0_u8, 0_u32),
            (0x15, 0, 1, getpid),
            (0x06, 0, 0, libc::SECCOMP_RET_KILL_PROCESS),
            (0x06, 0, 0, libc::SECCOMP_RET_ALLOW),
        ] {
            filter.write_all(&code.to_ne_bytes()).unwrap();
            filter.write_all(&[jump_true, jump_false]).unwrap();
            filter.write_all(&value.to_ne_bytes()).unwrap();
        }
        let mut share_grant = Grant::new(&share, Access::ReadOnly);
        share_grant.directory = Some(terra_platform::filesystem::open_share_root(&share).unwrap());
        let mut launch = prepare_launch(Launch {
            role: Role::Network,
            command,
            grants: vec![
                Grant::new(&probe, Access::ReadOnly),
                Grant::new(&box_dir, Access::ReadWrite),
                share_grant,
                Grant::new(&recipe, Access::ReadOnly),
                Grant::new(&pinned_paths, Access::ReadOnly),
                Grant::new(&host_pid, Access::ReadOnly),
                Grant::new("/dev/kvm", Access::Device),
            ],
            die_with_parent: true,
            policy: Some(&filter),
            staging_directory: &std::env::temp_dir(),
        })
        .unwrap();
        launch
            .command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let guard = terra_platform::process::supervise_vm_child(&mut launch.command, true).unwrap();
        let child = launch
            .spawn(Duration::from_secs(30))
            .expect("starting production Bubblewrap command");
        assert!(child.pid > 0);
        let mut child = child.child;
        if let Some(guard) = &guard {
            terra_platform::process::attach_vm_child(guard, &child).unwrap();
        }
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            if Instant::now() >= deadline {
                let _ = terra_platform::process::kill_vm_child(&mut child);
                child.wait().unwrap();
                panic!("native jail probe did not finish within 30 seconds");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let output = child.wait_with_output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stdout.contains("JAIL_PROBES_OK"), "{stdout}\n{stderr}");
        assert_eq!(
            output.status.code(),
            Some(128 + libc::SIGSYS),
            "seccomp did not kill the probe after exec: {stdout}\n{stderr}"
        );
        listener.set_nonblocking(true).unwrap();
        let (mut connection, _) = listener.accept().unwrap();
        connection
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut received = [0];
        connection.read_exact(&mut received).unwrap();
        assert_eq!(received, [b'N']);
        for path in [
            &sentinel,
            &other_pin,
            &share_file,
            &recipe,
            &pinned_paths,
            &host_pid,
        ] {
            assert_eq!(
                std::fs::read(path).unwrap(),
                b"unchanged",
                "{} changed",
                path.display()
            );
        }
    }
}
