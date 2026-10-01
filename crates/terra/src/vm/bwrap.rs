//! The host filesystem and namespaces visible to a Bubblewrap VM process.

use super::boot::{BootSpec, VM_PROCESS_FLAG_ARG};
use crate::state::{self, BoxRef};
use anyhow::{Context, Result, ensure};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::Write;
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use terra_protocol::PlanMode;

const BWRAP: &[u8] = include_bytes!(env!("TERRA_BWRAP_BIN"));
static EMBEDDED_BWRAP: OnceLock<std::result::Result<OwnedFd, String>> = OnceLock::new();

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

pub(crate) fn embedded_command() -> Result<Command> {
    let fd = EMBEDDED_BWRAP
        .get_or_init(create_embedded_bwrap)
        .as_ref()
        .map_err(|message| anyhow::anyhow!("{message}"))?
        .as_raw_fd();
    Ok(Command::new(format!("/proc/self/fd/{fd}")))
}

pub(super) fn command(
    spec: &BootSpec,
    bx: &BoxRef,
    terra_exe: &Path,
    seccomp_fd: RawFd,
    info_fd: RawFd,
) -> Result<Command> {
    ensure!(
        terra_exe.is_absolute(),
        "the Terra executable path must be absolute"
    );
    ensure!(
        bx.get_dir().is_absolute(),
        "the box state path must be absolute"
    );
    ensure!(
        seccomp_fd == 5 && info_fd == 6,
        "the seccomp and PID handoff descriptors must be 5 and 6"
    );
    ensure_static_executable(terra_exe)?;
    ensure!(
        bx.get_dir().is_dir(),
        "box state directory {} does not exist",
        bx.get_dir().display()
    );

    let mut cmd = embedded_command()?;
    restrict_environment(&mut cmd);
    cmd.args([
        "--unshare-user",
        "--unshare-ipc",
        "--unshare-pid",
        "--unshare-uts",
        "--as-pid-1",
        "--disable-userns",
        "--cap-drop",
        "ALL",
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        "--tmpfs",
        "/tmp",
    ]);
    if spec.foreground || spec.mode == PlanMode::Create {
        cmd.arg("--die-with-parent");
    }

    let mounts = collect_mounts(spec, bx, terra_exe)?;
    append_mounts(&mut cmd, mounts)?;
    cmd.args(["--dev-bind", "/dev/kvm", "/dev/kvm"]);
    cmd.arg("--seccomp").arg(seccomp_fd.to_string());
    cmd.arg("--info-fd").arg(info_fd.to_string());
    cmd.args(["--chdir", "/", "--"])
        .arg(terra_exe)
        .arg(VM_PROCESS_FLAG_ARG)
        .arg(bx.get_dir());
    Ok(cmd)
}

fn restrict_environment(cmd: &mut Command) {
    cmd.env_clear();
    for name in ["RUST_LOG", "TERRA_BOOT_TRACE"] {
        if let Some(value) = std::env::var_os(name) {
            cmd.env(name, value);
        }
    }
}

fn collect_mounts(spec: &BootSpec, bx: &BoxRef, terra_exe: &Path) -> Result<Vec<Mount>> {
    let mut mounts = vec![Mount::new(terra_exe, true, 0)];
    for path in [
        "/etc/resolv.conf",
        "/etc/hosts",
        "/etc/nsswitch.conf",
        "/etc/localtime",
    ] {
        let path = Path::new(path);
        if path.exists() {
            mounts.push(Mount::new(path, true, 0));
        }
    }
    if spec.mode == PlanMode::Run {
        for share in &spec.cfg.mounts {
            ensure!(
                share.host.is_absolute(),
                "share path {} is not absolute",
                share.host.display()
            );
            let directory = terra_platform::filesystem::open_share_root(&share.host)
                .with_context(|| format!("opening approved share {}", share.host.display()))?;
            let mut mount = Mount::new(&share.host, share.readonly, 1);
            mount.directory = Some(directory);
            mounts.push(mount);
        }
    }
    mounts.push(Mount::new(bx.get_dir(), false, 2));
    for name in [
        state::RECIPE_FILE,
        state::PINNED_PATHS_FILE,
        state::ORIGIN_FILE,
        state::BAKE_STAMP,
        state::HOST_PID_FILE,
    ] {
        let path = bx.get_dir().join(name);
        if path.exists() {
            ensure!(
                std::fs::symlink_metadata(&path)?.file_type().is_file(),
                "box metadata {} is not a regular file",
                path.display()
            );
            mounts.push(Mount::new(&path, true, 3));
        }
    }
    mounts.sort_by(|left, right| {
        left.path
            .components()
            .count()
            .cmp(&right.path.components().count())
            .then_with(|| left.priority.cmp(&right.priority))
            .then_with(|| left.path.cmp(&right.path))
    });
    Ok(mounts)
}

#[allow(unsafe_code)]
fn append_mounts(cmd: &mut Command, mounts: Vec<Mount>) -> Result<()> {
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
            cmd.arg(if mount.readonly {
                "--ro-bind-fd"
            } else {
                "--bind-fd"
            })
            .arg(directory.as_raw_fd().to_string());
            directories.push(directory);
        } else {
            cmd.arg(if mount.readonly {
                "--ro-bind"
            } else {
                "--bind"
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
        .with_context(|| format!("opening Terra executable {}", path.display()))?;
    let mut header = [0_u8; 64];
    file.read_exact(&mut header)
        .with_context(|| format!("reading ELF header of {}", path.display()))?;
    ensure!(
        &header[..6] == b"\x7fELF\x02\x01",
        "Bubblewrap requires a static 64-bit little-endian Linux Terra executable"
    );
    let program_offset = u64::from_le_bytes(header[32..40].try_into()?);
    let program_size = u64::from(u16::from_le_bytes(header[54..56].try_into()?));
    let program_count = u64::from(u16::from_le_bytes(header[56..58].try_into()?));
    ensure!(
        program_size >= 4
            && program_offset
                .checked_add(program_size.saturating_mul(program_count))
                .is_some_and(|end| end <= file.metadata().map_or(0, |metadata| metadata.len())),
        "Terra executable has invalid ELF program headers"
    );
    for index in 0..program_count {
        file.seek(SeekFrom::Start(program_offset + index * program_size))?;
        let mut program_type = [0_u8; 4];
        file.read_exact(&mut program_type)?;
        ensure!(
            u32::from_le_bytes(program_type) != 3,
            "Bubblewrap requires the static Linux musl Terra binary; this executable needs a dynamic loader"
        );
    }
    Ok(())
}

struct Mount {
    path: PathBuf,
    directory: Option<File>,
    readonly: bool,
    priority: u8,
}

impl Mount {
    fn new(path: &Path, readonly: bool, priority: u8) -> Self {
        Self {
            path: path.to_path_buf(),
            directory: None,
            readonly,
            priority,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Mount as Share};

    #[test]
    fn jail_environment_keeps_only_diagnostics() {
        let mut cmd = Command::new("/usr/bin/env");
        cmd.env("TERRA_TEST_HOST_SECRET", "secret");
        restrict_environment(&mut cmd);
        let mut expected = ["RUST_LOG", "TERRA_BOOT_TRACE"]
            .into_iter()
            .filter_map(|name| std::env::var_os(name).map(|value| (name, value)))
            .map(|(name, value)| format!("{name}={}", value.to_string_lossy()))
            .collect::<Vec<_>>();
        expected.sort();
        let output = cmd.output().unwrap();
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut actual = stdout.lines().collect::<Vec<_>>();
        actual.sort_unstable();
        assert_eq!(actual, expected);
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
        let handoff = tempfile::tempfile().unwrap();
        let _inherited = crate::sys::pass_seccomp(&mut command, &handoff).unwrap();
        let output = command.arg("--version").env("PATH", "").output().unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).starts_with("bubblewrap "));
    }

    #[test]
    fn run_shares_are_ordered_and_metadata_is_readonly() {
        let root = tempfile::tempdir().unwrap();
        let box_dir = root.path().join("box");
        let share = root.path().join("share");
        let nested = share.join("nested");
        std::fs::create_dir_all(&box_dir).unwrap();
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(box_dir.join(state::RECIPE_FILE), "{}").unwrap();
        let terra_exe = root.path().join("terra");
        let mut elf = [0_u8; 64];
        elf[..6].copy_from_slice(b"\x7fELF\x02\x01");
        elf[32..40].copy_from_slice(&64_u64.to_le_bytes());
        elf[54..56].copy_from_slice(&4_u16.to_le_bytes());
        std::fs::write(&terra_exe, elf).unwrap();
        let bx = BoxRef::from_state_dir(box_dir.clone(), root.path());
        let spec = BootSpec {
            cfg: Config {
                mounts: vec![
                    Share {
                        host: nested.clone(),
                        guest: "/nested".into(),
                        readonly: true,
                    },
                    Share {
                        host: share.clone(),
                        guest: "/share".into(),
                        readonly: false,
                    },
                ],
                ..Config::default()
            },
            project_dir: root.path().to_path_buf(),
            root: false,
            mode: PlanMode::Run,
            foreground: false,
            builtin_bwrap: false,
        };
        let args = command(&spec, &bx, &terra_exe, 5, 6).unwrap();
        let args = args
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
        let recipe = box_dir.join(state::RECIPE_FILE);
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
        assert!(args.windows(2).any(|args| args == ["--seccomp", "5"]));
        assert!(args.windows(2).any(|args| args == ["--info-fd", "6"]));
        assert!(args.iter().any(|arg| arg == "--unshare-pid"));
        assert!(!args.iter().any(|arg| arg == "--new-session"));
        assert!(!args.iter().any(|arg| arg == "--unshare-net"));
        let mut bake = spec;
        bake.mode = PlanMode::Create;
        let bake_args = command(&bake, &bx, &terra_exe, 5, 6).unwrap();
        assert!(
            !bake_args
                .get_args()
                .any(|arg| arg == share.as_os_str() || arg == nested.as_os_str())
        );
        assert!(bake_args.get_args().any(|arg| arg == "--die-with-parent"));

        let moved = root.path().join("moved");
        std::fs::rename(&share, &moved).unwrap();
        std::os::unix::fs::symlink(&moved, &share).unwrap();
        bake.mode = PlanMode::Run;
        assert!(command(&bake, &bx, &terra_exe, 5, 6).is_err());
        std::fs::remove_file(&share).unwrap();
        std::fs::rename(&moved, &share).unwrap();
        std::fs::rename(&nested, &moved).unwrap();
        std::os::unix::fs::symlink(&moved, &nested).unwrap();
        assert!(command(&bake, &bx, &terra_exe, 5, 6).is_err());

        let mut dynamic = elf.to_vec();
        dynamic[56..58].copy_from_slice(&1_u16.to_le_bytes());
        dynamic.extend_from_slice(&3_u32.to_le_bytes());
        std::fs::write(&terra_exe, dynamic).unwrap();
        assert!(ensure_static_executable(&terra_exe).is_err());
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
            let mut mount = Mount::new(&approved, readonly, 1);
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
        let other_pin = other_box.join(state::RECIPE_FILE);
        let share_file = share.join("readonly-file");
        let recipe = box_dir.join(state::RECIPE_FILE);
        let pinned_paths = box_dir.join(state::PINNED_PATHS_FILE);
        let host_pid = box_dir.join(state::HOST_PID_FILE);
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
        let bx = BoxRef::from_state_dir(box_dir, &project);
        let spec = BootSpec {
            cfg: Config {
                mounts: vec![Share {
                    host: share,
                    guest: "/share".into(),
                    readonly: true,
                }],
                ..Config::default()
            },
            project_dir: project,
            root: false,
            mode: PlanMode::Run,
            foreground: true,
            builtin_bwrap: true,
        };

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port().to_string();
        let mut launch = command(&spec, &bx, &probe, 5, 6).unwrap();
        launch.args([
            sentinel.as_os_str(),
            other_pin.as_os_str(),
            share_file.as_os_str(),
            recipe.as_os_str(),
            pinned_paths.as_os_str(),
            host_pid.as_os_str(),
            std::ffi::OsStr::new(&port),
        ]);
        launch
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut filter = tempfile::tempfile().unwrap();
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
        filter.rewind().unwrap();
        let info = tempfile::tempfile().unwrap();
        let guard = crate::sys::supervise_vm_child(&mut launch, true).unwrap();
        let inherited_filter = crate::sys::pass_seccomp(&mut launch, &filter).unwrap();
        let inherited_info = crate::sys::pass_bwrap_info(&mut launch, &info).unwrap();
        let mut child = launch
            .spawn()
            .expect("starting production Bubblewrap command");
        drop((inherited_filter, inherited_info));
        if let Some(guard) = &guard {
            crate::sys::attach_vm_child(guard, &child).unwrap();
        }
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            if Instant::now() >= deadline {
                let _ = crate::sys::kill_vm_child(&mut child);
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
