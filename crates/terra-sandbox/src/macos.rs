//! Seatbelt-confined workers with separate VM and network authority.

mod policy;
mod seatbelt;

use super::{Access, Grant, Launch, PreparedLaunch, Role};
use anyhow::{Context, Result, ensure};
use std::ffi::OsString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::{CommandExt as _, ExitStatusExt as _};
use std::path::Path;
use std::process::{Child, Command, ExitCode};
use std::time::Duration;
use terra_platform::process::sandbox_env::ROLE;

const PROBE_ENV: &str = "TERRA_MACOS_SANDBOX_PROBE";
const SPEC_ENV: &str = "TERRA_MACOS_SANDBOX_SPEC";
const ACTIVATION_FD: i32 = 9;
const ACTIVATION_ACK: u8 = 0x53;

pub struct Confinement {
    spec: tempfile::NamedTempFile,
    inherited: File,
    activation: UnixStream,
}

/// The spec only needs to outlive activation; `confirm` deletes it.
pub type Resources = ();

impl Confinement {
    pub(crate) fn confirm(self, child: &mut Child, timeout: Duration) -> Result<(u32, Resources)> {
        let Self {
            spec,
            inherited,
            mut activation,
        } = self;
        drop(inherited);
        ensure!(
            !timeout.is_zero(),
            "macOS confinement activation needs a deadline"
        );
        activation.set_read_timeout(Some(timeout))?;
        let mut acknowledgement = [0];
        if let Err(error) = activation.read_exact(&mut acknowledgement) {
            return Err(activation_failure(child, error, timeout));
        }
        ensure!(
            acknowledgement == [ACTIVATION_ACK],
            "macOS worker sent an invalid activation acknowledgement"
        );
        drop(spec);
        Ok((child.id(), ()))
    }
}

fn activation_failure(
    child: &mut Child,
    error: std::io::Error,
    timeout: Duration,
) -> anyhow::Error {
    if error.kind() != std::io::ErrorKind::UnexpectedEof {
        return anyhow::Error::new(error).context(format!(
            "macOS sandbox worker did not verify confinement within {timeout:?}"
        ));
    }
    // EOF means the worker is exiting, so this kill cannot change its exit status.
    let _ = terra_platform::process::kill_vm_child(child);
    // Reaping goes through `Child`: kill_vm_child's own try_wait may already have reaped it.
    match child.wait().ok().and_then(|status| status.signal()) {
        Some(signal) => anyhow::anyhow!(
            "macOS sandbox worker was killed by signal {signal} before verifying confinement"
        ),
        None => anyhow::Error::new(error)
            .context("macOS sandbox worker exited before verifying confinement"),
    }
}

pub fn prepare_launch(launch: Launch<'_>) -> Result<PreparedLaunch> {
    prepare_launch_via(launch, &std::env::current_exe()?)
}

fn prepare_launch_via(launch: Launch<'_>, launcher: &Path) -> Result<PreparedLaunch> {
    let Launch {
        role,
        command,
        grants,
        staging_directory,
    } = launch;
    ensure!(
        role != Role::Supervisor,
        "the macOS supervisor uses the trusted lifecycle launcher"
    );
    let executable = Path::new(command.get_program());
    ensure!(
        executable.is_absolute() && executable.is_file(),
        "macOS sandbox executable must be an existing absolute file"
    );
    ensure!(
        command.get_current_dir().is_none_or(Path::is_absolute),
        "macOS sandbox working directory must be absolute"
    );
    std::fs::create_dir_all(staging_directory)?;
    let spec = crate::write_worker_spec(
        staging_directory,
        &policy::WorkerSpec {
            role,
            grants: policy::resolve_grants(&grants, staging_directory)?,
        },
    )?;
    let mut worker_command = Command::new(launcher);
    worker_command
        .arg(super::LAUNCHER_WORKER_ARG)
        .arg("--macos-worker")
        .arg("--")
        .arg(executable)
        .args(command.get_args());
    crate::copy_explicit_environment(&mut worker_command, &command);
    worker_command.env(SPEC_ENV, spec.path());
    worker_command.current_dir(command.get_current_dir().unwrap_or(Path::new("/")));
    let (activation, child_activation) = UnixStream::pair()?;
    let inherited = terra_platform::process::pass_descriptor(
        &mut worker_command,
        &File::from(OwnedFd::from(child_activation)),
        ACTIVATION_FD,
    )?;
    Ok(PreparedLaunch {
        command: worker_command,
        confinement: Confinement {
            spec,
            inherited,
            activation,
        },
    })
}

/// The macOS supervisor stays unsandboxed; the trusted launcher applies each worker's Seatbelt profile before exec.
pub fn restrict_role(_role: Role) -> Result<()> {
    Ok(())
}

pub fn role_grants(role: Role) -> Vec<Grant> {
    let paths: &[&str] = match role {
        Role::Supervisor => &[],
        Role::Vm => &["/etc/localtime"],
        Role::Network => &["/etc/resolv.conf", "/etc/hosts"],
    };
    paths
        .iter()
        .filter(|path| Path::new(path).exists())
        .map(|path| Grant::new(*path, Access::ReadOnly))
        .collect()
}

pub(super) fn verify_confinement(role: Role) -> Result<()> {
    let probe = std::env::var_os(PROBE_ENV).context("macOS sandbox activation probe is missing")?;
    require_permission_denied(
        File::open(probe),
        "reading a host file outside the sandbox grants",
    )?;
    if role == Role::Vm {
        for address in ["127.0.0.1:9", "[::1]:9"] {
            let address: std::net::SocketAddr = address.parse()?;
            require_permission_denied(
                std::net::TcpStream::connect_timeout(&address, Duration::from_secs(1)),
                "opening a VM host-network connection",
            )?;
            require_permission_denied(
                std::net::TcpListener::bind(std::net::SocketAddr::new(address.ip(), 0)),
                "creating a VM host-network listener",
            )?;
        }
    }
    let mut activation = terra_platform::process::claim_ipc(ACTIVATION_FD)
        .context("claiming the macOS sandbox activation endpoint")?;
    activation
        .write_all(&[ACTIVATION_ACK])
        .context("acknowledging macOS sandbox activation")?;
    Ok(())
}

fn require_permission_denied<T>(result: std::io::Result<T>, operation: &str) -> Result<()> {
    match result {
        Err(error) if matches!(error.raw_os_error(), Some(libc::EPERM | libc::EACCES)) => Ok(()),
        Err(error) => Err(error).with_context(|| {
            format!("macOS sandbox activation could not prove denial of {operation}")
        }),
        Ok(_) => anyhow::bail!("macOS sandbox activation failed: {operation} was permitted"),
    }
}

pub fn run_launcher_worker(arguments: impl Iterator<Item = OsString>) -> Result<ExitCode> {
    let arguments: Vec<OsString> = arguments.collect();
    if arguments == [OsString::from("--version")] {
        println!("terra macOS sandbox {}", env!("CARGO_PKG_VERSION"));
        return Ok(ExitCode::SUCCESS);
    }
    let [flag, separator, executable, worker_arguments @ ..] = arguments.as_slice() else {
        anyhow::bail!(
            "terra {} accepts --version or --macos-worker -- <executable> <arguments>",
            super::LAUNCHER_WORKER_ARG
        );
    };
    ensure!(
        flag == "--macos-worker" && separator == "--",
        "terra {} needs --macos-worker -- before the worker executable",
        super::LAUNCHER_WORKER_ARG
    );
    ensure!(
        std::env::var_os(ROLE).is_none(),
        "a sandbox worker cannot run the trusted launcher"
    );
    let spec_path = std::env::var_os(SPEC_ENV).context("the macOS sandbox spec is missing")?;
    let spec: policy::WorkerSpec = crate::read_worker_spec(Path::new(&spec_path))?;
    let executable = std::fs::canonicalize(executable)
        .context("resolving the macOS sandbox worker executable")?;
    let profile = policy::render_profile(spec.role, &executable, &spec.grants)?;
    let mut worker = Command::new(&executable);
    worker
        .args(worker_arguments)
        .env_remove(SPEC_ENV)
        .env(ROLE, spec.role.name())
        .env(PROBE_ENV, &spec_path);
    seatbelt::apply(&profile)?;
    Err(anyhow::Error::new(worker.exec()).context(format!(
        "starting {} under its macOS sandbox profile",
        executable.display()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SpawnedLaunch;
    use std::assert_matches;
    use std::os::fd::FromRawFd;
    use std::os::unix::net::{UnixDatagram, UnixListener};
    use std::process::Stdio;

    const TEST_ENDPOINT: &str = "TERRA_MACOS_TEST_ENDPOINT";
    const TEST_METADATA: &str = "TERRA_MACOS_TEST_METADATA";
    const TEST_SHARE_ROOT: &str = "TERRA_MACOS_TEST_SHARE_ROOT";
    const TEST_SYMLINKED_SHARE: &str = "TERRA_MACOS_TEST_SYMLINKED_SHARE";
    const TEST_LISTENER_FD: i32 = 10;

    #[allow(unsafe_code, reason = "Hypervisor.framework has no safe binding here")]
    #[link(name = "Hypervisor", kind = "framework")]
    unsafe extern "C" {
        fn hv_vm_create(config: *mut std::ffi::c_void) -> i32;
        fn hv_vm_destroy() -> i32;
    }

    /// Hypervisor.framework is not gated by Seatbelt: only the
    /// `com.apple.security.hypervisor` entitlement decides, so the signed test
    /// binary gets 0 under every profile.
    #[allow(unsafe_code)]
    fn hypervisor_vm_create_result() -> i32 {
        // SAFETY: a null config requests the default VM; this process owns the
        // single VM slot and destroys it again on success.
        let result = unsafe { hv_vm_create(std::ptr::null_mut()) };
        if result == 0 {
            // SAFETY: the VM created above is still alive.
            assert_eq!(unsafe { hv_vm_destroy() }, 0);
        }
        result
    }

    #[test]
    fn activation_accepts_only_kernel_permission_denial() {
        assert!(require_permission_denied(Ok(()), "probe").is_err());
        assert!(
            require_permission_denied::<()>(
                Err(std::io::Error::from_raw_os_error(libc::ENOENT)),
                "probe"
            )
            .is_err()
        );
        for error in [libc::EACCES, libc::EPERM] {
            assert!(
                require_permission_denied::<()>(
                    Err(std::io::Error::from_raw_os_error(error)),
                    "probe"
                )
                .is_ok()
            );
        }
    }

    #[test]
    fn activation_reports_a_worker_killed_before_its_ack() {
        let message = failed_confirmation_message("kill -s KILL $$");
        assert!(message.contains("killed by signal 9"), "{message}");
    }

    #[test]
    fn activation_reports_a_worker_that_exits_before_its_ack() {
        let message = failed_confirmation_message("exit 7");
        assert!(message.contains("exited before verifying"), "{message}");
    }

    #[test]
    fn launcher_requires_the_worker_separator() {
        for arguments in [
            vec!["x"],
            vec!["--macos-worker"],
            vec!["--macos-worker", "/bin/true"],
        ] {
            assert!(run_launcher_worker(arguments.into_iter().map(Into::into)).is_err());
        }
        let error = run_launcher_worker(
            ["--macos-worker", "/bin/true", "x"]
                .into_iter()
                .map(Into::into),
        )
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("--macos-worker --"),
            "{error:#}"
        );
    }

    #[test]
    fn launcher_refuses_to_run_inside_a_worker() -> Result<()> {
        const CHILD: &str = "TERRA_MACOS_LAUNCHER_REFUSAL_TEST";
        if std::env::var_os(CHILD).is_some() {
            let error = run_launcher_worker(
                ["--macos-worker", "--", "/bin/true"]
                    .into_iter()
                    .map(Into::into),
            )
            .unwrap_err();
            assert!(
                format!("{error:#}").contains("a sandbox worker cannot run the trusted launcher"),
                "{error:#}"
            );
            return Ok(());
        }
        let output = Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "macos::tests::launcher_refuses_to_run_inside_a_worker",
            ])
            .env(CHILD, "1")
            .env(ROLE, "vm")
            .output()?;
        assert!(output.status.success(), "{output:?}");
        Ok(())
    }

    #[test]
    fn seatbelt_rejects_a_malformed_profile() -> Result<()> {
        const CHILD: &str = "TERRA_MACOS_SEATBELT_MALFORMED_TEST";
        if std::env::var_os(CHILD).is_some() {
            let error = seatbelt::apply(&policy::Profile {
                text: "(version 1)(deny".into(),
                parameters: vec![],
            })
            .unwrap_err();
            assert!(
                !format!("{error:#}").ends_with("no error message"),
                "{error:#}"
            );
            return Ok(());
        }
        let output = Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "macos::tests::seatbelt_rejects_a_malformed_profile",
            ])
            .env(CHILD, "1")
            .output()?;
        assert!(output.status.success(), "{output:?}");
        Ok(())
    }

    /// Runs `script` as a worker that never acknowledges. The worker must stay
    /// unreaped after the failed confirmation, because spawn's cleanup signals
    /// its raw PID.
    fn failed_confirmation_message(script: &str) -> String {
        let (activation, child_end) = UnixStream::pair().unwrap();
        let child_stdin = child_end.try_clone().unwrap();
        let mut child = Command::new("/bin/sh")
            .args(["-c", script])
            .stdin(Stdio::from(OwnedFd::from(child_stdin)))
            .spawn()
            .unwrap();
        let confinement = Confinement {
            spec: tempfile::NamedTempFile::new().unwrap(),
            inherited: File::from(OwnedFd::from(child_end)),
            activation,
        };
        let error = confinement
            .confirm(&mut child, Duration::from_secs(10))
            .unwrap_err();
        child
            .wait()
            .expect("a failed confirmation must reap the worker only through its Child");
        format!("{error:#}")
    }

    #[test]
    #[allow(unsafe_code)]
    fn sandboxed_worker_probe_child() -> Result<()> {
        let Some(endpoint) = std::env::var_os(TEST_ENDPOINT) else {
            return Ok(());
        };
        let role = match std::env::var(ROLE)?.as_str() {
            "vm" => Role::Vm,
            "network" => Role::Network,
            value => anyhow::bail!("unexpected sandboxed test role {value}"),
        };
        crate::verify_worker_role(role)?;
        require_permission_denied(
            Command::new("/usr/bin/true").status(),
            "executing a program the profile does not grant",
        )?;
        require_permission_denied(
            Command::new(std::env::current_exe()?)
                .arg("--list")
                .status(),
            "starting a child process",
        )?;
        ensure!(
            hypervisor_vm_create_result() == 0,
            "a profile cannot deny Hypervisor.framework to a worker with the entitlement"
        );
        let address = endpoint
            .to_str()
            .context("invalid native test endpoint")?
            .parse()?;
        let connection = std::net::TcpStream::connect_timeout(&address, Duration::from_secs(1));
        match role {
            Role::Vm => {
                require_permission_denied(connection, "connecting to the host test listener")?;
                verify_share_access_and_socket_denial()?;
                let symlinked = std::env::var_os(TEST_SYMLINKED_SHARE)
                    .context("missing native test symlinked share")?;
                terra_platform::filesystem::share::open_share_root(Path::new(&symlinked)).context(
                    "opening the canonical path of a share granted by its symlinked spelling",
                )?;
                // SAFETY: the native acceptance parent prebinds and inherits this owned listener.
                let listener = unsafe { UnixListener::from_raw_fd(TEST_LISTENER_FD) };
                listener.set_nonblocking(true)?;
                let (mut peer, _) = listener.accept()?;
                peer.set_read_timeout(Some(Duration::from_secs(1)))?;
                let mut bytes = [0; 3];
                peer.read_exact(&mut bytes)?;
                ensure!(&bytes == b"ipc", "inherited listener data was corrupted");
                peer.write_all(b"ack")?;
            }
            Role::Network => {
                require_permission_denied(
                    std::net::TcpListener::bind("127.0.0.1:0"),
                    "creating a broker TCP listener",
                )?;
                std::net::UdpSocket::bind("0.0.0.0:0").context("binding a broker UDP socket")?;
                let mut resolved = std::net::ToSocketAddrs::to_socket_addrs(&("localhost", 0))
                    .context("resolving a name through the system resolver")?;
                ensure!(
                    resolved.next().is_some(),
                    "name resolution returned no addresses"
                );
                connection?.write_all(b"broker")?;
            }
            Role::Supervisor => unreachable!("the test has no supervisor child"),
        }
        require_permission_denied(
            File::options()
                .write(true)
                .open(std::env::var_os(TEST_METADATA).context("missing native test metadata")?),
            "modifying the supervisor identity",
        )?;
        Ok(())
    }

    fn verify_share_access_and_socket_denial() -> Result<()> {
        let root = std::env::var_os(TEST_SHARE_ROOT).context("missing native test shares")?;
        require_permission_denied(
            std::fs::read_dir(&root),
            "listing the parent of approved shares",
        )?;
        for share in ["read-only", "writable"] {
            let directory = Path::new(&root).join(share);
            let opened = terra_platform::filesystem::share::open_share_root(&directory)
                .context("opening an approved share without ancestor read grants")?;
            ensure!(opened.metadata()?.is_dir(), "approved share is a directory");
            require_permission_denied(
                UnixStream::connect(directory.join("stream.socket")),
                "connecting to a host Unix stream inside an approved share",
            )?;
            match UnixDatagram::unbound() {
                Ok(datagram) => {
                    let path = directory.join("datagram.socket");
                    require_permission_denied(
                        datagram.connect(&path),
                        "connecting to a host Unix datagram inside an approved share",
                    )?;
                    require_permission_denied(
                        datagram.send_to(b"probe", path),
                        "sending to a host Unix datagram inside an approved share",
                    )?;
                }
                Err(error) => {
                    require_permission_denied::<()>(Err(error), "creating a VM Unix datagram")?;
                }
            }
        }
        Ok(())
    }

    fn bind_share_sockets(root: &Path) -> Result<Vec<(UnixListener, UnixDatagram)>> {
        let mut endpoints = Vec::new();
        for share in ["read-only", "writable"] {
            let directory = root.join(share);
            std::fs::create_dir_all(&directory)?;
            let listener = UnixListener::bind(directory.join("stream.socket"))?;
            let datagram = UnixDatagram::bind(directory.join("datagram.socket"))?;
            listener.set_nonblocking(true)?;
            datagram.set_nonblocking(true)?;
            endpoints.push((listener, datagram));
        }
        Ok(endpoints)
    }

    /// Launching through the real terra executable, both roles must be
    /// confined by their Seatbelt profile: host-file and program-exec denial,
    /// VM host-network denial including Unix sockets inside shares, share
    /// opening without ancestor read grants (also when the grant is spelled
    /// through a symlink), broker TCP-listener denial with UDP still bound,
    /// broker connectivity, inherited IPC, and read-only metadata. A launcher
    /// that cannot apply its spec must fail the launch before the worker runs.
    #[test]
    #[ignore = "requires native macOS and TERRA_BIN pointing to the newly built terra executable"]
    #[allow(
        clippy::too_many_lines,
        reason = "both sandboxed launches share the authority witnesses"
    )]
    fn sandboxed_workers_enforce_role_boundaries() -> Result<()> {
        let terra_bin = std::path::PathBuf::from(
            std::env::var_os("TERRA_BIN")
                .context("set TERRA_BIN to the native terra executable")?,
        );
        ensure!(
            terra_bin.is_absolute(),
            "TERRA_BIN must be an absolute path"
        );
        let state = std::env::home_dir().unwrap().join(".terra");
        std::fs::create_dir_all(&state)?;
        let root = tempfile::tempdir_in(&state)?;
        let metadata = root.path().join("host.pid");
        std::fs::write(&metadata, b"supervisor identity")?;
        terra_platform::filesystem::set_owner_only(&metadata, false)?;
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
        listener.set_nonblocking(true)?;
        let share_root = root.path().join("shares");
        let share_sockets = bind_share_sockets(&share_root)?;
        let symlinked_share = tempfile::tempdir()?;
        ensure!(
            std::fs::canonicalize(symlinked_share.path())? != symlinked_share.path(),
            "TMPDIR must be a symlinked path such as /tmp or the default /var/folders/... to test symlinked shares"
        );
        let executable = std::env::current_exe()?;
        for role in [Role::Vm, Role::Network] {
            let socket_path = root.path().join("agent.socket");
            let local_listener = UnixListener::bind(&socket_path)?;
            let mut local_client = UnixStream::connect(&socket_path)?;
            local_client.set_read_timeout(Some(Duration::from_secs(1)))?;
            local_client.write_all(b"ipc")?;
            let mut command = Command::new(&executable);
            command
                .args([
                    "--exact",
                    "macos::tests::sandboxed_worker_probe_child",
                    "--nocapture",
                ])
                .env(TEST_ENDPOINT, listener.local_addr()?.to_string())
                .env(TEST_METADATA, &metadata)
                .env(TEST_SHARE_ROOT, &share_root)
                .env(
                    TEST_SYMLINKED_SHARE,
                    std::fs::canonicalize(symlinked_share.path())?,
                );
            let mut grants = vec![Grant::new(&executable, Access::ReadOnly)];
            if role == Role::Vm {
                grants.push(Grant::new(&metadata, Access::ReadOnly));
                grants.push(Grant::new(share_root.join("read-only"), Access::ReadOnly));
                grants.push(Grant::new(share_root.join("writable"), Access::ReadWrite));
                grants.push(Grant::new(symlinked_share.path(), Access::ReadOnly));
            }
            let mut launch = prepare_launch_via(
                Launch {
                    role,
                    command,
                    grants,
                    staging_directory: &state,
                },
                &terra_bin,
            )?;
            launch.command.stdout(Stdio::piped()).stderr(Stdio::piped());
            let inherited_listener = if role == Role::Vm {
                Some(terra_platform::process::pass_descriptor(
                    &mut launch.command,
                    &File::from(OwnedFd::from(local_listener)),
                    TEST_LISTENER_FD,
                )?)
            } else {
                None
            };
            let SpawnedLaunch { child, .. } = launch.spawn(Duration::from_secs(10))?;
            drop(inherited_listener);
            let output = child.wait_with_output()?;
            assert!(output.status.success(), "{role:?}: {output:?}");
            match role {
                Role::Vm => {
                    assert_matches!(
                        listener.accept(),
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
                    );
                    let mut bytes = [0; 3];
                    local_client.read_exact(&mut bytes)?;
                    assert_eq!(&bytes, b"ack");
                }
                Role::Network => {
                    let (mut peer, _) = listener.accept()?;
                    peer.set_read_timeout(Some(Duration::from_secs(1)))?;
                    let mut bytes = [0; 6];
                    peer.read_exact(&mut bytes)?;
                    assert_eq!(&bytes, b"broker");
                }
                Role::Supervisor => unreachable!("the test has no supervisor child"),
            }
            std::fs::remove_file(socket_path)?;
        }
        for (listener, datagram) in share_sockets {
            assert_matches!(
                listener.accept(),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
            );
            let mut bytes = [0; 16];
            assert_matches!(
                datagram.recv(&mut bytes),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
            );
        }
        assert_eq!(std::fs::read(&metadata)?, b"supervisor identity");

        let mut command = Command::new(&executable);
        command.args(["--exact", "macos::tests::sandboxed_worker_probe_child"]);
        let mut launch = prepare_launch_via(
            Launch {
                role: Role::Network,
                command,
                grants: vec![Grant::new(&executable, Access::ReadOnly)],
                staging_directory: &state,
            },
            &terra_bin,
        )?;
        std::fs::write(launch.confinement.spec.path(), b"{}")?;
        let stderr_path = root.path().join("launcher.stderr");
        launch.command.stderr(File::create(&stderr_path)?);
        let started = std::time::Instant::now();
        let Err(error) = launch.spawn(Duration::from_secs(30)) else {
            panic!("a launcher with an unparsable spec must not confirm confinement");
        };
        assert!(started.elapsed() < Duration::from_secs(5), "{error:#}");
        let message = format!("{error:#}");
        assert!(
            message.contains("exited before verifying confinement"),
            "{message}"
        );
        let stderr = std::fs::read_to_string(&stderr_path)?;
        assert!(stderr.contains("missing field"), "{stderr}");
        Ok(())
    }
}
