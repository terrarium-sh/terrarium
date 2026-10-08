//! Signed App Sandbox workers with separate VM and network authority.

mod policy;

use super::{Access, Grant, Launch, PolicyBundle, Role, SpawnedLaunch};
use anyhow::{Context, Result, ensure};
use sha2::{Digest as _, Sha256};
use std::fmt::Write as _;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Command, ExitCode};
use std::time::Duration;

const CODESIGN: &str = "/usr/bin/codesign";
const ROLE_ENV: &str = "TERRA_MACOS_SANDBOX_ROLE";
const PROBE_ENV: &str = "TERRA_MACOS_SANDBOX_PROBE";
const ACTIVATION_FD: i32 = 9;
const ACTIVATION_ACK: u8 = 0x53;
const SIGNING_TIMEOUT: Duration = Duration::from_secs(30);

pub struct PreparedLaunch {
    pub command: Command,
    bundle: tempfile::TempDir,
    inherited: File,
    activation: UnixStream,
}

impl PreparedLaunch {
    pub fn spawn(self, identity_timeout: Duration) -> Result<SpawnedLaunch> {
        let Self {
            mut command,
            bundle,
            inherited,
            mut activation,
        } = self;
        ensure!(
            !identity_timeout.is_zero(),
            "macOS confinement activation needs a deadline"
        );
        activation.set_read_timeout(Some(identity_timeout))?;
        let spawned = command.spawn();
        drop((command, inherited));
        let mut child = spawned.context("starting macOS App Sandbox worker")?;
        let mut acknowledgement = [0];
        let result = activation
            .read_exact(&mut acknowledgement)
            .map_err(anyhow::Error::from)
            .and_then(|()| {
                ensure!(
                    acknowledgement == [ACTIVATION_ACK],
                    "macOS worker sent an invalid activation acknowledgement"
                );
                Ok(())
            });
        if let Err(error) = result {
            let _ = terra_platform::process::kill_vm_child(&mut child);
            let _ = child.kill();
            let _ = child.wait();
            return Err(error
                .context("macOS sandbox worker did not verify confinement before initialization"));
        }
        Ok(SpawnedLaunch {
            pid: child.id(),
            child,
            sandbox_bundle: Some(bundle),
        })
    }
}

pub fn prepare_launch(launch: Launch<'_>) -> Result<PreparedLaunch> {
    let Launch {
        role,
        command,
        grants,
        die_with_parent,
        policy,
        staging_directory,
    } = launch;
    ensure!(
        role != Role::Supervisor,
        "the macOS supervisor uses the trusted lifecycle launcher"
    );
    ensure!(
        die_with_parent,
        "macOS sandbox workers require supervisor parent-death handling"
    );
    if let Some(policy) = policy {
        ensure!(
            policy == policy::marker(role),
            "macOS worker policy does not match its trusted launch role"
        );
    }
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
    let bundle = tempfile::Builder::new()
        .prefix("macos-worker-")
        .tempdir_in(staging_directory)?;
    let probe = bundle.path().join("host-only-probe");
    std::fs::write(&probe, b"macOS App Sandbox must deny this host file")?;
    terra_platform::filesystem::set_owner_only(&probe, false)?;
    let entitlements = policy::render_entitlements(role, &grants, &probe)?;
    let identifier = build_identifier(role, executable, &entitlements)?;
    let application = bundle.path().join("Worker.app");
    let binary_directory = application.join("Contents/MacOS");
    std::fs::create_dir_all(&binary_directory)?;
    let worker = binary_directory.join("terra");
    std::fs::copy(executable, &worker).context("copying the executable for macOS role signing")?;
    let info = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict>\n<key>CFBundleIdentifier</key><string>{identifier}</string>\n<key>CFBundleExecutable</key><string>terra</string>\n<key>CFBundlePackageType</key><string>APPL</string>\n<key>CFBundleVersion</key><string>1</string>\n<key>LSMinimumSystemVersion</key><string>15.0</string>\n<key>LSUIElement</key><true/>\n</dict></plist>\n"
    );
    std::fs::write(application.join("Contents/Info.plist"), info)?;
    let entitlement_path = bundle.path().join("entitlements.plist");
    std::fs::write(&entitlement_path, entitlements)?;
    let identity = std::env::var_os("TERRA_MACOS_SIGN_IDENTITY").unwrap_or_else(|| "-".into());
    let mut sign = Command::new(CODESIGN);
    sign.args(["--force", "--sign"])
        .arg(identity)
        .args(["--timestamp=none", "--options", "runtime", "--identifier"])
        .arg(identifier)
        .arg("--entitlements")
        .arg(&entitlement_path)
        .arg(&application);
    run_codesign(&mut sign)
        .context("signing the macOS worker; install Apple's signing tools or set TERRA_MACOS_SIGN_IDENTITY to a local identity")?;
    run_codesign(
        Command::new(CODESIGN)
            .args(["--verify", "--strict"])
            .arg(&application),
    )
    .context("verifying the signed macOS worker")?;
    let mut worker_command = Command::new(worker);
    worker_command.args(command.get_args()).env_clear();
    for (name, value) in command.get_envs() {
        if let Some(value) = value {
            worker_command.env(name, value);
        }
    }
    worker_command
        .env(ROLE_ENV, role.name())
        .env(PROBE_ENV, probe);
    worker_command.current_dir(command.get_current_dir().unwrap_or(Path::new("/")));
    let (activation, child_activation) = UnixStream::pair()?;
    let inherited = terra_platform::process::pass_descriptor(
        &mut worker_command,
        &File::from(OwnedFd::from(child_activation)),
        ACTIVATION_FD,
    )?;
    Ok(PreparedLaunch {
        command: worker_command,
        bundle,
        inherited,
        activation,
    })
}

fn run_codesign(command: &mut Command) -> Result<()> {
    let mut stderr = tempfile::tempfile().context("creating codesign stderr capture")?;
    let mut child = command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(stderr.try_clone()?)
        .spawn()
        .context("starting codesign")?;
    let deadline = std::time::Instant::now() + SIGNING_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error).context("waiting for codesign");
            }
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("codesign did not finish within {SIGNING_TIMEOUT:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let mut message = String::new();
    std::io::Seek::rewind(&mut stderr)?;
    stderr.read_to_string(&mut message)?;
    ensure!(status.success(), "codesign failed ({status}): {message}");
    Ok(())
}

fn build_identifier(role: Role, executable: &Path, entitlements: &str) -> Result<String> {
    let mut digest = Sha256::new();
    let mut file = File::open(executable)?;
    let mut bytes = [0; 8192];
    loop {
        let length = file.read(&mut bytes)?;
        if length == 0 {
            break;
        }
        digest.update(&bytes[..length]);
    }
    digest.update(entitlements.as_bytes());
    let mut identifier = format!("is.alis.terrarium.worker.{}.", role.name());
    for byte in digest.finalize() {
        let _ = write!(identifier, "{byte:02x}");
    }
    Ok(identifier)
}

pub fn resolve_policy(policy: Option<&Path>, allow_fallback: bool) -> Result<PolicyBundle> {
    ensure!(
        policy.is_none(),
        "macOS uses signed App Sandbox role policies; remove vm.bwrap.policy (Linux seccomp overrides cannot be used on macOS)"
    );
    let _ = allow_fallback;
    Ok(PolicyBundle {
        supervisor: policy::marker(Role::Supervisor).to_vec(),
        vm: policy::marker(Role::Vm).to_vec(),
        network: policy::marker(Role::Network).to_vec(),
    })
}

pub fn install_policy(policy: &[u8]) -> Result<()> {
    ensure!(
        policy == policy::marker(Role::Supervisor),
        "macOS supervisor policy marker is invalid; worker authority must be installed by the signed launcher"
    );
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

pub fn verify_worker_role(role: Role) -> Result<()> {
    let Some(launched_role) = std::env::var_os(ROLE_ENV) else {
        return Ok(());
    };
    ensure!(
        launched_role == role.name() && role != Role::Supervisor,
        "macOS worker role differs from its trusted sandbox launch role"
    );
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

pub fn run_launcher_worker(
    arguments: impl Iterator<Item = std::ffi::OsString>,
) -> Result<ExitCode> {
    ensure!(
        arguments.eq([std::ffi::OsString::from("--version")]),
        "terra {} accepts only --version",
        super::LAUNCHER_WORKER_ARG
    );
    println!("terra macOS App Sandbox launcher v1 (host validation pending)");
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::FromRawFd;
    use std::os::unix::net::{UnixDatagram, UnixListener};
    use std::process::Stdio;

    const TEST_ENDPOINT: &str = "TERRA_MACOS_TEST_ENDPOINT";
    const TEST_METADATA: &str = "TERRA_MACOS_TEST_METADATA";
    const TEST_SHARE_ROOT: &str = "TERRA_MACOS_TEST_SHARE_ROOT";
    const TEST_LISTENER_FD: i32 = 10;

    #[test]
    fn direct_workers_require_no_sandbox_activation() -> Result<()> {
        const CHILD: &str = "TERRA_MACOS_DIRECT_WORKER_TEST";
        if std::env::var_os(CHILD).is_some() {
            for role in Role::ALL {
                verify_worker_role(role)?;
            }
            return Ok(());
        }
        let output = Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "macos::tests::direct_workers_require_no_sandbox_activation",
            ])
            .env(CHILD, "1")
            .env_remove(ROLE_ENV)
            .env_remove(PROBE_ENV)
            .output()?;
        assert!(output.status.success(), "{output:?}");
        Ok(())
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
    #[allow(unsafe_code)]
    fn signed_worker_probe_child() -> Result<()> {
        let Some(endpoint) = std::env::var_os(TEST_ENDPOINT) else {
            return Ok(());
        };
        let role = match std::env::var(ROLE_ENV)?.as_str() {
            "vm" => Role::Vm,
            "network" => Role::Network,
            value => anyhow::bail!("unexpected signed test role {value}"),
        };
        verify_worker_role(role)?;
        let address = endpoint
            .to_str()
            .context("invalid native test endpoint")?
            .parse()?;
        let connection = std::net::TcpStream::connect_timeout(&address, Duration::from_secs(1));
        match role {
            Role::Vm => {
                require_permission_denied(connection, "connecting to the host test listener")?;
                verify_share_socket_denial()?;
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
            Role::Network => connection?.write_all(b"broker")?,
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

    fn verify_share_socket_denial() -> Result<()> {
        let root = std::env::var_os(TEST_SHARE_ROOT).context("missing native test shares")?;
        for share in ["read-only", "writable"] {
            let directory = Path::new(&root).join(share);
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

    /// This check proves runtime App Sandbox activation, VM host-network
    /// denial including Unix sockets inside shares, broker connectivity,
    /// inherited IPC, and read-only metadata.
    /// A code signature by itself cannot pass the activation handshake.
    #[test]
    #[ignore = "requires native macOS App Sandbox and codesign"]
    #[allow(
        clippy::too_many_lines,
        reason = "both signed launches share the authority witnesses"
    )]
    fn signed_workers_enforce_role_boundaries() -> Result<()> {
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
                    "macos::tests::signed_worker_probe_child",
                    "--nocapture",
                ])
                .env(TEST_ENDPOINT, listener.local_addr()?.to_string())
                .env(TEST_METADATA, &metadata)
                .env(TEST_SHARE_ROOT, &share_root);
            let mut grants = vec![Grant::new(&executable, Access::ReadOnly)];
            if role == Role::Vm {
                grants.push(Grant::new(&metadata, Access::ReadOnly));
                grants.push(Grant::new(share_root.join("read-only"), Access::ReadOnly));
                grants.push(Grant::new(share_root.join("writable"), Access::ReadWrite));
            }
            let mut launch = prepare_launch(Launch {
                role,
                command,
                grants,
                die_with_parent: true,
                policy: Some(policy::marker(role)),
                staging_directory: &state,
            })?;
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
            let SpawnedLaunch {
                child,
                sandbox_bundle,
                ..
            } = launch.spawn(Duration::from_secs(10))?;
            drop(inherited_listener);
            let output = child.wait_with_output()?;
            assert!(output.status.success(), "{role:?}: {output:?}");
            drop(sandbox_bundle);
            match role {
                Role::Vm => {
                    assert!(
                        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
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
            assert!(
                matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
            );
            let mut bytes = [0; 16];
            assert!(
                matches!(datagram.recv(&mut bytes), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
            );
        }
        assert_eq!(std::fs::read(&metadata)?, b"supervisor identity");
        Ok(())
    }
}
