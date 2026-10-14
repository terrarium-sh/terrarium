use super::boot::{self, BootSpec, BrokerMetadata, LaunchedVm};
use crate::process::SupervisedChild;
use crate::state::{self, BoxRef};
use crate::sys;
use anyhow::{Context, Result, ensure};
use std::fs::File;
use std::io::{Read, Write};
use std::net::Shutdown;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};
#[cfg(any(target_os = "macos", windows))]
use terra_platform::local_socket::LocalListener;
use terra_platform::local_socket::{
    AsyncLocalStream, LocalStream, OwnedSocket, create_local_pair, receive_sockets, send_sockets,
};
use terra_sandbox::{Launch, Role};

pub(crate) const SUPERVISOR_ARG: &str = "__supervisor";
pub(crate) const NETWORK_ARG: &str = "__network";
pub(crate) const NETWORK_FD: i32 = 7;
#[cfg(any(target_os = "macos", windows))]
pub(crate) const AGENT_LISTENER_FD: i32 = 10;
#[cfg(any(target_os = "macos", windows))]
pub(crate) const CONTROL_LISTENER_FD: i32 = 11;
const CONFIG_FD: i32 = 8;
const STARTUP_TIMEOUT: Duration = Duration::from_secs(90);
const BROKER_STARTUP_TIMEOUT: Duration = Duration::from_secs(10);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);

pub(super) fn spawn(bx: &BoxRef, spec: &BootSpec, lock: &File, exe: &Path) -> Result<LaunchedVm> {
    super::resources::prepare_volumes(spec, bx)?;
    let mut child_spec = spec.clone();
    child_spec.host_publishes_pid = true;
    ensure!(
        child_spec.network_broker.is_none(),
        "broker metadata must be supplied by the supervisor"
    );
    let bytes = boot::encode_boot_spec(&child_spec)?;
    let diagnostics = sys::create_regular_file(&bx.get_dir().join("launcher.log"))?;
    let mut command = Command::new(exe);
    command
        .arg(SUPERVISOR_ARG)
        .arg(bx.get_dir())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(diagnostics);
    let guard = sys::supervise_supervisor_child(
        &mut command,
        spec.foreground || spec.mode == terra_protocol::PlanMode::Create,
    )?;
    let inherited = sys::pass_lock(&mut command, lock)?;
    #[cfg(windows)]
    let spawned = terra_platform::process::spawn_without_standard_handles(&mut command);
    #[cfg(unix)]
    let spawned = command.spawn();
    let mut child = spawned.context("starting box supervisor")?;
    drop(inherited);
    if let Some(guard) = &guard
        && let Err(error) = sys::attach_vm_child(guard, &child)
    {
        let _ = sys::kill_vm_child(&mut child);
        let _ = child.wait();
        return Err(error).context("attaching box supervisor");
    }
    if let Err(error) = boot::send_startup_input(&mut child, bytes) {
        let _ = sys::kill_vm_child(&mut child);
        let _ = child.wait();
        return Err(error);
    }
    Ok(LaunchedVm {
        child,
        _guard: guard,
    })
}

pub(crate) fn run(dir: PathBuf) -> Result<ExitCode> {
    eprintln!(
        "terra boot_stage=supervisor_start unix_time_ns={}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    sys::validate_host_root()?;
    #[cfg(target_os = "linux")]
    enable_subreaping()?;
    let lock = sys::claim_inherited_lock(&dir.join(state::PID_FILE))
        .context("missing supervisor run lock")?;
    let result = run_box(dir, &lock);
    #[cfg(target_os = "linux")]
    let cleanup = reap_adopted_children();
    #[cfg(not(target_os = "linux"))]
    let cleanup: Result<()> = Ok(());
    match (result, cleanup) {
        (Ok(code), Ok(())) => Ok(code),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(error.context(format!("{cleanup:#}"))),
    }
}

fn run_box(dir: PathBuf, lock: &File) -> Result<ExitCode> {
    crate::process::install_interrupt_handler()?;
    let mut boot = read_supervisor_input(std::io::stdin(), BROKER_STARTUP_TIMEOUT)?;
    let bx = BoxRef::from_state_dir(dir, &boot.project_dir);
    let supervisor_identity =
        sys::create_regular_file(&bx.get_dir().join(state::SUPERVISOR_PID_FILE))?;
    BoxRef::publish_pid(&supervisor_identity, std::process::id(), false)?;
    let identity = sys::create_regular_file(&bx.get_dir().join(state::HOST_PID_FILE))?;
    #[cfg(any(target_os = "macos", windows))]
    prepare_vm_outputs(&bx)?;
    let executable = std::env::current_exe()?;
    let (mut broker, endpoint) = start_optional_broker(&executable, &mut boot)?
        .map_or((None, None), |(broker, endpoint)| {
            (Some(broker), Some(endpoint))
        });
    let mut launch = super::launcher::prepare_vm_launch(&boot, &bx, &executable)?;
    let command = &mut launch.command;
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    #[cfg(any(target_os = "macos", windows))]
    let inherited_listeners = pass_vm_listeners(command, &bx, boot.mode)?;
    let inherited = endpoint
        .as_ref()
        .map(|endpoint| sys::pass_ipc(command, endpoint, NETWORK_FD))
        .transpose()?;
    let inherited_lock = sys::pass_lock(command, lock)?;
    drop(endpoint);
    let guard = supervise_worker_child(command)?;
    let spawned = launch.spawn(BROKER_STARTUP_TIMEOUT)?;
    drop((inherited, inherited_lock));
    #[cfg(any(target_os = "macos", windows))]
    drop(inherited_listeners);
    let vm_pid = spawned.pid;
    let mut vm = SupervisedChild::from_launch(spawned, guard)?;
    boot::publish_vm_pid(vm_pid, &bx, lock, &identity, boot.mode)?;
    boot::send_startup_input(vm.child_mut(), boot::encode_boot_spec(&boot)?)?;
    let ready = boot::start_ready_reader(vm.child_mut())?;
    terra_sandbox::restrict_role(Role::Supervisor)?;
    let result = supervise(&bx, &mut vm, broker.as_mut(), &ready, STARTUP_TIMEOUT);
    drop((vm, broker));
    result
}

fn start_optional_broker(
    executable: &Path,
    boot: &mut BootSpec,
) -> Result<Option<(SupervisedChild, LocalStream)>> {
    ensure!(
        boot.network_broker.is_none(),
        "broker metadata must be supplied by the supervisor"
    );
    if !boot.cfg.network.enabled {
        return Ok(None);
    }
    let mut config = build_broker_config(boot)?;
    let host_listeners = terra_network::bind_listeners(&mut config)?;
    let listeners = config.listeners.clone();
    let (endpoint, broker_endpoint) = create_local_pair()?;
    let (broker, ready) = start_broker(executable, &config, host_listeners, broker_endpoint)?;
    boot.network_broker = Some(BrokerMetadata { ready, listeners });
    Ok(Some((broker, endpoint)))
}

#[cfg(any(target_os = "macos", windows))]
fn prepare_vm_outputs(bx: &BoxRef) -> Result<()> {
    #[cfg(target_os = "macos")]
    std::fs::create_dir_all(bx.get_dir().join("runtime-logs"))?;
    #[cfg(windows)]
    sys::create_regular_file(&bx.get_dir().join(state::LOG_FILE))?;
    sys::create_regular_file(&bx.get_dir().join(state::DIAGNOSTICS_LOG))?;
    Ok(())
}

#[cfg(any(target_os = "macos", windows))]
fn pass_vm_listeners(
    command: &mut Command,
    bx: &BoxRef,
    mode: terra_protocol::PlanMode,
) -> Result<Vec<LocalListener>> {
    let mut paths = vec![(AGENT_LISTENER_FD, bx.get_dir().join(state::AGENT_SOCKET))];
    if mode == terra_protocol::PlanMode::Run {
        paths.push((
            CONTROL_LISTENER_FD,
            bx.get_dir().join(state::CONTROL_SOCKET),
        ));
    }
    let mut inherited = Vec::new();
    for (descriptor, path) in paths {
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("removing previous VM listener"),
        }
        let listener = LocalListener::bind(&path)?;
        sys::set_owner_only(&path, false)?;
        inherited.push(sys::pass_listener(command, &listener, descriptor)?);
    }
    Ok(inherited)
}

fn supervise(
    bx: &BoxRef,
    vm: &mut SupervisedChild,
    mut broker: Option<&mut SupervisedChild>,
    ready: &std::sync::mpsc::Receiver<Result<bool>>,
    startup_timeout: Duration,
) -> Result<ExitCode> {
    let deadline = Instant::now() + startup_timeout;
    let mut is_ready = false;
    loop {
        ensure!(
            !crate::process::is_interrupted(),
            "box supervisor interrupted"
        );
        let mut vm_status = vm.try_wait()?;
        if vm_status.is_none()
            && let Some(broker_child) = broker.as_mut()
            && let Some(status) = broker_child.try_wait()?
        {
            if is_ready {
                log::warn!("{bx}'s network broker stopped ({status}); networking is unavailable");
                broker = None;
            } else {
                if status.success() {
                    vm_status = vm.wait(CLEANUP_TIMEOUT, true).ok();
                }
                ensure!(
                    vm_status.is_some(),
                    "{bx}'s network broker stopped unexpectedly ({status}); stopping the box"
                );
            }
        }
        if let Some(status) = vm_status {
            if !is_ready
                && ready
                    .recv_timeout(CLEANUP_TIMEOUT)
                    .is_ok_and(|result| matches!(result, Ok(true)))
            {
                boot::write_agent_ready();
            }
            if let Some(broker) = broker.as_mut()
                && let Ok(broker_status) = broker.wait(CLEANUP_TIMEOUT, false)
            {
                ensure!(
                    is_ready || broker_status.success(),
                    "{bx}'s network broker stopped unexpectedly ({broker_status}) during VM shutdown"
                );
            }
            let code = status
                .code()
                .unwrap_or_else(|| 128 + sys::find_terminating_signal(status).unwrap_or(0));
            return Ok(ExitCode::from(crate::exit_status_byte(code)));
        }
        if !is_ready {
            match ready.try_recv() {
                Ok(result) => {
                    ensure!(result?, "VM closed its startup pipe before readiness");
                    is_ready = true;
                    boot::write_agent_ready();
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    anyhow::bail!("VM startup reader disconnected")
                }
            }
            ensure!(
                is_ready || Instant::now() < deadline,
                "timed out waiting for guest agent readiness"
            );
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

pub(crate) fn build_broker_config(spec: &BootSpec) -> Result<terra_network::config::Config> {
    ensure!(
        spec.cfg.network.enabled,
        "local-only VM does not use a network broker"
    );
    let mappings = if spec.mode == terra_protocol::PlanMode::Run {
        crate::policy::network::rules::parse_port_mappings(&spec.cfg.network.ports)?
    } else {
        Vec::new()
    };
    let mut listeners = Vec::new();
    for (index, mapping) in mappings.into_iter().enumerate() {
        for (offset, address) in [
            (1, std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            (2, std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
        ] {
            listeners.push(terra_network::config::PublishedListener {
                grant: u32::try_from(index * 2 + offset)?,
                address: (address, mapping.host).into(),
                transport: mapping.transport,
            });
        }
    }
    Ok(terra_network::config::Config {
        policy: spec.cfg.network.host_policy()?,
        listeners,
    })
}

pub(crate) fn start_broker(
    executable: &Path,
    config: &terra_network::config::Config,
    host_listeners: Vec<socket2::Socket>,
    endpoint: LocalStream,
) -> Result<(SupervisedChild, terra_network::config::Ready)> {
    let (startup, configuration) = create_local_pair()?;
    startup.set_read_timeout(Some(BROKER_STARTUP_TIMEOUT))?;
    startup.set_write_timeout(Some(BROKER_STARTUP_TIMEOUT))?;
    let mut command = Command::new(executable);
    command.arg(NETWORK_ARG);
    let mut launch = terra_sandbox::prepare_launch(Launch {
        role: Role::Network,
        command,
        grants: Vec::new(),
        staging_directory: &state::get_terra_home_path()?,
    })?;
    let command = &mut launch.command;
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    let files = [
        sys::pass_ipc(command, &endpoint, NETWORK_FD)?,
        sys::pass_ipc(command, &configuration, CONFIG_FD)?,
    ];
    drop((endpoint, configuration));
    let guard = supervise_worker_child(command)?;
    let spawned = launch.spawn(BROKER_STARTUP_TIMEOUT)?;
    drop(files);
    let broker_pid = spawned.pid;
    let broker = SupervisedChild::from_launch(spawned, guard)?;
    let bytes = serde_json::to_vec(&config)?;
    ensure!(
        bytes.len() <= terra_network::config::MAX_STARTUP_BYTES,
        "broker startup configuration exceeds its limit"
    );
    let startup_input = BrokerStartup {
        listeners: host_listeners.into_iter().map(OwnedSocket::from).collect(),
        broker_pid,
        config: bytes,
    };
    let ready = exchange_broker_startup(startup, startup_input, BROKER_STARTUP_TIMEOUT)?;
    Ok((broker, ready))
}

/// The outbound sockets a sandboxed broker's launcher opens for it.
struct LauncherOutbound(terra_sandbox::LauncherSockets);

impl terra_network::OutboundSockets for LauncherOutbound {
    fn connect_tcp(
        &self,
        peer: std::net::SocketAddr,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<socket2::Socket>> + Send>>
    {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        self.0.connect_tcp(
            peer,
            Box::new(move |reply| {
                let _ = sender.send(reply);
            }),
        );
        Box::pin(async move {
            receiver
                .await
                .unwrap_or_else(|_| Err(std::io::ErrorKind::BrokenPipe.into()))
        })
    }

    fn bind_udp(&self, domain: socket2::Domain) -> std::io::Result<socket2::Socket> {
        self.0.bind_udp(domain)
    }
}

fn read_supervisor_input(
    reader: impl Read + Send + 'static,
    timeout: Duration,
) -> Result<BootSpec> {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("supervisor-startup".into())
        .spawn(move || {
            let _ = sender.send(boot::read_boot_spec(reader));
        })?;
    receiver
        .recv_timeout(timeout)
        .context("waiting for supervisor startup input")?
}

/// What the supervisor sends a starting broker: its published listeners, bound before the broker
/// or the supervisor's own sandbox exists, then its configuration.
struct BrokerStartup {
    listeners: Vec<OwnedSocket>,
    broker_pid: u32,
    config: Vec<u8>,
}

fn exchange_broker_startup(
    mut startup: LocalStream,
    input: BrokerStartup,
    timeout: Duration,
) -> Result<terra_network::config::Ready> {
    let interrupt = startup.try_clone()?;
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("network-startup".into())
        .spawn(move || {
            let result = (|| {
                send_sockets(&startup, &input.listeners, input.broker_pid)?;
                drop(input.listeners);
                startup.write_all(&input.config)?;
                startup.shutdown(Shutdown::Write)?;
                let ready: terra_network::config::Ready = terra_protocol::read_frame_with_limit(
                    &mut startup,
                    terra_network::config::MAX_READY_BYTES,
                )?
                .context("network broker closed its readiness channel")?;
                ensure!(
                    ready.host_service_ports.len() <= terra_policy::MAX_EXPANDED_RULES,
                    "invalid broker readiness metadata"
                );
                Ok(ready)
            })();
            let _ = sender.send(result);
        })?;
    let result = receiver
        .recv_timeout(timeout)
        .context("waiting for network broker readiness");
    if result.is_err() {
        let _ = interrupt.shutdown(Shutdown::Both);
    }
    result?
}

#[cfg(unix)]
fn supervise_worker_child(command: &mut Command) -> Result<Option<sys::VmChildGuard>> {
    sys::supervise_vm_child(command, true).context("supervising VM worker")
}

#[cfg(windows)]
#[allow(
    clippy::unnecessary_wraps,
    reason = "Unix retains a fallible process guard"
)]
fn supervise_worker_child(_command: &mut Command) -> Result<Option<sys::VmChildGuard>> {
    Ok(None)
}

pub(crate) fn run_broker() -> Result<ExitCode> {
    #[cfg(unix)]
    super::resources::raise_broker_open_files()?;
    let mut startup = sys::claim_ipc(CONFIG_FD)?;
    startup.set_read_timeout(Some(BROKER_STARTUP_TIMEOUT))?;
    startup.set_write_timeout(Some(BROKER_STARTUP_TIMEOUT))?;
    let listeners = receive_sockets(&startup)?
        .into_iter()
        .map(socket2::Socket::from)
        .collect();
    let mut bytes = Vec::new();
    (&mut startup)
        .take((terra_network::config::MAX_STARTUP_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= terra_network::config::MAX_STARTUP_BYTES,
        "broker startup configuration exceeds its limit"
    );
    let config: terra_network::config::Config = serde_json::from_slice(&bytes)?;
    let sockets = match terra_sandbox::LauncherSockets::claim()? {
        Some(launcher) => {
            terra_network::SocketSource::Delegated(std::sync::Arc::new(LauncherOutbound(launcher)))
        }
        None => terra_network::SocketSource::Native,
    };
    let channel = sys::claim_ipc(NETWORK_FD)?;
    channel.set_nonblocking(true)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(terra_network::MAX_RESOLVERS)
        .build()?;
    let result = runtime.block_on(async move {
        let broker = terra_network::Broker::new(&config, listeners, sockets)?;
        startup.write_all(&terra_protocol::encode_frame_with_limit(
            &broker.ready(),
            terra_network::config::MAX_READY_BYTES,
        )?)?;
        drop(startup);
        broker.serve(AsyncLocalStream::from_std(channel)?).await
    });
    runtime.shutdown_timeout(Duration::from_secs(1));
    result?;
    Ok(ExitCode::SUCCESS)
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn enable_subreaping() -> Result<()> {
    // SAFETY: prctl sets a process-local flag and uses no pointers.
    ensure!(
        unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } == 0,
        "enabling supervisor child reaping: {}",
        std::io::Error::last_os_error()
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn reap_adopted_children() -> Result<()> {
    let deadline = Instant::now() + CLEANUP_TIMEOUT;
    loop {
        let mut status = 0;
        // SAFETY: the supervisor owns its adopted children; status is writable.
        let pid = unsafe { libc::waitpid(-1, &raw mut status, libc::WNOHANG) };
        if pid > 0 {
            continue;
        }
        if pid < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ECHILD) {
                return Ok(());
            }
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(error.into());
            }
        }
        ensure!(
            Instant::now() < deadline,
            "supervisor children did not exit after cleanup"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn startup_input(config: &[u8]) -> BrokerStartup {
        BrokerStartup {
            listeners: Vec::new(),
            broker_pid: std::process::id(),
            config: config.to_vec(),
        }
    }

    /// The broker cannot read host interfaces itself, so without these addresses its floor would let
    /// a guest reach the host's own public IPs.
    #[test]
    fn broker_config_carries_the_host_interface_addresses() {
        let boot = BootSpec {
            cfg: crate::config::Config::default(),
            project_dir: PathBuf::from("/project"),
            root: false,
            mode: terra_protocol::PlanMode::Run,
            foreground: false,
            host_publishes_pid: false,
            network_broker: None,
        };
        let expected = sys::host_addresses().unwrap();
        assert!(!expected.is_empty(), "host reports no interface addresses");
        assert_eq!(
            build_broker_config(&boot).unwrap().policy.host_addresses,
            expected
        );
    }

    #[test]
    fn local_only_startup_needs_no_broker_executable_or_channel() {
        let mut boot = BootSpec {
            cfg: crate::config::Config {
                network: crate::config::Network {
                    enabled: false,
                    ..crate::config::Network::default()
                },
                ..crate::config::Config::default()
            },
            project_dir: PathBuf::from("/project"),
            root: false,
            mode: terra_protocol::PlanMode::Run,
            foreground: false,
            host_publishes_pid: false,
            network_broker: None,
        };
        assert!(
            start_optional_broker(Path::new("missing-broker-executable"), &mut boot)
                .unwrap()
                .is_none()
        );
        assert!(boot.network_broker.is_none());
    }

    #[test]
    fn startup_exchange_rejects_invalid_metadata_and_absolute_timeout() {
        {
            let ready = terra_network::config::Ready {
                host_service_ports: vec![None; terra_policy::MAX_EXPANDED_RULES + 1],
            };
            let (startup, mut broker) = create_local_pair().unwrap();
            let worker = std::thread::spawn(move || {
                assert!(receive_sockets(&broker).unwrap().is_empty());
                let mut input = Vec::new();
                broker.read_to_end(&mut input).unwrap();
                broker
                    .write_all(
                        &terra_protocol::encode_frame_with_limit(
                            &ready,
                            terra_network::config::MAX_READY_BYTES,
                        )
                        .unwrap(),
                    )
                    .unwrap();
                assert_eq!(input, b"config");
            });
            let error =
                exchange_broker_startup(startup, startup_input(b"config"), Duration::from_secs(2))
                    .unwrap_err();
            assert!(
                error.to_string().contains("invalid broker readiness"),
                "{error:#}"
            );
            worker.join().unwrap();
        }
        let (startup, mut broker) = create_local_pair().unwrap();
        let started = Instant::now();
        let error = exchange_broker_startup(startup, startup_input(b""), Duration::from_millis(50))
            .unwrap_err();
        assert!(error.to_string().contains("broker readiness"));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(receive_sockets(&broker).unwrap().is_empty());
        let mut byte = [0];
        assert_eq!(broker.read(&mut byte).unwrap(), 0);
    }

    #[test]
    fn supervisor_input_deadline_covers_an_open_startup_pipe() {
        let (input, writer) = create_local_pair().unwrap();
        let started = Instant::now();
        let error = read_supervisor_input(input, Duration::from_millis(50))
            .err()
            .unwrap();
        assert!(error.to_string().contains("supervisor startup input"));
        assert!(started.elapsed() < Duration::from_secs(1));
        drop(writer);
    }

    #[cfg(target_os = "linux")]
    const TEST_CHILD: &str = "vm::supervisor::tests::supervisor_test_child";

    #[cfg(target_os = "linux")]
    fn build_test_command(mode: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", TEST_CHILD, "--nocapture"])
            .env("TERRA_TEST_SUPERVISOR_MODE", mode);
        command
    }

    #[cfg(target_os = "linux")]
    fn spawn_test_worker(mode: &str) -> SupervisedChild {
        let mut command = build_test_command(mode);
        command
            .stdin(if mode == "fail-after-input" {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let guard = sys::supervise_vm_child(&mut command, true).unwrap();
        SupervisedChild::new(command.spawn().unwrap(), guard).unwrap()
    }

    #[cfg(target_os = "linux")]
    fn exercise_broker_first_shutdown(mode: &str) {
        let directory = tempfile::tempdir().unwrap();
        let bx = BoxRef::from_state_dir(directory.path().into(), directory.path());
        let mut command = build_test_command("fail-after-input");
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let guard = sys::supervise_vm_child(&mut command, true).unwrap();
        let mut vm = SupervisedChild::new(command.spawn().unwrap(), guard).unwrap();
        let mut broker = spawn_test_worker("success");
        broker.wait(CLEANUP_TIMEOUT, false).unwrap();
        assert!(vm.try_wait().unwrap().is_none());
        let (sender, receiver) = std::sync::mpsc::channel();
        let notification = if mode == "invalid" {
            Err(anyhow::anyhow!("invalid readiness"))
        } else {
            Ok(mode == "ready")
        };
        sender.send(notification).unwrap();
        let mut input = vm.child_mut().stdin.take().unwrap();
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(500));
            input.write_all(&[1]).unwrap();
        });
        assert_eq!(
            supervise(
                &bx,
                &mut vm,
                Some(&mut broker),
                &receiver,
                Duration::from_secs(5),
            )
            .unwrap(),
            ExitCode::from(7)
        );
        release.join().unwrap();
    }

    #[cfg(target_os = "linux")]
    fn exercise_ready_broker_loss() {
        let directory = tempfile::tempdir().unwrap();
        let bx = BoxRef::from_state_dir(directory.path().into(), directory.path());
        let mut vm = spawn_test_worker("fail-after-input");
        let mut broker = spawn_test_worker("fail-after-input");
        let vm_pid = vm.child_mut().id();
        let broker_pid = broker.child_mut().id();
        let mut vm_input = vm.child_mut().stdin.take().unwrap();
        let mut broker_input = broker.child_mut().stdin.take().unwrap();
        let release = std::thread::spawn(move || {
            std::io::stdin().read_exact(&mut [0]).unwrap();
            broker_input.write_all(&[1]).unwrap();
            let deadline = Instant::now() + CLEANUP_TIMEOUT;
            while sys::read_process_start_time(broker_pid).is_some() {
                assert!(Instant::now() < deadline, "broker exit was not reaped");
                std::thread::sleep(Duration::from_millis(10));
            }
            assert!(sys::read_process_start_time(vm_pid).is_some());
            vm_input.write_all(&[1]).unwrap();
        });
        let (sender, receiver) = std::sync::mpsc::channel();
        sender.send(Ok(true)).unwrap();
        assert_eq!(
            supervise(
                &bx,
                &mut vm,
                Some(&mut broker),
                &receiver,
                Duration::from_secs(5),
            )
            .unwrap(),
            ExitCode::from(7)
        );
        release.join().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn supervisor_test_child() {
        let Ok(mode) = std::env::var("TERRA_TEST_SUPERVISOR_MODE") else {
            return;
        };
        match mode.as_str() {
            "wait" => std::thread::sleep(Duration::from_secs(30)),
            "fail" => std::process::exit(23),
            "success" => std::process::exit(0),
            "fail-after-input" => {
                std::io::stdin().read_exact(&mut [0]).unwrap();
                std::process::exit(7);
            }
            "ready" | "not-ready" | "invalid" => exercise_broker_first_shutdown(&mode),
            "broker-loss" => exercise_ready_broker_loss(),
            "parent" => {
                let mut workers = [spawn_test_worker("wait"), spawn_test_worker("wait")];
                let pids = workers.each_mut().map(|worker| worker.child_mut().id());
                std::fs::write(
                    std::env::var_os("TERRA_TEST_SUPERVISOR_PIDS").unwrap(),
                    serde_json::to_vec(&pids).unwrap(),
                )
                .unwrap();
                loop {
                    std::thread::park();
                }
            }
            "parent-death" => {
                enable_subreaping().unwrap();
                let directory = tempfile::tempdir().unwrap();
                let pids_path = directory.path().join("workers");
                let mut command = build_test_command("parent");
                command.env("TERRA_TEST_SUPERVISOR_PIDS", &pids_path);
                let mut parent = SupervisedChild::new(command.spawn().unwrap(), None).unwrap();
                let deadline = Instant::now() + Duration::from_secs(5);
                while !pids_path.exists() {
                    assert!(Instant::now() < deadline);
                    std::thread::sleep(Duration::from_millis(10));
                }
                let pids: [u32; 2] =
                    serde_json::from_slice(&std::fs::read(&pids_path).unwrap()).unwrap();
                parent.child_mut().kill().unwrap();
                parent.wait(CLEANUP_TIMEOUT, false).unwrap();
                reap_adopted_children().unwrap();
                for pid in pids {
                    assert!(sys::read_process_start_time(pid).is_none());
                }
            }
            "lifecycle" => {
                enable_subreaping().unwrap();
                let directory = tempfile::tempdir().unwrap();
                let bx = BoxRef::from_state_dir(directory.path().into(), directory.path());
                for (vm_mode, broker_mode, notification, expected) in [
                    ("fail", Some("wait"), Some(Ok(false)), Some(23)),
                    ("wait", Some("fail"), None, None),
                    ("wait", Some("success"), None, None),
                    (
                        "wait",
                        Some("wait"),
                        Some(Err(anyhow::anyhow!("bad ready"))),
                        None,
                    ),
                    ("wait", Some("wait"), None, None),
                    ("success", None, Some(Ok(true)), Some(0)),
                    ("fail", None, Some(Ok(false)), Some(23)),
                    ("wait", None, Some(Err(anyhow::anyhow!("bad ready"))), None),
                    ("wait", None, None, None),
                ] {
                    let mut vm = spawn_test_worker(vm_mode);
                    let mut broker = broker_mode.map(spawn_test_worker);
                    let mut pids = vec![vm.child_mut().id()];
                    if let Some(broker) = &mut broker {
                        pids.push(broker.child_mut().id());
                    }
                    if expected.is_some() {
                        vm.wait(CLEANUP_TIMEOUT, false).unwrap();
                    }
                    let (sender, receiver) = std::sync::mpsc::channel();
                    if let Some(notification) = notification {
                        sender.send(notification).unwrap();
                    }
                    let result = supervise(
                        &bx,
                        &mut vm,
                        broker.as_mut(),
                        &receiver,
                        Duration::from_millis(100),
                    );
                    match expected {
                        Some(code) => assert_eq!(result.unwrap(), ExitCode::from(code)),
                        None => assert!(result.is_err()),
                    }
                    drop((vm, broker));
                    reap_adopted_children().unwrap();
                    for pid in pids {
                        assert!(sys::read_process_start_time(pid).is_none());
                    }
                }
            }
            _ => std::process::exit(1),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn broker_shutdown_preserves_pending_readiness_without_promoting_startup_failure() {
        for (mode, expected_ready) in [("ready", true), ("not-ready", false), ("invalid", false)] {
            let output =
                crate::process::run_capture(&mut build_test_command(mode), Duration::from_secs(10))
                    .unwrap();
            assert!(output.status.success(), "{mode}: {output:?}");
            assert_eq!(
                output
                    .stdout
                    .contains(&terra_protocol::AGENT_READY_NOTIFICATION),
                expected_ready,
                "{mode}: {output:?}"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn broker_loss_after_readiness_preserves_the_vm_and_its_exit_status() {
        let mut command = build_test_command("broker-loss");
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        let mut supervisor = SupervisedChild::new(command.spawn().unwrap(), None).unwrap();
        let mut output = std::io::BufReader::new(supervisor.child_mut().stdout.take().unwrap());
        let (sender, ready) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            for byte in output.by_ref().bytes().take(4096) {
                if byte.unwrap() == terra_protocol::AGENT_READY_NOTIFICATION {
                    sender.send(()).unwrap();
                    break;
                }
            }
            std::io::copy(&mut output, &mut std::io::sink()).unwrap();
        });
        ready.recv_timeout(Duration::from_secs(5)).unwrap();
        supervisor
            .child_mut()
            .stdin
            .as_mut()
            .unwrap()
            .write_all(&[1])
            .unwrap();
        assert!(
            supervisor
                .wait(Duration::from_secs(5), false)
                .unwrap()
                .success()
        );
        reader.join().unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn failures_timeouts_and_abrupt_parent_death_reap_all_workers() {
        for mode in ["lifecycle", "parent-death"] {
            let output =
                crate::process::run_capture(&mut build_test_command(mode), Duration::from_secs(15))
                    .unwrap();
            assert!(output.status.success(), "{mode}: {output:?}");
        }
    }
}
