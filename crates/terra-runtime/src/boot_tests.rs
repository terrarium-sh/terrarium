fn kernel_boot_assets() -> (Vec<u8>, Vec<u8>, tempfile::TempPath) {
    use std::io::Read;
    let build = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../build");
    let decode = |name| {
        flate2::read::GzDecoder::new(
            std::fs::File::open(build.join(name)).expect("run `make build` first"),
        )
    };
    let mut kernel = Vec::new();
    decode("vmlinux.gz").read_to_end(&mut kernel).unwrap();
    let stage_disk = |name| {
        let mut disk = tempfile::NamedTempFile::new().unwrap();
        std::io::copy(&mut decode(name), &mut disk).unwrap();
        disk.into_temp_path()
    };
    let mut boot_disk = Vec::new();
    decode("boot.img.gz").read_to_end(&mut boot_disk).unwrap();
    (kernel, boot_disk, stage_disk("rootfs.img.gz"))
}

/// Boot plan proving agent readiness end to end: Create mode with one
/// hook asserting every online CPU the machine was given. A hook
/// failure is the agent's nonzero exit report, so SMP rides the same
/// frame as the boot.
fn boot_plan(
    mode: terra_protocol::PlanMode,
    on_create: Vec<String>,
    workload: Vec<String>,
    await_initial_session: bool,
) -> Vec<u8> {
    use std::collections::BTreeMap;
    use terra_protocol::{Net, Plan, encode_frame};
    let plan = Plan {
        mode,
        workdir: None,
        shares: Vec::new(),
        volumes: Vec::new(),
        net: Net {
            guest_ip: std::net::IpAddr::V4(terra_network::GuestNetworkConfig::default().guest_ip),
            prefix: terra_network::GuestNetworkConfig::default().prefix_len,
            gateway: std::net::IpAddr::V4(terra_network::GuestNetworkConfig::default().gateway_ip),
            dns: std::net::IpAddr::V4(terra_network::GuestNetworkConfig::default().dns_server),
        },
        env: BTreeMap::new(),
        root: true,
        sudo: Vec::new(),
        on_create,
        on_start: Vec::new(),
        pre_stop: Vec::new(),
        daemons: Vec::new(),
        workload,
        sandbox_info: String::new(),
        await_initial_session,
        host_tz: None,
        host_time: None,
        host_seed: None,
    };
    encode_frame(&plan).expect("plan encodes")
}

fn boot_probe_plan(vcpus: usize) -> Vec<u8> {
    boot_plan(
        terra_protocol::PlanMode::Create,
        vec![format!("test $(nproc) = {vcpus}")],
        Vec::new(),
        false,
    )
}

async fn run_vm(
    input: super::orchestration::VmInput,
) -> Result<super::orchestration::VmOutcome, String> {
    super::orchestration::prepare(input).await?.run(|| {}).await
}

fn agent_bridge_plan() -> Vec<u8> {
    boot_plan(
        terra_protocol::PlanMode::Run,
        Vec::new(),
        vec!["sleep".into(), "15".into()],
        false,
    )
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a native hypervisor and `make test-component-boot`"]
async fn kernel_boots_directory_share() {
    #[cfg(unix)]
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use terra_protocol::{Plan, PlanMode, Share, encode_frame, read_frame};
    let directory = tempfile::tempdir().unwrap();
    let mount = std::fs::canonicalize(directory.path()).unwrap();
    std::fs::write(directory.path().join("host-file"), "host-data").unwrap();
    std::fs::write(directory.path().join("large-host"), vec![b'x'; 65_537]).unwrap();
    let executable = directory.path().join("script");
    std::fs::write(&executable, "#!/bin/sh\necho executed\n").unwrap();
    #[cfg(unix)]
    {
        let mut permissions = std::fs::metadata(&executable).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&executable, permissions).unwrap();
    }
    let tag = crate::component::fs::share_tag(0);
    let encoded = boot_plan(PlanMode::Run, Vec::new(), vec!["/bin/true".into()], false);
    let mut plan: Plan = read_frame(&mut encoded.as_slice()).unwrap().unwrap();
    plan.on_start.push("set -ex; test $(/work/script) = executed; test $(cat /work/host-file) = host-data; printf guest-data >/work/guest-file; ln /work/guest-file /work/hardlink; ln -s guest-file /work/link; test $(cat /work/link) = guest-data; mv /work/guest-file /work/renamed; test $(cat /work/hardlink) = guest-data; cp /work/large-host /work/large-copy; cmp /work/large-host /work/large-copy; test $(wc -c </work/large-copy) = 65537; sync".into());
    let diagnostics = tempfile::NamedTempFile::new().unwrap();
    plan.shares.push(Share {
        tag,
        guest: "/work".into(),
        readonly: false,
    });
    let (kernel, boot_disk, root_disk) = kernel_boot_assets();
    let outcome = run_vm(super::orchestration::VmInput {
        component_memory_limits: crate::box_runtime::ComponentMemoryLimits::default(),
        kernel,
        boot_disk,
        root_disk: root_disk.to_path_buf(),
        volume_disks: Vec::new(),
        shares: vec![crate::component::fs::ShareGrant::new(&mount, false).unwrap()],
        plan: encode_frame(&plan).unwrap(),
        artifacts: crate::test_fixtures::trusted_artifacts(),
        network_policy: boot_network_policy(),
        port_mappings: Vec::new(),
        ram_bytes: BOOT_RAM,
        vcpus: 2,
        deadline: Some(std::time::Duration::from_mins(1)),
        hard_stop: None,
        listener: None,
        control: None,
        diagnostics: Some(diagnostics.reopen().unwrap()),
    })
    .await
    .expect("shared directory worker runs");
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "{outcome:?}\n{}",
        std::fs::read_to_string(diagnostics.path()).unwrap()
    );
    assert_eq!(
        std::fs::read(directory.path().join("renamed")).unwrap(),
        b"guest-data"
    );
    assert_eq!(
        std::fs::read(directory.path().join("large-copy")).unwrap(),
        vec![b'x'; 65_537]
    );
    #[cfg(unix)]
    assert_eq!(
        std::fs::metadata(directory.path().join("renamed"))
            .unwrap()
            .nlink(),
        2
    );
}

struct DenyAllPolicy;

impl terra_network::Policy for DenyAllPolicy {
    fn allows(&self, _: std::net::IpAddr, _: Option<u16>) -> bool {
        false
    }
}

fn boot_network_policy() -> terra_network::PolicyHandle {
    std::sync::Arc::new(DenyAllPolicy)
}

/// 512 MiB of guest RAM for the kernel boot: kernel, Alpine
/// userspace, and page cache with room to spare.
const BOOT_RAM: u64 = 512 << 20;

async fn boot_workload(
    ram_bytes: u64,
    workload: Vec<String>,
) -> Result<super::orchestration::VmOutcome, String> {
    let vcpus = if std::env::var_os("TERRA_BOOT_ONE_CPU").is_some() {
        1
    } else {
        2
    };
    let (kernel, boot_disk, root_path) = kernel_boot_assets();
    run_vm(super::orchestration::VmInput {
        component_memory_limits: crate::box_runtime::ComponentMemoryLimits::default(),
        kernel,
        boot_disk,
        root_disk: root_path.to_path_buf(),
        volume_disks: Vec::new(),
        shares: Vec::new(),
        plan: boot_plan(terra_protocol::PlanMode::Run, Vec::new(), workload, false),
        artifacts: crate::test_fixtures::trusted_artifacts(),
        network_policy: boot_network_policy(),
        port_mappings: Vec::new(),
        ram_bytes,
        vcpus,
        deadline: Some(std::time::Duration::from_secs(150)),
        hard_stop: None,
        listener: None,
        control: None,
        diagnostics: None,
    })
    .await
}

/// Phase 1B gate: the pinned kernel boots on two vCPUs with both disks
/// behind real block components, the agent dials the control port over
/// the native vsock bridge, reads its plan, proves both CPUs online,
/// and reports success. `TERRA_BOOT_TRACE=1` logs MSR/EOI flow.
#[tokio::test]
#[ignore = "requires a native hypervisor and `make test-component-boot`"]
async fn kernel_boots_to_agent_ready() {
    let vcpus: usize = if std::env::var_os("TERRA_BOOT_ONE_CPU").is_some() {
        1
    } else {
        2
    };
    let (kernel, boot_disk, root_path) = kernel_boot_assets();
    let outcome = run_vm(super::orchestration::VmInput {
        component_memory_limits: crate::box_runtime::ComponentMemoryLimits::default(),
        kernel,
        boot_disk,
        root_disk: root_path.to_path_buf(),
        volume_disks: Vec::new(),
        shares: Vec::new(),
        plan: boot_probe_plan(vcpus),
        artifacts: crate::test_fixtures::trusted_artifacts(),
        network_policy: boot_network_policy(),
        port_mappings: Vec::new(),
        hard_stop: None,
        ram_bytes: BOOT_RAM,
        vcpus,
        deadline: Some(std::time::Duration::from_secs(150)),
        listener: None,
        control: None,
        diagnostics: None,
    })
    .await
    .expect("worker runs");
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "agent control outcome: {outcome:?}"
    );
}

#[tokio::test]
#[ignore = "requires a native hypervisor and `make test-component-boot`"]
async fn kernel_reports_free_pages_after_boot() {
    let outcome = boot_workload(2048 << 20, vec!["sleep".into(), "4".into()])
        .await
        .expect("worker runs");
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "agent control outcome: {outcome:?}"
    );
}

#[tokio::test]
#[ignore = "requires a native hypervisor and `make test-component-boot`"]
async fn kernel_boots_with_high_ram_above_the_mmio_hole() {
    let outcome = boot_workload(
        8 << 30,
        vec![
            "sh".into(),
            "-ec".into(),
            "awk '/MemTotal:/ { exit !($2 > 7000000) }' /proc/meminfo; mount -o remount,size=4G /dev/shm; dd if=/dev/zero of=/dev/shm/high-ram bs=1M count=3584; test $(stat -c %s /dev/shm/high-ram) -eq 3758096384; test $(stat -c %b /dev/shm/high-ram) -ge 7000000".into(),
        ],
    )
    .await
    .expect("worker runs");
    assert_eq!(
        outcome.exit_code,
        Some(0),
        "agent control outcome: {outcome:?}"
    );
}

fn bridge_listener() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    terra_platform::io::local::LocalListener,
) {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;

    let dir = tempfile::tempdir().expect("temporary socket directory");
    let path = dir.path().join("agent.sock");
    let listener =
        terra_platform::io::local::LocalListener::bind(&path).expect("bind agent socket");
    #[cfg(unix)]
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .expect("secure agent socket");
    #[cfg(unix)]
    assert_eq!(
        std::fs::metadata(&path)
            .expect("agent socket metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    (dir, path, listener)
}

fn connect_agent(
    path: &std::path::Path,
) -> std::io::Result<terra_platform::io::local::LocalStream> {
    use std::io::Read as _;
    use terra_protocol::AGENT_HELLO;

    let deadline = std::time::Instant::now() + std::time::Duration::from_mins(2);
    loop {
        let attempt = (|| {
            let mut stream = terra_platform::io::local::LocalStream::connect(path)?;
            stream.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;
            let mut hello = [0; AGENT_HELLO.len()];
            stream.read_exact(&mut hello)?;
            if hello != AGENT_HELLO {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "agent hello mismatch",
                ));
            }
            Ok(stream)
        })();
        match attempt {
            Ok(stream) => return Ok(stream),
            Err(_) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(error) => return Err(error),
        }
    }
}

fn assert_agent_control_and_exec(path: &std::path::Path) -> std::io::Result<()> {
    use std::io::Write as _;
    use terra_protocol::{AgentService, ControlReply, ControlRequest, encode_frame, read_frame};

    let mut control = connect_agent(path).map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!("connecting session-control service: {error}"),
        )
    })?;
    control.write_all(&encode_frame(&AgentService::SessionControl)?)?;
    control.write_all(&encode_frame(&ControlRequest::List)?)?;
    let control_reply = read_frame::<ControlReply>(&mut control).map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!("reading session-control reply: {error}"),
        )
    })?;
    assert_eq!(
        control_reply,
        Some(ControlReply::Done),
        "empty session has no attached clients"
    );

    assert_eq!(
        agent_exec(path, &["printf", "agent-bridge"])?,
        b"agent-bridge"
    );
    Ok(())
}

fn agent_exec(path: &std::path::Path, argv: &[&str]) -> std::io::Result<Vec<u8>> {
    use std::io::Write as _;
    use terra_protocol::{AgentOutput, AgentService, ExecRequest, encode_frame, read_frame};

    let mut exec = connect_agent(path).map_err(|error| {
        std::io::Error::new(error.kind(), format!("connecting exec service: {error}"))
    })?;
    exec.write_all(&encode_frame(&AgentService::Exec)?)?;
    exec.write_all(&encode_frame(&ExecRequest {
        argv: argv.iter().map(ToString::to_string).collect(),
        as_root: true,
        tty: None,
        workdir: None,
        env: std::collections::BTreeMap::new(),
    })?)?;
    let mut output = Vec::new();
    loop {
        match read_frame::<AgentOutput>(&mut exec)? {
            Some(AgentOutput::Out(bytes) | AgentOutput::Err(bytes)) => {
                output.extend_from_slice(&bytes);
            }
            Some(AgentOutput::Exit { code }) => {
                if code != 0 {
                    return Err(std::io::Error::other(format!(
                        "agent exec exits {code}: {}",
                        String::from_utf8_lossy(&output)
                    )));
                }
                break;
            }
            Some(AgentOutput::Detached) => panic!("exec service detached"),
            None => panic!("agent exec closed before its exit frame"),
        }
    }
    Ok(output)
}

fn await_foreground_workload(path: &std::path::Path) -> std::io::Result<(Vec<u8>, i32)> {
    use std::io::Write as _;
    use terra_protocol::{AgentOutput, AgentService, encode_frame, read_frame};

    let mut session = connect_agent(path)?;
    session.write_all(&encode_frame(&AgentService::Session)?)?;
    let mut output = Vec::new();
    loop {
        match read_frame::<AgentOutput>(&mut session)? {
            Some(AgentOutput::Out(bytes) | AgentOutput::Err(bytes)) => {
                output.extend_from_slice(&bytes);
            }
            Some(AgentOutput::Exit { code }) => return Ok((output, code)),
            Some(AgentOutput::Detached) => {
                return Err(std::io::Error::other("foreground session detached"));
            }
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "foreground session closed before its exit frame",
                ));
            }
        }
    }
}

struct LocalHttpPolicy {
    address: std::net::IpAddr,
    port: u16,
}

impl terra_network::Policy for LocalHttpPolicy {
    fn allows(&self, ip: std::net::IpAddr, port: Option<u16>) -> bool {
        ip == self.address && port == Some(self.port)
    }

    fn lookup_name(&self, _: &str) -> terra_network::NameLookup {
        terra_network::NameLookup::Static(vec![self.address])
    }

    fn blocks_direct_dns(&self) -> bool {
        true
    }
}

fn local_http_server(
    address: std::net::Ipv4Addr,
    body: Vec<u8>,
) -> (
    u16,
    std::sync::mpsc::Sender<()>,
    std::thread::JoinHandle<()>,
) {
    use std::io::{Read as _, Write as _};

    let listener = std::net::TcpListener::bind((address, 0)).expect("bind local HTTP server");
    listener
        .set_nonblocking(true)
        .expect("make local HTTP server nonblocking");
    let port = listener.local_addr().expect("local HTTP address").port();
    let (stop, stopped) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        loop {
            if stopped.try_recv().is_ok() {
                return;
            }
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let mut request = [0; 1024];
                    let _ = stream.read(&mut request);
                    stream
                        .write_all(
                            format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len())
                                .as_bytes(),
                        )
                        .and_then(|()| stream.write_all(&body))
                        .expect("write local HTTP response");
                    return;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(error) => panic!("accept local HTTP request: {error}"),
            }
        }
    });
    (port, stop, server)
}

fn local_upload_server(
    address: std::net::Ipv4Addr,
    expected_bytes: usize,
) -> (
    u16,
    std::sync::mpsc::Sender<()>,
    std::thread::JoinHandle<()>,
) {
    use std::io::{Read as _, Write as _};

    let listener = std::net::TcpListener::bind((address, 0)).expect("bind local upload server");
    listener
        .set_nonblocking(true)
        .expect("make local upload server nonblocking");
    let port = listener.local_addr().expect("local upload address").port();
    let (stop, stopped) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        loop {
            if stopped.try_recv().is_ok() {
                return;
            }
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let mut data = vec![0; expected_bytes];
                    stream.read_exact(&mut data).expect("read upload");
                    assert!(data.iter().all(|byte| *byte == 0), "upload bytes match");
                    stream
                        .write_all(b"uploaded")
                        .expect("write upload response");
                    return;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(error) => panic!("accept local upload: {error}"),
            }
        }
    });
    (port, stop, server)
}

/// Phase 1E gate: a Run VM serves agent control and exec over the worker's
/// owner-only Unix listener while the real component-backed machine is running.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a native hypervisor, `make component-block-aot component-vsock-aot`, and boot assets"]
async fn kernel_boots_to_agent_bridge() {
    let (_socket_dir, socket_path, listener) = bridge_listener();
    let (kernel, boot_disk, root_path) = kernel_boot_assets();
    let client_path = socket_path.clone();
    let client = tokio::task::spawn_blocking(move || assert_agent_control_and_exec(&client_path));
    let worker = run_vm(super::orchestration::VmInput {
        component_memory_limits: crate::box_runtime::ComponentMemoryLimits::default(),
        kernel,
        boot_disk,
        root_disk: root_path.to_path_buf(),
        volume_disks: Vec::new(),
        shares: Vec::new(),
        plan: agent_bridge_plan(),
        artifacts: crate::test_fixtures::trusted_artifacts(),
        network_policy: boot_network_policy(),
        port_mappings: Vec::new(),
        hard_stop: None,
        ram_bytes: BOOT_RAM,
        vcpus: 2,
        deadline: Some(std::time::Duration::from_secs(150)),
        listener: Some(listener),
        control: None,
        diagnostics: None,
    });
    let (outcome, client) = tokio::join!(worker, client);
    client
        .expect("agent bridge client thread runs")
        .expect("agent bridge serves control and exec");
    let outcome = outcome.expect("worker runs");
    assert_eq!(outcome.exit_code, Some(0), "agent outcome: {outcome:?}");
}

/// Phase 1E gate: the host stop channel reaches a running guest workload and
/// the worker reaps the machine after the agent reports the signal exit.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a native hypervisor, component AOT artifacts, and boot assets"]
async fn kernel_boots_and_agent_stop_ends_workload() {
    use std::io::Write as _;

    let (_socket_dir, socket_path, listener) = bridge_listener();
    let (kernel, boot_disk, root_path) = kernel_boot_assets();
    let (_control_dir, control_path, control_listener) = bridge_listener();
    let mut control_writer =
        terra_platform::io::local::LocalStream::connect(&control_path).unwrap();
    let (control, _) = control_listener.accept().unwrap();
    let client_path = socket_path.clone();
    let client = tokio::task::spawn_blocking(move || {
        assert_agent_control_and_exec(&client_path)?;
        control_writer.write_all(&[terra_protocol::STOP_SIGNAL])
    });
    let worker = run_vm(super::orchestration::VmInput {
        component_memory_limits: crate::box_runtime::ComponentMemoryLimits::default(),
        kernel,
        boot_disk,
        root_disk: root_path.to_path_buf(),
        volume_disks: Vec::new(),
        shares: Vec::new(),
        plan: boot_plan(
            terra_protocol::PlanMode::Run,
            Vec::new(),
            vec!["sleep".into(), "120".into()],
            false,
        ),
        artifacts: crate::test_fixtures::trusted_artifacts(),
        network_policy: boot_network_policy(),
        port_mappings: Vec::new(),
        hard_stop: None,
        ram_bytes: BOOT_RAM,
        vcpus: 2,
        deadline: Some(std::time::Duration::from_secs(150)),
        listener: Some(listener),
        control: Some(control),
        diagnostics: None,
    });
    let (outcome, client) = tokio::join!(worker, client);
    client
        .expect("stop client thread runs")
        .expect("write worker stop signal");
    let outcome = outcome.expect("worker runs");
    assert_eq!(outcome.exit_code, Some(143), "agent outcome: {outcome:?}");
    assert!(
        outcome.vcpu_outcomes.iter().all(Result::is_ok),
        "worker reaps every vCPU: {outcome:?}"
    );
}

/// A foreground Run box waits for its first attached client, then carries the
/// workload's terminal output and exit status through the native agent bridge.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a native hypervisor, component AOT artifacts, and boot assets"]
async fn kernel_boots_foreground_session_reports_workload_exit() {
    let (_socket_dir, socket_path, listener) = bridge_listener();
    let (kernel, boot_disk, root_path) = kernel_boot_assets();
    let client_path = socket_path.clone();
    let client = tokio::task::spawn_blocking(move || await_foreground_workload(&client_path));
    let worker = run_vm(super::orchestration::VmInput {
        component_memory_limits: crate::box_runtime::ComponentMemoryLimits::default(),
        kernel,
        boot_disk,
        root_disk: root_path.to_path_buf(),
        volume_disks: Vec::new(),
        shares: Vec::new(),
        plan: boot_plan(
            terra_protocol::PlanMode::Run,
            Vec::new(),
            vec![
                "sh".into(),
                "-c".into(),
                "printf foreground-lifecycle; exit 7".into(),
            ],
            true,
        ),
        artifacts: crate::test_fixtures::trusted_artifacts(),
        network_policy: boot_network_policy(),
        port_mappings: Vec::new(),
        hard_stop: None,
        ram_bytes: BOOT_RAM,
        vcpus: 2,
        deadline: Some(std::time::Duration::from_mins(1)),
        listener: Some(listener),
        control: None,
        diagnostics: None,
    });
    let (outcome, client) = Box::pin(tokio::time::timeout(
        std::time::Duration::from_secs(75),
        async { tokio::join!(worker, client) },
    ))
    .await
    .expect("foreground workload finishes within its bound");
    let (output, exit_code) = client
        .expect("foreground client thread runs")
        .expect("foreground session carries output and exit");
    assert!(
        String::from_utf8_lossy(&output).contains("foreground-lifecycle"),
        "foreground output: {}",
        String::from_utf8_lossy(&output)
    );
    assert_eq!(exit_code, 7, "foreground session exit");
    let outcome = outcome.expect("worker runs");
    assert_eq!(outcome.exit_code, Some(7), "worker outcome: {outcome:?}");
    assert!(
        outcome.vcpu_outcomes.iter().all(Result::is_ok),
        "worker reaps every vCPU: {outcome:?}"
    );
}

async fn assert_policy_dns_http(address: std::net::IpAddr, body: &[u8]) {
    let (_socket_dir, socket_path, listener) = bridge_listener();
    let (kernel, boot_disk, root_path) = kernel_boot_assets();
    let listener_address = std::net::Ipv4Addr::UNSPECIFIED;
    let body = body.to_vec();
    let (port, stop_server, server) = local_http_server(listener_address, body.clone());
    let client_path = socket_path.clone();
    let client = tokio::task::spawn_blocking(move || {
        assert_agent_control_and_exec(&client_path)?;
        let output = agent_exec(
            &client_path,
            &["wget", "-qO-", &format!("http://agent.test:{port}")],
        )?;
        assert_eq!(output, body);
        Ok::<(), std::io::Error>(())
    });
    let worker = run_vm(super::orchestration::VmInput {
        component_memory_limits: crate::box_runtime::ComponentMemoryLimits::default(),
        kernel,
        boot_disk,
        root_disk: root_path.to_path_buf(),
        volume_disks: Vec::new(),
        shares: Vec::new(),
        plan: agent_bridge_plan(),
        artifacts: crate::test_fixtures::trusted_artifacts(),
        network_policy: std::sync::Arc::new(LocalHttpPolicy { address, port }),
        port_mappings: Vec::new(),
        hard_stop: None,
        ram_bytes: BOOT_RAM,
        vcpus: 2,
        deadline: Some(std::time::Duration::from_secs(150)),
        listener: Some(listener),
        control: None,
        diagnostics: None,
    });
    let (outcome, client) = tokio::join!(worker, client);
    let _ = stop_server.send(());
    client
        .expect("network client thread runs")
        .expect("agent fetches the policy DNS HTTP server");
    server.join().expect("local HTTP server thread runs");
    let outcome = outcome.expect("worker runs");
    assert_eq!(outcome.exit_code, Some(0), "agent outcome: {outcome:?}");
}

async fn assert_policy_dns_upload(address: std::net::IpAddr, bytes: usize) {
    let (_socket_dir, socket_path, listener) = bridge_listener();
    let (kernel, boot_disk, root_path) = kernel_boot_assets();
    let listener_address = std::net::Ipv4Addr::UNSPECIFIED;
    let (port, stop_server, server) = local_upload_server(listener_address, bytes);
    let client_path = socket_path.clone();
    let client = tokio::task::spawn_blocking(move || {
        assert_agent_control_and_exec(&client_path)?;
        let command = format!("head -c {bytes} /dev/zero | nc agent.test {port}");
        assert_eq!(
            agent_exec(&client_path, &["sh", "-c", &command])?,
            b"uploaded"
        );
        Ok::<(), std::io::Error>(())
    });
    let worker = run_vm(super::orchestration::VmInput {
        component_memory_limits: crate::box_runtime::ComponentMemoryLimits::default(),
        kernel,
        boot_disk,
        root_disk: root_path.to_path_buf(),
        volume_disks: Vec::new(),
        shares: Vec::new(),
        plan: agent_bridge_plan(),
        artifacts: crate::test_fixtures::trusted_artifacts(),
        network_policy: std::sync::Arc::new(LocalHttpPolicy { address, port }),
        port_mappings: Vec::new(),
        hard_stop: None,
        ram_bytes: BOOT_RAM,
        vcpus: 2,
        deadline: Some(std::time::Duration::from_secs(150)),
        listener: Some(listener),
        control: None,
        diagnostics: None,
    });
    let (outcome, client) = tokio::join!(worker, client);
    let _ = stop_server.send(());
    client
        .expect("upload client thread runs")
        .expect("agent uploads through the policy server");
    server.join().expect("local upload server thread runs");
    let outcome = outcome.expect("worker runs");
    assert_eq!(outcome.exit_code, Some(0), "agent outcome: {outcome:?}");
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a native hypervisor, component AOT artifacts, and boot assets"]
async fn kernel_boots_through_standard_wasi_tcp() {
    assert_policy_dns_http(native_ipv4_address(), b"agent-network").await;
}

fn native_ipv4_address() -> std::net::IpAddr {
    let socket = std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0))
        .expect("bind local address probe");
    socket
        .connect((std::net::Ipv4Addr::new(192, 0, 2, 1), 80))
        .expect("select local address");
    socket.local_addr().expect("read local address").ip()
}

fn reserved_loopback_port() -> u16 {
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .expect("reserve loopback port");
    listener.local_addr().expect("read reserved port").port()
}

fn published_http_response(port: u16, host_closes_first: bool) -> std::io::Result<Vec<u8>> {
    use std::io::{Read as _, Write as _};

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);
    loop {
        let attempt = (|| {
            let mut stream = std::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))?;
            stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
            stream.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
            if host_closes_first {
                stream.shutdown(std::net::Shutdown::Write)?;
            }
            let mut response = Vec::new();
            stream.read_to_end(&mut response)?;
            Ok::<Vec<u8>, std::io::Error>(response)
        })();
        match attempt {
            Ok(response) if !response.is_empty() => return Ok(response),
            Ok(_) | Err(_) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(error) => return Err(error),
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "published listener closed without a response",
                ));
            }
        }
    }
}

/// A guest closing its response sends EOF to a host still holding its write half open.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a native hypervisor, component AOT artifacts, and boot assets"]
async fn kernel_boots_published_loopback_http() {
    Box::pin(assert_published_loopback_http(false)).await;
}

/// A host finishing its request can still receive the complete guest response and EOF.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a native hypervisor, component AOT artifacts, and boot assets"]
async fn kernel_boots_published_loopback_http_after_host_eof() {
    Box::pin(assert_published_loopback_http(true)).await;
}

async fn assert_published_loopback_http(host_closes_first: bool) {
    use std::io::Write as _;

    const GUEST_PORT: u16 = 8080;
    const BODY: &[u8] = b"published-body";
    let host_port = reserved_loopback_port();
    let (kernel, boot_disk, root_path) = kernel_boot_assets();
    let (_control_dir, control_path, control_listener) = bridge_listener();
    let mut control_writer =
        terra_platform::io::local::LocalStream::connect(&control_path).unwrap();
    let (control, _) = control_listener.accept().unwrap();
    let diagnostics = tempfile::NamedTempFile::new().expect("create diagnostics");
    let client = tokio::task::spawn_blocking(move || {
        let response = published_http_response(host_port, host_closes_first)?;
        control_writer.write_all(&[terra_protocol::STOP_SIGNAL])?;
        Ok::<Vec<u8>, std::io::Error>(response)
    });
    let worker = run_vm(super::orchestration::VmInput {
        component_memory_limits: crate::box_runtime::ComponentMemoryLimits::default(),
        kernel,
        boot_disk,
        root_disk: root_path.to_path_buf(),
        volume_disks: Vec::new(),
        shares: Vec::new(),
        plan: boot_plan(
            terra_protocol::PlanMode::Run,
            Vec::new(),
            vec![
                "sh".into(),
                "-c".into(),
                "while true; do printf 'HTTP/1.1 200 OK\\r\\nContent-Length: 14\\r\\nConnection: close\\r\\n\\r\\npublished-body' | busybox nc -l -p 8080; done".into(),
            ],
            false,
        ),
        artifacts: crate::test_fixtures::trusted_artifacts(),
        network_policy: boot_network_policy(),
        port_mappings: vec![terra_network::PortMapping::new(host_port, GUEST_PORT)],
        hard_stop: None,
        ram_bytes: BOOT_RAM,
        vcpus: 2,
        deadline: Some(std::time::Duration::from_mins(1)),
        listener: None,
        control: Some(control),
        diagnostics: Some(diagnostics.reopen().expect("reopen diagnostics")),
    });
    let (outcome, response) = Box::pin(tokio::time::timeout(
        std::time::Duration::from_secs(75),
        async { tokio::join!(worker, client) },
    ))
    .await
    .unwrap_or_else(|error| {
        panic!(
            "published HTTP workload finishes within its bound: {error:?}\n{}",
            std::fs::read_to_string(diagnostics.path()).expect("read diagnostics")
        )
    });
    let response = response
        .expect("published HTTP client thread runs")
        .expect("published port responds");
    assert!(
        response.ends_with(BODY),
        "published HTTP response: {}",
        String::from_utf8_lossy(&response)
    );
    let outcome = outcome.expect("worker runs");
    assert_eq!(outcome.exit_code, Some(143), "worker outcome: {outcome:?}");
    assert!(
        outcome.vcpu_outcomes.iter().all(Result::is_ok),
        "worker reaps every vCPU: {outcome:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a native hypervisor, component AOT artifacts, and boot assets"]
async fn kernel_boots_through_standard_wasi_large_tcp() {
    assert_policy_dns_http(native_ipv4_address(), &vec![b's'; 65_537]).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a native hypervisor, component AOT artifacts, and boot assets"]
async fn kernel_uploads_through_standard_wasi_tcp() {
    assert_policy_dns_upload(native_ipv4_address(), 65_537).await;
}
