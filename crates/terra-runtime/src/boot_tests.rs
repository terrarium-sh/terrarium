use crate::component::network::{HostServiceAddresses, NetworkBackend, PortMapping};
use std::assert_matches;
use terra_network::config::{Config, Network, PublishedListener, StaticDnsRecord};

fn load_boot_disk(path: &std::path::Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;

    let mut decoder = flate2::read::GzDecoder::new(std::fs::File::open(path)?);
    terra_protocol::guest_image::GuestImage::Boot
        .validate(decoder.header().and_then(flate2::GzHeader::extra))?;
    let mut boot_disk = Vec::new();
    decoder.read_to_end(&mut boot_disk)?;
    Ok(boot_disk)
}

fn load_kernel(path: &std::path::Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;

    let mut decoder = flate2::read::GzDecoder::new(std::fs::File::open(path)?);
    terra_protocol::guest_image::GuestImage::Kernel
        .validate(decoder.header().and_then(flate2::GzHeader::extra))?;
    let mut kernel = Vec::new();
    decoder.read_to_end(&mut kernel)?;
    Ok(kernel)
}

fn kernel_boot_assets() -> (Vec<u8>, Vec<u8>, tempfile::TempPath) {
    let build = std::env::var_os("TERRA_BOOT_ASSETS_DIR").map_or_else(
        || std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../build"),
        std::path::PathBuf::from,
    );
    let decode = |name| {
        flate2::read::GzDecoder::new(
            std::fs::File::open(build.join(name)).expect("run `make build` first"),
        )
    };
    let kernel = load_kernel(&build.join("vmlinux.gz")).unwrap();
    let stage_disk = |name| {
        let mut disk = tempfile::NamedTempFile::new().unwrap();
        std::io::copy(&mut decode(name), &mut disk).unwrap();
        disk.into_temp_path()
    };
    let boot_disk = load_boot_disk(&build.join("boot.img.gz")).unwrap();
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
        net: Net::Tsi,
        published_ports: Vec::new(),
        published_udp_ports: Vec::new(),
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
    encode_frame(&terra_protocol::BootPlan::new(plan)).expect("plan encodes")
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
    use terra_protocol::{PlanMode, Share, encode_frame, read_frame};
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
    let envelope: terra_protocol::BootPlan = read_frame(&mut encoded.as_slice()).unwrap().unwrap();
    let mut plan = envelope.plan;
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
        plan: encode_frame(&terra_protocol::BootPlan::new(plan)).unwrap(),
        artifacts: crate::test_fixtures::trusted_artifacts(),
        network_backend: Some(create_boot_network_backend()),
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

fn create_boot_network_backend() -> NetworkBackend {
    start_network_broker(Network::default(), &[])
}

fn start_network_broker(policy: Network, port_mappings: &[PortMapping]) -> NetworkBackend {
    let mut listeners = Vec::new();
    for (index, mapping) in port_mappings.iter().enumerate() {
        for (offset, address) in [
            (1, std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            (2, std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
        ] {
            listeners.push(PublishedListener {
                grant: u32::try_from(index * 2 + offset).unwrap(),
                address: (address, mapping.host).into(),
                transport: mapping.transport,
            });
        }
    }
    crate::component::network::start_test_broker(Config {
        policy,
        gateways: [
            HostServiceAddresses::default().gateway_ip.into(),
            HostServiceAddresses::default().gateway_ip6.into(),
        ],
        listeners,
    })
    .expect("network broker starts")
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
        network_backend: Some(create_boot_network_backend()),
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

/// The bundled kernel boots with both block devices, delivers the agent plan
/// through the agent vsock connection, and reports both vCPUs online.
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
        network_backend: Some(create_boot_network_backend()),
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
    let deadline = std::time::Instant::now() + std::time::Duration::from_mins(2);
    loop {
        match connect_agent_once(path) {
            Ok(stream) => return Ok(stream),
            Err(_) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(error) => return Err(error),
        }
    }
}

fn connect_agent_once(
    path: &std::path::Path,
) -> std::io::Result<terra_platform::io::local::LocalStream> {
    use std::io::Read as _;
    use terra_protocol::AGENT_HELLO;

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
}

fn assert_agent_control_and_exec(path: &std::path::Path) -> std::io::Result<()> {
    let control = connect_agent(path).map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!("connecting session-control service: {error}"),
        )
    })?;
    assert_agent_control_reply(control)?;
    assert_eq!(
        agent_exec(path, &["printf", "agent-bridge"])?,
        b"agent-bridge"
    );
    Ok(())
}

fn assert_agent_control_reply(
    mut control: terra_platform::io::local::LocalStream,
) -> std::io::Result<()> {
    use std::io::Write as _;
    use terra_protocol::{AgentService, ControlReply, ControlRequest, encode_frame, read_frame};

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
    Ok(())
}

fn agent_exec(path: &std::path::Path, argv: &[&str]) -> std::io::Result<Vec<u8>> {
    agent_exec_with_input(path, argv, None)
}

fn agent_exec_with_input(
    path: &std::path::Path,
    argv: &[&str],
    input: Option<&[u8]>,
) -> std::io::Result<Vec<u8>> {
    let exec = connect_agent(path).map_err(|error| {
        std::io::Error::new(error.kind(), format!("connecting exec service: {error}"))
    })?;
    run_agent_exec(exec, argv, input)
}

fn run_agent_exec(
    mut exec: terra_platform::io::local::LocalStream,
    argv: &[&str],
    input: Option<&[u8]>,
) -> std::io::Result<Vec<u8>> {
    use terra_protocol::{AgentOutput, read_frame};

    write_agent_exec_request(&mut exec, argv, input)?;
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

fn write_agent_exec_request(
    exec: &mut terra_platform::io::local::LocalStream,
    argv: &[&str],
    input: Option<&[u8]>,
) -> std::io::Result<()> {
    use std::io::Write as _;
    use terra_protocol::{AgentService, ClientInput, ExecRequest, encode_frame};

    exec.write_all(&encode_frame(&AgentService::Exec)?)?;
    exec.write_all(&encode_frame(&ExecRequest {
        argv: argv.iter().map(ToString::to_string).collect(),
        as_root: true,
        tty: None,
        workdir: None,
        env: std::collections::BTreeMap::new(),
    })?)?;
    if let Some(input) = input {
        for bytes in input.chunks(8192) {
            exec.write_all(&encode_frame(&ClientInput::Keys(bytes.to_vec()))?)?;
        }
        exec.write_all(&encode_frame(&ClientInput::Eof)?)?;
    }
    Ok(())
}

fn exec_until_agent_disconnect(path: &std::path::Path, argv: &[&str]) -> std::io::Result<()> {
    use std::io::ErrorKind;
    use terra_protocol::{AgentOutput, read_frame};

    let mut exec = connect_agent_once(path)?;
    write_agent_exec_request(&mut exec, argv, None)?;
    loop {
        match read_frame::<AgentOutput>(&mut exec) {
            Ok(None) => return Ok(()),
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::UnexpectedEof | ErrorKind::ConnectionReset | ErrorKind::BrokenPipe
                ) =>
            {
                return Ok(());
            }
            Err(error) => return Err(error),
            Ok(Some(AgentOutput::Out(_) | AgentOutput::Err(_))) => {}
            Ok(Some(frame @ (AgentOutput::Exit { .. } | AgentOutput::Detached))) => {
                return Err(std::io::Error::other(format!(
                    "shared reset reported an exec outcome instead of disconnecting: {frame:?}"
                )));
            }
        }
    }
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

fn create_http_network_backend(address: std::net::IpAddr, port: u16) -> NetworkBackend {
    start_network_broker(
        Network {
            allow: vec![std::net::SocketAddr::new(address, port).to_string()],
            hosts: vec![StaticDnsRecord {
                name: "agent.test".into(),
                addr: address.to_string(),
            }],
            ..Network::default()
        },
        &[],
    )
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
#[ignore = "requires a native hypervisor, `make component-block-aot component-agent-aot component-vsock-frontend-aot`, and boot assets"]
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
        network_backend: Some(create_boot_network_backend()),
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

/// Local-only boots omit the network device while agent control, 2 MiB session
/// payloads in both directions, and host STOP still cross the agent vsock connection.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires native KVM, matching component AOT artifacts, and boot assets"]
async fn kernel_boots_local_only_agent_control_and_session() {
    use std::io::Write as _;
    use terra_protocol::{Net, PlanMode, encode_frame, read_frame};

    let (_socket_dir, socket_path, listener) = bridge_listener();
    let (_control_dir, control_path, control_listener) = bridge_listener();
    let mut control_writer =
        terra_platform::io::local::LocalStream::connect(&control_path).unwrap();
    let (control, _) = control_listener.accept().unwrap();
    let client = tokio::task::spawn_blocking(move || {
        assert_agent_control_and_exec(&socket_path)?;
        let output = agent_exec(&socket_path, &["head", "-c", "2097152", "/dev/zero"])?;
        assert_eq!(output.len(), 2 << 20);
        assert!(output.iter().all(|&byte| byte == 0));
        let input = vec![0; 2 << 20];
        let digest = agent_exec_with_input(&socket_path, &["sha256sum"], Some(&input))?;
        assert_eq!(
            digest,
            b"5647f05ec18958947d32874eeb788fa396a05d0bab7c1b71f112ceb7e9b31eee  -\n"
        );
        control_writer.write_all(&[terra_protocol::STOP_SIGNAL])
    });
    let encoded = boot_plan(
        PlanMode::Run,
        Vec::new(),
        vec!["sleep".into(), "120".into()],
        false,
    );
    let envelope: terra_protocol::BootPlan = read_frame(&mut encoded.as_slice()).unwrap().unwrap();
    let mut plan = envelope.plan;
    plan.net = Net::LocalOnly;
    let diagnostics = tempfile::NamedTempFile::new().unwrap();
    let (kernel, boot_disk, root_path) = kernel_boot_assets();
    let worker = run_vm(super::orchestration::VmInput {
        component_memory_limits: crate::box_runtime::ComponentMemoryLimits::default(),
        kernel,
        boot_disk,
        root_disk: root_path.to_path_buf(),
        volume_disks: Vec::new(),
        shares: Vec::new(),
        plan: encode_frame(&terra_protocol::BootPlan::new(plan)).unwrap(),
        artifacts: crate::test_fixtures::trusted_artifacts(),
        network_backend: None,
        port_mappings: Vec::new(),
        hard_stop: None,
        ram_bytes: BOOT_RAM,
        vcpus: 2,
        deadline: Some(std::time::Duration::from_secs(150)),
        listener: Some(listener),
        control: Some(control),
        diagnostics: Some(diagnostics.reopen().unwrap()),
    });
    let (outcome, client) = tokio::join!(worker, client);
    let output = std::fs::read_to_string(diagnostics.path()).unwrap();
    client
        .expect("local-only client thread runs")
        .unwrap_or_else(|error| panic!("local-only agent services: {error}\n{output}"));
    let outcome = outcome.unwrap_or_else(|error| panic!("local-only VM: {error}\n{output}"));
    assert_eq!(outcome.exit_code, Some(143), "{outcome:?}\n{output}");
    assert!(
        outcome.vcpu_outcomes.iter().all(Result::is_ok),
        "{outcome:?}"
    );
}

const STALLED_FILE_BYTES: u64 = 64 << 20;
const STALLED_GUEST_PORT: u16 = 8080;

fn begin_stalled_download(
    path: &std::path::Path,
) -> std::io::Result<terra_platform::io::local::LocalStream> {
    use std::io::Write as _;
    use terra_protocol::{AgentService, SyncReply, SyncRequest, encode_frame, read_frame};

    let mut stream = connect_agent(path)?;
    stream.write_all(&encode_frame(&AgentService::Sync)?)?;
    stream.write_all(&encode_frame(&SyncRequest::BeginSession {
        guest_root: "/work".into(),
    })?)?;
    assert_matches!(
        read_frame::<SyncReply>(&mut stream)?,
        Some(SyncReply::SessionReady { .. })
    );
    stream.write_all(&encode_frame(&SyncRequest::ReadFile {
        relative_path: "pressure-file".into(),
    })?)?;
    assert_matches!(
        read_frame::<SyncReply>(&mut stream)?,
        Some(SyncReply::ReadFileReady {
            size: STALLED_FILE_BYTES,
            ..
        })
    );
    Ok(stream)
}

fn download_file_position(path: &std::path::Path) -> std::io::Result<u64> {
    let output = agent_exec(
        path,
        &[
            "sh",
            "-c",
            r#"for descriptor in /proc/1/fd/*; do
test "$(readlink "$descriptor")" = /work/pressure-file || continue
sed -n 's/^pos:[[:space:]]*//p' "/proc/1/fdinfo/${descriptor##*/}"
exit
done
exit 1"#,
        ],
    )?;
    String::from_utf8(output)
        .map_err(std::io::Error::other)?
        .trim()
        .parse()
        .map_err(std::io::Error::other)
}

fn wait_for_stalled_download(path: &std::path::Path) -> std::io::Result<u64> {
    use std::time::{Duration, Instant};

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut previous = 0;
    let mut stable_since = Instant::now();
    loop {
        let position = download_file_position(path)?;
        assert!(position > 0 && position < STALLED_FILE_BYTES);
        if position != previous {
            previous = position;
            stable_since = Instant::now();
        } else if stable_since.elapsed() >= Duration::from_millis(250) {
            return Ok(position);
        }
        if Instant::now() >= deadline {
            return Err(std::io::Error::other(
                "unread download did not stop before EOF",
            ));
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn fill_stalled_network_writer(stream: &mut std::net::TcpStream) -> std::io::Result<usize> {
    use std::io::Write as _;
    use std::time::{Duration, Instant};

    stream.set_nonblocking(true)?;
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut accepted = 0;
    let mut stalled_since = None;
    loop {
        match stream.write(&[0; 8192]) {
            Ok(0) => return Err(std::io::ErrorKind::WriteZero.into()),
            Ok(count) => {
                accepted += count;
                assert!(accepted < 16 << 20, "unread network peer remains bounded");
                stalled_since = None;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if stalled_since.get_or_insert_with(Instant::now).elapsed()
                    >= Duration::from_millis(250)
                {
                    assert!(
                        accepted >= 8192,
                        "network transfer progressed before stalling"
                    );
                    return Ok(accepted);
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
        if Instant::now() >= deadline {
            return Err(std::io::Error::other(
                "unread network peer did not exert backpressure",
            ));
        }
    }
}

fn stop_with_stalled_transfers(
    path: &std::path::Path,
    host_port: u16,
    mut control: terra_platform::io::local::LocalStream,
) -> std::io::Result<(
    terra_platform::io::local::LocalStream,
    std::net::TcpStream,
    std::time::Instant,
)> {
    use std::io::Write as _;

    let stalled = (|| {
        eprintln!("STALLED_BULK_WAITING_FOR_GUEST_LISTENER");
        agent_exec(
            path,
            &[
                "sh",
                "-c",
                &format!(
                    "while ! grep -q ':{STALLED_GUEST_PORT:04X} ' /proc/net/tcp /proc/net/tcp6; do sleep 0.01; done"
                ),
            ],
        )?;
        eprintln!("STALLED_BULK_GUEST_LISTENER_READY");
        let mut network = std::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, host_port))?;
        let network_bytes = fill_stalled_network_writer(&mut network)?;
        eprintln!("NETWORK_STALLED accepted_bytes={network_bytes}");
        let download = begin_stalled_download(path)?;
        eprintln!("STALLED_BULK_DOWNLOAD_STARTED");
        let file_position = wait_for_stalled_download(path)?;
        eprintln!("FILE_STALLED read_position={file_position}");
        assert_agent_control_and_exec(path)?;
        assert_eq!(download_file_position(path)?, file_position);
        assert_eq!(
            network.write(&[0]).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        eprintln!(
            "BULK_STALLED network_accepted_bytes={network_bytes} file_read_position={file_position} file_bytes={STALLED_FILE_BYTES} stable_window_ms=250"
        );
        Ok((download, network, std::time::Instant::now()))
    })();
    let stopped = control.write_all(&[terra_protocol::STOP_SIGNAL]);
    stalled.and_then(|streams| stopped.map(|()| streams))
}

/// An unread download stops the guest source fd below EOF, and a published peer
/// that never reads makes the host writer persistently `WouldBlock`. Fresh agent
/// control still answers, then STOP cancels both operations and reaps the VM
/// without draining either transfer first. These observations prove application
/// backpressure, without claiming that every internal queue is full.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires native KVM, matching component AOT artifacts, and boot assets"]
async fn kernel_boots_control_and_stop_progress_with_stalled_network_and_file() {
    use std::time::Duration;
    use terra_protocol::{BootPlan, PlanMode, Share, encode_frame, read_frame};

    let directory = tempfile::tempdir().unwrap();
    std::fs::File::create(directory.path().join("pressure-file"))
        .unwrap()
        .set_len(STALLED_FILE_BYTES)
        .unwrap();
    let (_socket_dir, socket_path, listener) = bridge_listener();
    let (_control_dir, control_path, control_listener) = bridge_listener();
    let control_writer = terra_platform::io::local::LocalStream::connect(&control_path).unwrap();
    let (control, _) = control_listener.accept().unwrap();
    let host_port = reserved_loopback_port();
    let encoded = boot_plan(
        PlanMode::Run,
        Vec::new(),
        vec![
            "sh".into(),
            "-c".into(),
            format!("exec busybox nc -l -p {STALLED_GUEST_PORT} -e /bin/sleep 120"),
        ],
        false,
    );
    let mut envelope: BootPlan = read_frame(&mut encoded.as_slice()).unwrap().unwrap();
    envelope.plan.published_ports.push(STALLED_GUEST_PORT);
    envelope.plan.shares.push(Share {
        tag: crate::component::fs::share_tag(0),
        guest: "/work".into(),
        readonly: false,
    });
    envelope
        .plan
        .pre_stop
        .push("touch /work/CONTROL_WHILE_BULK_STALLED".into());
    let client = tokio::task::spawn_blocking(move || {
        stop_with_stalled_transfers(&socket_path, host_port, control_writer)
    });
    let diagnostics = tempfile::NamedTempFile::new().unwrap();
    let (kernel, boot_disk, root_path) = kernel_boot_assets();
    let worker = run_vm(super::orchestration::VmInput {
        component_memory_limits: crate::box_runtime::ComponentMemoryLimits::default(),
        kernel,
        boot_disk,
        root_disk: root_path.to_path_buf(),
        volume_disks: Vec::new(),
        shares: vec![crate::component::fs::ShareGrant::new(directory.path(), false).unwrap()],
        plan: encode_frame(&envelope).unwrap(),
        artifacts: crate::test_fixtures::trusted_artifacts(),
        network_backend: Some(start_network_broker(
            Network::default(),
            &[PortMapping::new(host_port, STALLED_GUEST_PORT)],
        )),
        port_mappings: vec![PortMapping::new(host_port, STALLED_GUEST_PORT)],
        ram_bytes: BOOT_RAM,
        vcpus: 2,
        deadline: Some(Duration::from_secs(45)),
        hard_stop: None,
        listener: Some(listener),
        control: Some(control),
        diagnostics: Some(diagnostics.reopen().unwrap()),
    });
    let (outcome, client) = tokio::join!(worker, client);
    let output = std::fs::read_to_string(diagnostics.path()).unwrap();
    let (download, network, stop_sent) = client
        .unwrap()
        .unwrap_or_else(|error| panic!("stalled bulk clients: {error}\n{output}"));
    let outcome = outcome.unwrap_or_else(|error| panic!("stalled bulk VM: {error}\n{output}"));
    let stop_elapsed = stop_sent.elapsed();
    assert!(
        stop_elapsed < Duration::from_secs(10),
        "STOP while stalled: {outcome:?}\n{output}"
    );
    assert_eq!(outcome.exit_code, Some(143), "{outcome:?}\n{output}");
    assert!(
        outcome.vcpu_outcomes.iter().all(Result::is_ok),
        "{outcome:?}"
    );
    assert!(
        directory.path().join("CONTROL_WHILE_BULK_STALLED").exists(),
        "{output}"
    );
    assert_stalled_transfers_closed(download, network);
    eprintln!(
        "CONTROL_AND_STOP_WHILE_BULK_STALLED stop_elapsed_us={}",
        stop_elapsed.as_micros()
    );
}

fn assert_stalled_transfers_closed(
    mut download: terra_platform::io::local::LocalStream,
    mut network: std::net::TcpStream,
) {
    use std::io::Read as _;

    let mut partial = Vec::new();
    download.read_to_end(&mut partial).unwrap();
    assert!(u64::try_from(partial.len()).unwrap() < STALLED_FILE_BYTES);
    network.set_nonblocking(false).unwrap();
    network
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .unwrap();
    match network.read(&mut [0]) {
        Ok(0) => {}
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
        result => panic!("stopped network transfer remains live: {result:?}"),
    }
}

fn serve_network_reset_peer(listener: &std::net::TcpListener) -> bool {
    use std::io::{Read as _, Write as _};
    use std::time::{Duration, Instant};

    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return false;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("network reset peer: {error}"),
        }
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    stream.write_all(&[0x5a]).unwrap();
    match stream.read(&mut [0]) {
        Ok(0) => true,
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => true,
        result => panic!("network reset did not close broker peer: {result:?}"),
    }
}

fn read_reset_marker(path: &std::path::Path) -> std::io::Result<(u64, u64)> {
    use std::time::{Duration, Instant};

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match std::fs::read_to_string(path) {
            Ok(contents) if !contents.trim().is_empty() => {
                let words: Vec<_> = contents.split_whitespace().collect();
                let [first, second] = words.as_slice() else {
                    return Err(std::io::Error::other("invalid network reset marker"));
                };
                return Ok((
                    first.parse().map_err(std::io::Error::other)?,
                    second.parse().map_err(std::io::Error::other)?,
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        if Instant::now() >= deadline {
            return Err(std::io::Error::other(format!(
                "network reset marker did not appear: {}",
                path.display()
            )));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn exec_after_agent_ready(path: &std::path::Path, argv: &[&str]) -> std::io::Result<Vec<u8>> {
    run_agent_exec(connect_agent_once(path)?, argv, None)
}

fn stop_after_network_reset(
    path: &std::path::Path,
    directory: &std::path::Path,
    diagnostics: &std::path::Path,
    closed: &std::sync::mpsc::Receiver<bool>,
    shared_reset: bool,
    mut control: terra_platform::io::local::LocalStream,
) -> std::io::Result<std::time::Instant> {
    use std::io::Write as _;
    use std::time::{Duration, Instant};

    let checked = (|| {
        let (pid, receive_syscall) = read_reset_marker(&directory.join("NETWORK_READ_WAITING"))?;
        let syscall_path = format!("/proc/{pid}/syscall");
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let output = exec_after_agent_ready(path, &["cat", &syscall_path])?;
            if String::from_utf8_lossy(&output).split_whitespace().next()
                == Some(receive_syscall.to_string().as_str())
            {
                break;
            }
            if Instant::now() >= deadline {
                return Err(std::io::Error::other(
                    "guest external receive did not block",
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        std::thread::sleep(Duration::from_millis(250));
        let output = exec_after_agent_ready(path, &["cat", &syscall_path])?;
        assert_eq!(
            String::from_utf8_lossy(&output).split_whitespace().next(),
            Some(receive_syscall.to_string().as_str())
        );
        assert!(!directory.join("NETWORK_RESET_RESULT").exists());
        let endpoints_before =
            exec_after_agent_ready(path, &["/work/vsock-probe", "endpoints-network"])?;
        let started = Instant::now();
        if shared_reset {
            exec_until_agent_disconnect(path, &["/work/vsock-probe", "shared-reset"])?;
            assert!(directory.join("SHARED_RESET_STARTED").exists());
            assert!(closed.recv_timeout(Duration::from_secs(3)).unwrap());
            return Ok(started);
        }
        let stopped = exec_after_agent_ready(path, &["/work/vsock-probe", "control-stop"])?;
        assert!(String::from_utf8_lossy(&stopped).contains("NETWORK_CONTROL_STOPPED"));
        let (receive_error, poll_events) =
            read_reset_marker(&directory.join("NETWORK_RESET_RESULT"))?;
        assert!(receive_error > 0 && poll_events > 0);
        assert!(closed.recv_timeout(Duration::from_secs(3)).unwrap());
        let deadline = Instant::now() + Duration::from_secs(3);
        while !std::fs::read_to_string(diagnostics)?.contains("network unavailable") {
            if Instant::now() >= deadline {
                return Err(std::io::Error::other(
                    "network disconnect diagnostic missing",
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_agent_control_reply(connect_agent_once(path)?)?;
        assert_eq!(
            exec_after_agent_ready(path, &["printf", "agent-after-network-reset"])?,
            b"agent-after-network-reset"
        );
        assert_eq!(
            exec_after_agent_ready(path, &["/work/vsock-probe", "endpoints"])?,
            endpoints_before
        );
        exec_after_agent_ready(path, &["sh", "-c", &format!("kill -0 {pid}")])?;
        eprintln!(
            "NETWORK_OWNER_RESET_AGENT_LIVE recv_errno={receive_error} poll_events={poll_events} blocked_window_ms=250"
        );
        Ok(Instant::now())
    })();
    if shared_reset {
        checked
    } else {
        let stopped = control.write_all(&[terra_protocol::STOP_SIGNAL]);
        checked.and_then(|started| stopped.map(|()| started))
    }
}

/// Network control loss resets blocked sockets and releases broker resources while agent control and exec remain live.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires native KVM, Zig, and matching kernel, guest, and component artifacts"]
async fn kernel_network_control_loss_preserves_agent_control_and_stop() {
    assert_vsock_reset_effect(false).await;
}

/// Unbinding the one stock virtio-vsock device ends both roles without restoring stale readiness or requests.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires native KVM, Zig, and matching kernel, guest, and component artifacts"]
async fn kernel_shared_vsock_reset_disconnects_both_roles() {
    assert_vsock_reset_effect(true).await;
}

#[allow(clippy::too_many_lines)]
async fn assert_vsock_reset_effect(shared_reset: bool) {
    use terra_protocol::{BootPlan, PlanMode, Share, encode_frame, read_frame};

    let directory = tempfile::tempdir().unwrap();
    let probe = directory.path().join("vsock-probe");
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../terra/tests/assets/vsock_probe.c");
    let status = std::process::Command::new("zig")
        .args([
            "cc",
            "-target",
            &format!("{}-linux-musl", std::env::consts::ARCH),
        ])
        .args(["-static", "-O2", "-Wall", "-Wextra", "-Werror"])
        .arg(format!(
            "-DTERRA_SOCKET_ABI={}",
            terra_protocol::socket::VERSION
        ))
        .arg(format!(
            "-DTERRA_NETWORK_ABI={}",
            terra_protocol::application::VERSION
        ))
        .arg("-o")
        .arg(&probe)
        .arg(source)
        .status()
        .unwrap();
    assert!(status.success(), "compile reset probe: {status}");
    let peer = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = peer.local_addr().unwrap().port();
    let (closed, closed_receiver) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        closed.send(serve_network_reset_peer(&peer)).unwrap();
    });
    let encoded = boot_plan(
        PlanMode::Run,
        Vec::new(),
        vec![
            "sh".into(),
            "-c".into(),
            format!(
                "exec /work/vsock-probe {} {port} > /work/NETWORK_RESET_PROBE_LOG 2>&1",
                terra_protocol::socket::HOST_SERVICE_IPV4
            ),
        ],
        false,
    );
    let mut envelope: BootPlan = read_frame(&mut encoded.as_slice()).unwrap().unwrap();
    envelope.plan.shares.push(Share {
        tag: crate::component::fs::share_tag(0),
        guest: "/work".into(),
        readonly: false,
    });
    let (_socket_dir, socket_path, listener) = bridge_listener();
    let (_control_dir, control_path, control_listener) = bridge_listener();
    let control_writer = terra_platform::io::local::LocalStream::connect(&control_path).unwrap();
    let (control, _) = control_listener.accept().unwrap();
    let diagnostics = tempfile::NamedTempFile::new().unwrap();
    let client_directory = directory.path().to_owned();
    let client_diagnostics = diagnostics.path().to_owned();
    let client = tokio::task::spawn_blocking(move || {
        stop_after_network_reset(
            &socket_path,
            &client_directory,
            &client_diagnostics,
            &closed_receiver,
            shared_reset,
            control_writer,
        )
    });
    let (kernel, boot_disk, root_path) = kernel_boot_assets();
    let worker = run_vm(super::orchestration::VmInput {
        component_memory_limits: crate::box_runtime::ComponentMemoryLimits::default(),
        kernel,
        boot_disk,
        root_disk: root_path.to_path_buf(),
        volume_disks: Vec::new(),
        shares: vec![crate::component::fs::ShareGrant::new(directory.path(), false).unwrap()],
        plan: encode_frame(&envelope).unwrap(),
        artifacts: crate::test_fixtures::trusted_artifacts(),
        network_backend: Some(start_network_broker(
            Network {
                allow: vec![format!("HOST_LOOPBACK:{port}")],
                ..Network::default()
            },
            &[],
        )),
        port_mappings: Vec::new(),
        ram_bytes: BOOT_RAM,
        vcpus: 2,
        deadline: Some(std::time::Duration::from_secs(45)),
        hard_stop: None,
        listener: Some(listener),
        control: Some(control),
        diagnostics: Some(diagnostics.reopen().unwrap()),
    });
    let (outcome, client) = tokio::join!(worker, client);
    let server = server.join();
    let diagnostic = std::fs::read_to_string(diagnostics.path()).unwrap();
    let probe_output = std::fs::read_to_string(directory.path().join("NETWORK_RESET_PROBE_LOG"))
        .unwrap_or_else(|error| format!("probe output unavailable: {error}"));
    let stopped = client.unwrap().unwrap_or_else(|error| {
        panic!("network reset client: {error}\nguest probe:\n{probe_output}\n{diagnostic}")
    });
    server.unwrap();
    if shared_reset {
        if let Ok(outcome) = &outcome {
            assert_ne!(
                outcome.exit_code,
                Some(0),
                "shared reset accepted a successful workload: {outcome:?}"
            );
        }
        assert!(
            stopped.elapsed() < std::time::Duration::from_secs(10),
            "shared reset did not end the VM: {outcome:?}\n{diagnostic}"
        );
        eprintln!(
            "SHARED_VSOCK_RESET_BOTH_ROLES_ENDED elapsed_us={}",
            stopped.elapsed().as_micros()
        );
    } else {
        let outcome =
            outcome.unwrap_or_else(|error| panic!("network owner reset VM: {error}\n{diagnostic}"));
        assert_eq!(outcome.exit_code, Some(143), "{outcome:?}\n{diagnostic}");
        assert!(
            outcome.vcpu_outcomes.iter().all(Result::is_ok),
            "{outcome:?}"
        );
        assert!(stopped.elapsed() < std::time::Duration::from_secs(10));
        eprintln!(
            "NETWORK_OWNER_RESET_AGENT_STOP_OK elapsed_us={}",
            stopped.elapsed().as_micros()
        );
    }
}

/// A static musl resolver retries truncated UDP DNS over native loopback TCP,
/// while both requests resolve through the replacement network component.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires native KVM, Zig, matching components, and boot assets"]
async fn kernel_boots_libc_dns_tcp_fallback() {
    use terra_protocol::{PlanMode, Share, encode_frame, read_frame};

    let directory = tempfile::tempdir().unwrap();
    let probe = directory.path().join("socket-probe");
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../terra/tests/assets/socket_probe.c");
    let status = std::process::Command::new("zig")
        .args([
            "cc",
            "-target",
            &format!("{}-linux-musl", std::env::consts::ARCH),
        ])
        .args(["-static", "-O2", "-Wall", "-Wextra", "-Werror"])
        // musl's CMSG_NXTHDR mixes unsigned lengths with signed pointer differences.
        .args(["-Wno-sign-compare", "-o"])
        .arg(&probe)
        .arg(source)
        .status()
        .unwrap();
    assert!(status.success(), "compile static DNS probe: {status}");
    let encoded = boot_plan(
        PlanMode::Run,
        Vec::new(),
        vec!["/work/socket-probe".into(), "--dns-tcp-fallback".into()],
        true,
    );
    let envelope: terra_protocol::BootPlan = read_frame(&mut encoded.as_slice()).unwrap().unwrap();
    let mut plan = envelope.plan;
    plan.shares.push(Share {
        tag: crate::component::fs::share_tag(0),
        guest: "/work".into(),
        readonly: true,
    });
    let (backend, stop, responder) = crate::self_test::network::create_dns_fallback_backend();
    let backend_client = backend.client.clone();
    let diagnostics = tempfile::NamedTempFile::new().unwrap();
    let (kernel, boot_disk, root_path) = kernel_boot_assets();
    let (_socket_dir, socket_path, listener) = bridge_listener();
    let client = tokio::task::spawn_blocking(move || await_foreground_workload(&socket_path));
    let worker = run_vm(super::orchestration::VmInput {
        component_memory_limits: crate::box_runtime::ComponentMemoryLimits::default(),
        kernel,
        boot_disk,
        root_disk: root_path.to_path_buf(),
        volume_disks: Vec::new(),
        shares: vec![crate::component::fs::ShareGrant::new(directory.path(), true).unwrap()],
        plan: encode_frame(&terra_protocol::BootPlan::new(plan)).unwrap(),
        artifacts: crate::test_fixtures::trusted_artifacts(),
        network_backend: Some(backend),
        port_mappings: Vec::new(),
        ram_bytes: BOOT_RAM,
        vcpus: 2,
        deadline: Some(std::time::Duration::from_mins(1)),
        hard_stop: None,
        listener: Some(listener),
        control: None,
        diagnostics: Some(diagnostics.reopen().unwrap()),
    });
    let (outcome, client) = tokio::join!(worker, client);
    let output = std::fs::read_to_string(diagnostics.path()).unwrap();
    let _ = stop.send(());
    backend_client.disconnect();
    responder
        .await
        .unwrap()
        .unwrap_or_else(|error| panic!("DNS fallback broker: {error}\n{output}"));
    let outcome = outcome.unwrap_or_else(|error| panic!("DNS fallback VM: {error}\n{output}"));
    assert_eq!(outcome.exit_code, Some(0), "{outcome:?}\n{output}");
    let (stdout, exit_code) = client
        .expect("DNS probe client task")
        .expect("DNS probe session");
    assert_eq!(exit_code, 0);
    assert!(String::from_utf8_lossy(&stdout).contains("SOCKET_DNS_OK"));
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
        network_backend: Some(create_boot_network_backend()),
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
        network_backend: Some(create_boot_network_backend()),
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
        network_backend: Some(create_http_network_backend(address, port)),
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
        network_backend: Some(create_http_network_backend(address, port)),
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
async fn kernel_boots_through_broker_tcp() {
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
    use terra_protocol::read_frame;

    const GUEST_PORT: u16 = 8080;
    const BODY: &[u8] = b"published-body";
    let host_port = reserved_loopback_port();
    let (kernel, boot_disk, root_path) = kernel_boot_assets();
    let (_control_dir, control_path, control_listener) = bridge_listener();
    let mut control_writer =
        terra_platform::io::local::LocalStream::connect(&control_path).unwrap();
    let (control, _) = control_listener.accept().unwrap();
    let diagnostics = tempfile::NamedTempFile::new().expect("create diagnostics");
    let encoded = boot_plan(
        terra_protocol::PlanMode::Run,
        Vec::new(),
        vec![
            "sh".into(),
            "-c".into(),
            "while true; do printf 'HTTP/1.1 200 OK\\r\\nContent-Length: 14\\r\\nConnection: close\\r\\n\\r\\npublished-body' | busybox nc -l -p 8080; done".into(),
        ],
        false,
    );
    let envelope: terra_protocol::BootPlan = read_frame(&mut encoded.as_slice()).unwrap().unwrap();
    let mut plan = envelope.plan;
    plan.published_ports.push(GUEST_PORT);
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
        plan: terra_protocol::encode_frame(&terra_protocol::BootPlan::new(plan)).unwrap(),
        artifacts: crate::test_fixtures::trusted_artifacts(),
        network_backend: Some(start_network_broker(
            Network::default(),
            &[PortMapping::new(host_port, GUEST_PORT)],
        )),
        port_mappings: vec![PortMapping::new(host_port, GUEST_PORT)],
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
async fn kernel_boots_through_broker_large_tcp() {
    assert_policy_dns_http(native_ipv4_address(), &vec![b's'; 65_537]).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires a native hypervisor, component AOT artifacts, and boot assets"]
async fn kernel_uploads_through_broker_tcp() {
    assert_policy_dns_upload(native_ipv4_address(), 65_537).await;
}

fn serve_idle_tx_probe(
    listener: &std::net::TcpListener,
    stop: &std::sync::atomic::AtomicBool,
    idle_count: usize,
    has_active_stream: bool,
) -> (usize, bool) {
    use std::io::{Read as _, Write as _};
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};

    listener.set_nonblocking(true).unwrap();
    let mut streams = Vec::new();
    let mut has_closed_idle = idle_count == 0;
    let mut has_active_request = false;
    let mut has_active_reply = false;
    let deadline = Instant::now() + Duration::from_secs(90);
    while !stop.load(Ordering::Acquire) && Instant::now() < deadline {
        match listener.accept() {
            Ok((stream, _)) => {
                assert!(streams.len() < idle_count + usize::from(has_active_stream));
                stream.set_nonblocking(true).unwrap();
                streams.push(stream);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => panic!("idle TX probe accept: {error}"),
        }
        if has_active_stream && streams.len() > idle_count && !has_active_reply {
            if idle_count != 0 {
                match streams[0].read(&mut [0]) {
                    Ok(0) => has_closed_idle = true,
                    Ok(_) => panic!("idle TX peer received unexpected data"),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(error) => panic!("idle TX peer close: {error}"),
                }
            }
            if !has_active_request {
                let mut byte = [0];
                match streams[idle_count].read(&mut byte) {
                    Ok(1) => {
                        assert_eq!(byte, [0x5a]);
                        has_active_request = true;
                    }
                    Ok(length) => panic!("active TX request length: {length}"),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(error) => panic!("active TX request: {error}"),
                }
            }
            if has_closed_idle && has_active_request {
                assert_eq!(streams[idle_count].write(&[0xa5]).unwrap(), 1);
                has_active_reply = true;
            }
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    (streams.len(), has_active_reply)
}

/// Forty idle TCP sockets preserve native TCP progress and independent close.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires native KVM, Zig, matching components, and boot assets"]
#[allow(clippy::too_many_lines)]
async fn kernel_network_idle_sockets_preserve_tcp_progress() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use terra_protocol::{BootPlan, Net, PlanMode, Share, encode_frame, read_frame};

    let directory = tempfile::tempdir().unwrap();
    let probe = directory.path().join("network-tx-probe");
    let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../terra/tests/assets/network_tx_probe.c");
    let status = std::process::Command::new("zig")
        .args([
            "cc",
            "-target",
            &format!("{}-linux-musl", std::env::consts::ARCH),
        ])
        .args(["-static", "-O2", "-Wall", "-Wextra", "-Werror", "-o"])
        .arg(&probe)
        .arg(source)
        .status()
        .unwrap();
    assert!(status.success(), "compile static TX probe: {status}");
    for (mode, net, idle_count, marker) in [("sockets", Net::Tsi, 40, "NETWORK_TX_IDLE_READS_OK")] {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let backend = start_network_broker(
            Network {
                allow: vec![format!("HOST_LOOPBACK:{port}")],
                ..Network::default()
            },
            &[],
        );
        let stop = Arc::new(AtomicBool::new(false));
        let server_stop = Arc::clone(&stop);
        let has_active_stream = true;
        let server = std::thread::spawn(move || {
            serve_idle_tx_probe(&listener, &server_stop, idle_count, has_active_stream)
        });
        let encoded = boot_plan(
            PlanMode::Run,
            Vec::new(),
            vec![
                "/work/network-tx-probe".into(),
                mode.into(),
                port.to_string(),
            ],
            true,
        );
        let mut envelope: BootPlan = read_frame(&mut encoded.as_slice()).unwrap().unwrap();
        envelope.plan.net = net;
        envelope.plan.shares.push(Share {
            tag: crate::component::fs::share_tag(0),
            guest: "/work".into(),
            readonly: true,
        });
        let diagnostics = tempfile::NamedTempFile::new().unwrap();
        let (kernel, boot_disk, root_path) = kernel_boot_assets();
        let (_socket_dir, socket_path, listener) = bridge_listener();
        let client = tokio::task::spawn_blocking(move || await_foreground_workload(&socket_path));
        let worker = run_vm(super::orchestration::VmInput {
            component_memory_limits: crate::box_runtime::ComponentMemoryLimits::default(),
            kernel,
            boot_disk,
            root_disk: root_path.to_path_buf(),
            volume_disks: Vec::new(),
            shares: vec![crate::component::fs::ShareGrant::new(directory.path(), true).unwrap()],
            plan: encode_frame(&envelope).unwrap(),
            artifacts: crate::test_fixtures::trusted_artifacts(),
            network_backend: Some(backend),
            port_mappings: Vec::new(),
            ram_bytes: BOOT_RAM,
            vcpus: 2,
            deadline: Some(std::time::Duration::from_secs(75)),
            hard_stop: None,
            listener: Some(listener),
            control: None,
            diagnostics: Some(diagnostics.reopen().unwrap()),
        });
        let (outcome, client) = tokio::join!(worker, client);
        stop.store(true, Ordering::Release);
        let server_result = server.join().unwrap();
        let diagnostics = std::fs::read_to_string(diagnostics.path()).unwrap();
        let outcome =
            outcome.unwrap_or_else(|error| panic!("{mode} TX probe VM: {error}\n{diagnostics}"));
        let (stdout, exit_code) = client
            .expect("TX probe client task")
            .unwrap_or_else(|error| panic!("{mode} TX probe session: {error}\n{diagnostics}"));
        let stdout = String::from_utf8_lossy(&stdout);
        assert_eq!(exit_code, 0, "{mode}: {stdout}\n{diagnostics}");
        assert_eq!(
            outcome.exit_code,
            Some(0),
            "{mode}: {outcome:?}\n{diagnostics}"
        );
        assert!(stdout.contains(marker), "{mode}: {stdout}\n{diagnostics}");
        assert_eq!(server_result.0, idle_count + usize::from(has_active_stream));
        assert_eq!(server_result.1, has_active_stream);
        eprintln!("{stdout}");
    }
}
