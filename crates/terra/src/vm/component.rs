//! Prepare native capabilities and start the embedded WASI VMM.

use super::boot::BootSpec;
use super::{encode_boot_plan, image};
use crate::policy::network::rules;
use crate::state::BoxRef;
use crate::{logs, sys};
use anyhow::{Context, Result};
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::process::ExitCode;
use terra_platform::io::local::{LocalListener, LocalStream, create_local_pair};
use terra_protocol::PlanMode;
use terra_runtime::TrustedArtifacts;
use terra_runtime::component::fs::ShareGrant;
use terra_runtime::orchestration::VmInput;

#[allow(unsafe_code)]
const ARTIFACTS: TrustedArtifacts = {
    // SAFETY: Make generates these AOT artifacts from repository components for this target.
    unsafe {
        TrustedArtifacts::new(
            include_bytes!(env!("TERRA_BLOCK_AOT")),
            include_bytes!(env!("TERRA_AGENT_AOT")),
            include_bytes!(env!("TERRA_VSOCK_FRONTEND_AOT")),
            include_bytes!(env!("TERRA_FS_AOT")),
            include_bytes!(env!("TERRA_MEM_AOT")),
            include_bytes!(env!("TERRA_BOOT_AOT")),
            include_bytes!(env!("TERRA_VMM_AOT")),
            include_bytes!(env!("TERRA_INTERRUPT_CONTROLLER_AOT")),
        )
    }
};

#[allow(
    clippy::unused_async,
    reason = "broker supervision uses bounded host process waits"
)]
pub async fn run_host_self_test() -> Result<()> {
    super::supervisor::run_host_self_test()
}

fn volume_disk_paths(spec: &BootSpec, bx: &BoxRef) -> Vec<std::path::PathBuf> {
    spec.cfg
        .volumes
        .iter()
        .map(|volume| bx.get_volume_image(&volume.name))
        .collect()
}

pub(crate) async fn run_host_self_test_worker(
    dir: std::path::PathBuf,
    endpoints: [u16; 3],
) -> Result<ExitCode> {
    let spec = super::boot::read_boot_spec(std::io::stdin().lock())?;
    let bx = BoxRef::from_state_dir(dir, &spec.project_dir);
    let _run_lock = sys::claim_inherited_lock(&bx.get_dir().join(crate::state::PID_FILE))
        .context("missing self-test VM run lock")?;
    prepare_vm_process(&bx, spec.mode)?;
    exercise_host_services(&bx)?;
    let directory = super::supervisor::self_test_directory(&bx);
    #[cfg(any(target_os = "macos", windows))]
    let agent_listeners = Some(terra_runtime::self_test::AgentListeners {
        control: sys::claim_listener(
            super::supervisor::AGENT_CONTROL_LISTENER_FD,
            &directory.join("agent-control.sock"),
        )?,
        agent: sys::claim_listener(
            super::supervisor::AGENT_AGENT_LISTENER_FD,
            &directory.join("agent-agent.sock"),
        )?,
    });
    #[cfg(target_os = "linux")]
    let agent_listeners = None;
    let Some(backend) = prepare_network_backend(&spec)? else {
        terra_runtime::self_test::run_self_test_local_only(ARTIFACTS, &directory, agent_listeners)
            .await
            .map_err(|error| anyhow::anyhow!("{error:#}"))?;
        return Ok(ExitCode::SUCCESS);
    };
    let client = backend.client.clone();
    exercise_broker_denials_and_limits(&client).await?;
    terra_runtime::self_test::run_self_test_with_network(
        ARTIFACTS,
        &directory,
        backend,
        terra_runtime::self_test::network::Endpoints {
            tcp: endpoints[0],
            udp: endpoints[1],
            published: endpoints[2],
        },
        agent_listeners,
    )
    .await
    .map_err(|error| anyhow::anyhow!("{error:#}"))?;
    client.disconnect();
    Ok(ExitCode::SUCCESS)
}

async fn exercise_broker_denials_and_limits(client: &terra_network::Client) -> Result<()> {
    use terra_network::{Error, Operation, Reply};
    anyhow::ensure!(
        client
            .request(Operation::OpenTcp {
                peer: "192.0.2.1:443".parse()?,
                inline_urgent: false
            })
            .await
            == Err(Error::AccessDenied),
        "broker broadened egress grants"
    );
    anyhow::ensure!(
        client
            .request(Operation::Resolve("denied.test".into()))
            .await
            == Err(Error::AccessDenied),
        "broker broadened name grants"
    );
    anyhow::ensure!(
        client.request(Operation::Resolve("localhost".into())).await
            == Err(Error::NameUnresolvable),
        "broker learned a floored resolver answer"
    );
    anyhow::ensure!(
        client.request(Operation::Accept(u32::MAX)).await == Err(Error::AccessDenied),
        "broker broadened listener grants"
    );
    anyhow::ensure!(
        client.request(Operation::Cancel(u64::MAX)).await == Ok(Reply::Cancelled(false)),
        "broker accepted a stale cancellation"
    );
    let mut handles = Vec::new();
    for _ in 0..=terra_network::MAX_RESOURCES {
        match client.request(Operation::OpenUdp).await {
            Ok(Reply::Opened { handle, .. }) => handles.push(handle),
            Err(Error::LimitExceeded) => break,
            result => anyhow::bail!("unexpected broker resource admission: {result:?}"),
        }
    }
    anyhow::ensure!(
        !handles.is_empty() && handles.len() <= terra_network::MAX_RESOURCES,
        "broker resource limit failed"
    );
    let handle = handles[0];
    anyhow::ensure!(
        client
            .request(Operation::Read {
                handle,
                max_bytes: 1
            })
            .await
            == Err(Error::WrongKind),
        "broker accepted wrong resource kind"
    );
    for handle in handles {
        client
            .request(Operation::Close(handle))
            .await
            .map_err(|error| anyhow::anyhow!("broker close: {error:?}"))?;
    }
    anyhow::ensure!(
        client.request(Operation::Close(handle)).await == Err(Error::StaleHandle),
        "broker accepted stale handle"
    );
    Ok(())
}

fn exercise_host_services(bx: &BoxRef) -> Result<()> {
    anyhow::ensure!(
        bx.read_vm_process()
            .is_some_and(|process| process.pid > 0 && process.process_identity.is_some()),
        "host self-test VM identity was not published"
    );
    anyhow::ensure!(
        !image::load_kernel()?.is_empty() && !image::load_boot_image()?.is_empty(),
        "embedded kernel or boot image is empty"
    );
    let diagnostics = bx.get_dir().join(crate::state::DIAGNOSTICS_LOG);
    anyhow::ensure!(
        sys::create_regular_file(&diagnostics)?.metadata()?.len() == 0,
        "host self-test diagnostics did not start empty"
    );
    let listener = agent_listener(bx)?;
    let (host, mut worker) = create_local_pair().context("creating host self-test stop channel")?;
    worker.set_read_timeout(Some(std::time::Duration::from_secs(2)))?;
    relay_stop(stop_listener(bx)?, host);
    super::boot::write_agent_ready();
    let (accepted, _) = listener.accept()?;
    drop((accepted, listener));
    let mut stop = [0];
    worker.read_exact(&mut stop)?;
    anyhow::ensure!(
        stop == [terra_protocol::STOP_SIGNAL],
        "host self-test stop request was not relayed"
    );
    Ok(())
}

fn prepare_vm_process(bx: &BoxRef, mode: PlanMode) -> Result<()> {
    sys::validate_host_root()?;
    #[cfg(unix)]
    super::resources::limit_vm_process()?;
    logs::init(bx)?;
    if mode == PlanMode::Run {
        sys::install_stop_signal_handlers();
    }
    Ok(())
}

fn open_shares(spec: &BootSpec) -> Result<Vec<ShareGrant>> {
    if spec.mode == PlanMode::Create {
        return Ok(Vec::new());
    }

    let mounts = &spec.cfg.mounts;
    let mut grants = Vec::with_capacity(mounts.len());
    for mount in mounts {
        grants.push(
            ShareGrant::new(&mount.host, mount.readonly).with_context(|| {
                format!(
                    "opening share {}",
                    crate::render::escape_printable_path(&mount.host)
                )
            })?,
        );
    }
    Ok(grants)
}

fn agent_listener(bx: &BoxRef) -> Result<LocalListener> {
    let path = bx.get_dir().join(crate::state::AGENT_SOCKET);
    #[cfg(any(target_os = "macos", windows))]
    if uses_inherited_listeners() {
        return sys::claim_listener(super::supervisor::AGENT_LISTENER_FD, &path)
            .map_err(Into::into);
    }
    let _ = std::fs::remove_file(&path);
    image::sweep_staging_temps(bx.get_dir(), |_| false);
    let listener = LocalListener::bind(&path)
        .with_context(|| format!("binding the agent socket {}", path.display()))?;
    sys::set_owner_only(&path, false).with_context(|| format!("securing {}", path.display()))?;
    Ok(listener)
}

fn stop_listener(bx: &BoxRef) -> Result<LocalListener> {
    let path = bx.get_dir().join(crate::state::CONTROL_SOCKET);
    #[cfg(any(target_os = "macos", windows))]
    if uses_inherited_listeners() {
        return sys::claim_listener(super::supervisor::CONTROL_LISTENER_FD, &path)
            .map_err(Into::into);
    }
    let _ = std::fs::remove_file(&path);
    let listener = LocalListener::bind(&path)
        .with_context(|| format!("binding the stop socket {}", path.display()))?;
    sys::set_owner_only(&path, false).with_context(|| format!("securing {}", path.display()))?;
    Ok(listener)
}

#[cfg(any(target_os = "macos", windows))]
fn uses_inherited_listeners() -> bool {
    #[cfg(target_os = "macos")]
    const ROLE_ENV: &str = "TERRA_MACOS_SANDBOX_ROLE";
    #[cfg(windows)]
    const ROLE_ENV: &str = "TERRA_WINDOWS_SANDBOX_ROLE";
    std::env::var_os(ROLE_ENV).is_some_and(|role| role == "vm")
}

fn relay_stop(listener: LocalListener, mut control: LocalStream) {
    std::thread::spawn(move || {
        if let Ok((mut request, _)) = listener.accept() {
            let mut byte = [0];
            if request.read_exact(&mut byte).is_ok() && byte == [terra_protocol::STOP_SIGNAL] {
                let _ = control.write_all(&byte);
            }
        }
    });
}

#[allow(clippy::too_many_lines)]
pub async fn run(
    spec: &BootSpec,
    bx: &BoxRef,
    lock: Option<&File>,
    on_ready: impl FnOnce() + Send,
) -> Result<ExitCode> {
    prepare_vm_process(bx, spec.mode)?;
    let component_memory_limits = spec.cfg.components.memory_limits()?;

    let kernel = image::load_kernel()?;
    let boot_disk = image::load_boot_image()?;
    let root_disk = bx.get_dir().join(crate::state::ROOTFS_FILE);
    let plan = encode_boot_plan(spec)?;
    let volume_disks = volume_disk_paths(spec, bx);
    let shares = open_shares(spec)?;
    let listener = Some(agent_listener(bx)?);
    let port_mappings = if spec.mode == PlanMode::Run {
        rules::parse_port_mappings(&spec.cfg.network.ports)?
    } else {
        Vec::new()
    };
    let network_backend = prepare_network_backend(spec)?;

    log::info!(
        "terra: {} {bx} ({} vCPU, {} MiB)",
        if spec.mode == PlanMode::Create {
            "baking"
        } else {
            "starting"
        },
        spec.cfg.hw.cpus,
        spec.cfg.hw.mem_mib
    );
    let diagnostics_path = bx.get_dir().join(crate::state::DIAGNOSTICS_LOG);
    let diagnostics = Some(sys::create_regular_file(&diagnostics_path)?);
    let control = if spec.mode == PlanMode::Run {
        let (host, worker) = create_local_pair().context("creating the VM stop channel")?;
        sys::register_stop_channel(host.try_clone()?);
        relay_stop(stop_listener(bx)?, host);
        Some(worker)
    } else {
        None
    };

    if !spec.host_publishes_pid {
        BoxRef::publish_pid(
            lock.context("missing VM run lock")?,
            std::process::id(),
            spec.mode == PlanMode::Create,
        )
        .context("publishing the VM process identity")?;
    }
    let prepared = terra_runtime::orchestration::prepare(VmInput {
        component_memory_limits,
        kernel,
        boot_disk,
        root_disk,
        volume_disks,
        shares,
        plan,
        artifacts: ARTIFACTS,
        network_backend,
        port_mappings,
        ram_bytes: u64::from(spec.cfg.hw.mem_mib) << 20,
        vcpus: usize::from(spec.cfg.hw.cpus),
        deadline: None,
        hard_stop: Some(std::process::abort),
        listener,
        control,
        diagnostics,
    })
    .await;
    let worker_result = match prepared {
        Ok(prepared) => {
            log::info!("component VMM prepared; starting guest CPUs and devices");
            prepared.run(on_ready).await
        }
        Err(error) => Err(error),
    };
    let outcome = worker_result.map_err(|error| {
        log::error!("component VMM failed: {error:?}");
        anyhow::anyhow!("running the component VMM: {error:?}")
    })?;
    let code = outcome.exit_code.ok_or_else(|| {
        log::error!(
            "component VMM stopped without agent status: {:?}",
            outcome.vcpu_outcomes
        );
        anyhow::anyhow!("the component VMM stopped without an agent exit status")
    })?;
    Ok(ExitCode::from(crate::exit_status_byte(code)))
}

fn prepare_network_backend(
    spec: &BootSpec,
) -> Result<Option<terra_runtime::component::network::NetworkBackend>> {
    if !spec.cfg.network.enabled {
        anyhow::ensure!(
            spec.network_broker.is_none(),
            "local-only VM received network broker metadata"
        );
        return Ok(None);
    }
    let metadata = spec
        .network_broker
        .as_ref()
        .context("missing VM network broker metadata")?;
    let endpoint = sys::claim_ipc(super::supervisor::NETWORK_FD)?;
    endpoint.set_nonblocking(true)?;
    Ok(Some(terra_runtime::component::network::NetworkBackend {
        client: terra_network::Client::new(terra_platform::io::local::AsyncLocalStream::from_std(
            endpoint,
        )?),
        ready: metadata.ready.clone(),
        listeners: metadata.listeners.clone(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Mount};
    use std::path::PathBuf;

    #[test]
    fn broker_absence_requires_local_only_configuration() {
        let mut spec = BootSpec {
            cfg: Config::default(),
            project_dir: PathBuf::from("/project"),
            root: false,
            mode: PlanMode::Run,
            foreground: false,
            host_publishes_pid: false,
            network_broker: None,
        };
        let error = prepare_network_backend(&spec).err().unwrap();
        assert!(
            error
                .to_string()
                .contains("missing VM network broker metadata")
        );
        spec.cfg.network.enabled = false;
        assert!(prepare_network_backend(&spec).unwrap().is_none());
        assert!(super::super::supervisor::build_broker_config(&spec).is_err());
        spec.network_broker = Some(super::super::boot::BrokerMetadata {
            ready: terra_network::config::Ready {
                version: terra_network::config::PROTOCOL_VERSION,
                host_service_ports: Vec::new(),
                blocks_direct_dns: true,
            },
            listeners: Vec::new(),
        });
        assert!(prepare_network_backend(&spec).is_err());
    }

    #[test]
    fn stop_socket_relays_the_request_to_the_vm_control_channel() {
        let dir = tempfile::tempdir().unwrap();
        let bx = BoxRef::from_state_dir(dir.path().join("state"), dir.path());
        std::fs::create_dir(bx.get_dir()).unwrap();
        let listener = stop_listener(&bx).unwrap();
        let (host, mut worker) = create_local_pair().unwrap();
        worker
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        relay_stop(listener, host);
        bx.request_stop().unwrap();
        let mut byte = [0];
        worker.read_exact(&mut byte).unwrap();
        assert_eq!(byte, [terra_protocol::STOP_SIGNAL]);
    }

    #[test]
    fn workload_mounts_have_matching_grants_and_plan_tags() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let spec = BootSpec {
            cfg: Config {
                mounts: vec![Mount {
                    host: root,
                    guest: PathBuf::from("/work"),
                    readonly: true,
                }],
                ..Config::default()
            },
            project_dir: PathBuf::from("/project"),
            root: false,
            mode: PlanMode::Run,
            foreground: false,
            host_publishes_pid: false,
            network_broker: None,
        };
        let grants = open_shares(&spec).unwrap();
        let plan = super::super::build_plan(&spec).unwrap().shares;

        assert!(grants[0].readonly);
        assert_eq!(plan[0].tag, "terra-share-0");
        assert_eq!(plan[0].guest, "/work");
        assert!(plan[0].readonly);
    }

    /// A guest can replace a nested share with a symlink between boots.
    #[test]
    fn boot_refuses_a_share_redirected_into_box_state() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let share = root.join("data");
        let project_dir = root.join("project");
        let bx = BoxRef::from_state_dir(root.join("state"), &project_dir);
        std::fs::create_dir(&share).unwrap();
        std::fs::create_dir(bx.get_dir()).unwrap();
        let spec = BootSpec {
            cfg: Config {
                mounts: vec![Mount {
                    host: share.clone(),
                    guest: PathBuf::from("/data"),
                    readonly: false,
                }],
                ..Config::default()
            },
            project_dir,
            root: false,
            mode: PlanMode::Run,
            foreground: false,
            host_publishes_pid: false,
            network_broker: None,
        };
        assert!(open_shares(&spec).is_ok());
        std::fs::remove_dir(&share).unwrap();
        crate::sys::symlink_dir(bx.get_dir(), &share).unwrap();
        let error = open_shares(&spec).err().unwrap().to_string();
        assert!(error.contains("opening share"), "{error}");

        crate::sys::remove_directory_symlink(&share).unwrap();
        std::fs::create_dir(&share).unwrap();
        let child = share.join("child");
        std::fs::create_dir(&child).unwrap();
        let mut spec = spec;
        spec.cfg.mounts[0].host = child;
        assert!(open_shares(&spec).is_ok());
        std::fs::remove_dir_all(&share).unwrap();
        std::fs::create_dir(bx.get_dir().join("child")).unwrap();
        crate::sys::symlink_dir(bx.get_dir(), &share).unwrap();
        assert!(open_shares(&spec).is_err());
    }

    #[test]
    fn bake_has_no_host_shares() {
        let spec = BootSpec {
            cfg: Config {
                mounts: vec![Mount {
                    host: PathBuf::from("/not-opened-for-a-bake"),
                    guest: PathBuf::from("/work"),
                    readonly: false,
                }],
                ..Config::default()
            },
            project_dir: PathBuf::from("/project"),
            root: false,
            mode: PlanMode::Create,
            foreground: false,
            host_publishes_pid: false,
            network_broker: None,
        };
        let grants = open_shares(&spec).unwrap();
        let plan = super::super::build_plan(&spec).unwrap().shares;

        assert!(grants.is_empty());
        assert!(plan.is_empty());
    }
}
