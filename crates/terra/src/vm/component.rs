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
use terra_platform::code_memory::PageAligned;
use terra_platform::local_socket::{LocalListener, LocalStream, create_local_pair};
use terra_protocol::PlanMode;
use terra_runtime::component::AccessMode;
use terra_runtime::component::fs::ShareGrant;
use terra_runtime::orchestration::VmInput;
use terra_runtime::{TrustedArtifact, TrustedArtifacts};

macro_rules! embedded_artifact {
    ($variable:literal) => {{
        static BYTES: &PageAligned<[u8]> = &PageAligned(*include_bytes!(env!($variable)));
        TrustedArtifact::from_trusted_page_aligned(BYTES)
    }};
}

#[allow(unsafe_code)]
const ARTIFACTS: TrustedArtifacts = {
    // SAFETY: Make generates these AOT artifacts from repository components for this target.
    unsafe {
        TrustedArtifacts {
            block: embedded_artifact!("TERRA_BLOCK_AOT"),
            agent: embedded_artifact!("TERRA_AGENT_AOT"),
            vsock_frontend: embedded_artifact!("TERRA_VSOCK_FRONTEND_AOT"),
            fs: embedded_artifact!("TERRA_FS_AOT"),
            mem: embedded_artifact!("TERRA_MEM_AOT"),
            boot: embedded_artifact!("TERRA_BOOT_AOT"),
            vmm: embedded_artifact!("TERRA_VMM_AOT"),
            interrupt_controller: embedded_artifact!("TERRA_INTERRUPT_CONTROLLER_AOT"),
        }
    }
};

fn volume_disk_paths(spec: &BootSpec, bx: &BoxRef) -> Vec<std::path::PathBuf> {
    if spec.mode == PlanMode::Create {
        return Vec::new();
    }
    spec.cfg
        .volumes
        .iter()
        .map(|volume| bx.get_volume_image_path(&volume.name))
        .collect()
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
    for (index, mount) in mounts.iter().enumerate() {
        #[cfg(not(windows))]
        let _ = index;
        let access = if mount.readonly {
            AccessMode::ReadOnly
        } else {
            AccessMode::ReadWrite
        };
        #[cfg(windows)]
        let grant = if uses_inherited_listeners() {
            let identity = std::env::var(format!("TERRA_WINDOWS_MOUNT_ID_{index}"))?.parse()?;
            ShareGrant::new_host_granted(&mount.host, access, identity)
        } else {
            ShareGrant::new(&mount.host, access)
        };
        #[cfg(not(windows))]
        let grant = ShareGrant::new(&mount.host, access);
        grants.push(grant.with_context(|| {
            format!(
                "opening share {}",
                crate::render::escape_printable_path(&mount.host)
            )
        })?);
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
    terra_platform::process::sandbox_env::is_vm_worker()
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
    let rootfs_disk = bx.get_dir().join(crate::state::ROOTFS_FILE);
    let plan = encode_boot_plan(spec, bx.get_name())?;
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
            "setting up"
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
            spec.mode,
        )
        .context("publishing the VM process identity")?;
    }
    let prepared = terra_runtime::orchestration::prepare(VmInput {
        component_memory_limits,
        kernel,
        boot_disk,
        rootfs_disk,
        rootfs_access: super::rootfs_access(spec),
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
        client: terra_network::Client::new(
            terra_platform::local_socket::AsyncLocalStream::from_std(endpoint)?,
        ),
        ready: metadata.ready.clone(),
        listeners: metadata.listeners.clone(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Mount};
    use std::path::{Path, PathBuf};

    #[test]
    fn setup_attaches_no_volume_disks() {
        let bx = BoxRef::from_state_dir(PathBuf::from("/box"), Path::new("/project"));
        let mut spec = BootSpec {
            cfg: Config {
                volumes: vec![crate::config::Volume {
                    name: "scratch".into(),
                    guest: Some("/scratch".into()),
                    rootfs_overlay: false,
                    size_mib: 8,
                    lifetime: crate::config::VolumeLifetime::Boot,
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
        assert_eq!(volume_disk_paths(&spec, &bx), [] as [PathBuf; 0]);
        spec.mode = PlanMode::Run;
        assert_eq!(
            volume_disk_paths(&spec, &bx),
            [bx.get_volume_image_path("scratch")]
        );
    }

    fn embedded_artifacts() -> [TrustedArtifact; 8] {
        let TrustedArtifacts {
            block,
            agent,
            vsock_frontend,
            fs,
            mem,
            boot,
            vmm,
            interrupt_controller,
        } = ARTIFACTS;
        [
            block,
            agent,
            vsock_frontend,
            fs,
            mem,
            boot,
            vmm,
            interrupt_controller,
        ]
    }

    /// The first engine to load an artifact in place owns it; every test loads
    /// through this one so test order cannot change the owner.
    static SHARED_ENGINE: std::sync::LazyLock<wasmtime::Engine> =
        std::sync::LazyLock::new(|| terra_runtime::engine::device_engine().unwrap());

    /// Every embedded artifact runs from the executable's own file pages
    /// rather than a private copy, loaded once per process.
    #[test]
    fn embedded_artifacts_deserialize_in_place() {
        for artifact in embedded_artifacts() {
            let first = artifact.deserialize_in_place(&SHARED_ENGINE).unwrap();
            let second = artifact.deserialize_in_place(&SHARED_ENGINE).unwrap();
            assert_eq!(first.image_range(), second.image_range());
            #[cfg(target_os = "linux")]
            assert!(is_executable_file_mapping(first.image_range()));
        }
    }

    #[cfg(target_os = "linux")]
    fn is_executable_file_mapping(image: std::ops::Range<*const u8>) -> bool {
        let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
        maps.lines().any(|line| {
            let fields: Vec<&str> = line.split_ascii_whitespace().collect();
            let (start, end) = fields[0].split_once('-').unwrap();
            let start = usize::from_str_radix(start, 16).unwrap();
            let end = usize::from_str_radix(end, 16).unwrap();
            start < image.end.addr()
                && image.start.addr() < end
                && fields[1].contains('x')
                && fields[4] != "0"
        })
    }

    /// A second engine would register the in-place unwind tables twice, which
    /// aborts the process in libgcc, so it gets a private copy instead.
    #[test]
    fn another_engine_falls_back_to_a_private_copy() {
        let shared = ARTIFACTS.boot.deserialize_in_place(&SHARED_ENGINE).unwrap();
        let other = terra_runtime::engine::device_engine().unwrap();
        assert!(ARTIFACTS.boot.deserialize_in_place(&other).is_err());
        let copied = ARTIFACTS.boot.deserialize(&other).unwrap();
        assert_ne!(copied.image_range(), shared.image_range());
    }

    /// Bytes that may share their pages with other data never run in place and
    /// still load through a private copy.
    #[test]
    #[allow(unsafe_code)]
    fn bytes_without_pages_of_their_own_fall_back_to_a_private_copy() {
        let heap = Box::leak(
            include_bytes!(env!("TERRA_BOOT_AOT"))
                .to_vec()
                .into_boxed_slice(),
        );
        // SAFETY: the heap bytes are a copy of a trusted embedded artifact.
        let artifact = unsafe { TrustedArtifact::from_trusted_bytes(heap) };
        assert!(artifact.deserialize_in_place(&SHARED_ENGINE).is_err());
        artifact.deserialize(&SHARED_ENGINE).unwrap();
    }

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
                host_service_ports: Vec::new(),
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
        let plan = super::super::build_plan(&spec, "dev").unwrap().shares;

        assert_eq!(grants[0].access, AccessMode::ReadOnly);
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
    fn setup_boot_has_no_host_shares() {
        let spec = BootSpec {
            cfg: Config {
                mounts: vec![Mount {
                    host: PathBuf::from("/not-opened-for-a-setup-boot"),
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
        assert!(open_shares(&spec).unwrap().is_empty());
    }
}
