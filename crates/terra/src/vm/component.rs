//! Prepare native capabilities and start the embedded WASI VMM.

use super::boot::BootSpec;
use super::{build_plan, image};
use crate::policy::network::rules;
use crate::policy::network::runtime;
use crate::state::BoxRef;
use crate::{logs, sys};
use anyhow::{Context, Result};
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::process::ExitCode;
use std::sync::Arc;
use terra_platform::io::local::{LocalListener, LocalStream};
use terra_protocol::{
    Disk, MAX_PLAN_BYTES, MAX_PLAN_HOST_STATE_BYTES, PlanMode, Share, encode_frame_with_limit,
    to_volume_device,
};
use terra_runtime::TrustedArtifacts;
use terra_runtime::component::fs::{ShareGrant, share_tag};
use terra_runtime::orchestration::VmInput;

#[allow(unsafe_code)]
const ARTIFACTS: TrustedArtifacts = {
    // SAFETY: Make generates these AOT artifacts from repository components for this target.
    unsafe {
        TrustedArtifacts::new(
            include_bytes!(env!("TERRA_BLOCK_AOT")),
            include_bytes!(env!("TERRA_VSOCK_AOT")),
            include_bytes!(env!("TERRA_NETWORK_AOT")),
            include_bytes!(env!("TERRA_FS_AOT")),
            include_bytes!(env!("TERRA_MEM_AOT")),
            include_bytes!(env!("TERRA_BOOT_AOT")),
            include_bytes!(env!("TERRA_VMM_AOT")),
            include_bytes!(env!("TERRA_MMIO_AOT")),
            include_bytes!(env!("TERRA_INTERRUPT_CONTROLLER_AOT")),
        )
    }
};

fn volume_disks(spec: &BootSpec, bx: &BoxRef) -> Result<(Vec<std::path::PathBuf>, Vec<Disk>)> {
    let mut paths = Vec::with_capacity(spec.cfg.volumes.len());
    let mut plan = Vec::with_capacity(spec.cfg.volumes.len());
    for (index, volume) in spec.cfg.volumes.iter().enumerate() {
        let path = bx.get_volume_image(&volume.name);
        image::ensure_volume_image(&path, volume.size_mib)
            .with_context(|| format!("preparing volume image {}", path.display()))?;
        paths.push(path);
        plan.push(Disk {
            dev: to_volume_device(index)
                .with_context(|| format!("volume {index} is past the last guest block device"))?,
            guest: volume.guest.to_string_lossy().into_owned(),
        });
    }
    Ok((paths, plan))
}

fn shares(spec: &BootSpec) -> Result<(Vec<ShareGrant>, Vec<Share>)> {
    if spec.mode == PlanMode::Create {
        return Ok((Vec::new(), Vec::new()));
    }

    let mounts = &spec.cfg.mounts;
    let mut grants = Vec::with_capacity(mounts.len());
    let mut plan = Vec::with_capacity(mounts.len());
    for (index, mount) in mounts.iter().enumerate() {
        grants.push(
            ShareGrant::new(&mount.host, mount.readonly).with_context(|| {
                format!(
                    "opening share {}",
                    crate::render::escape_printable_path(&mount.host)
                )
            })?,
        );
        plan.push(Share {
            tag: share_tag(index),
            guest: mount.guest.to_string_lossy().into_owned(),
            readonly: mount.readonly,
        });
    }
    Ok((grants, plan))
}

fn agent_listener(bx: &BoxRef) -> Result<LocalListener> {
    let path = bx.get_dir().join(crate::state::AGENT_SOCKET);
    let _ = std::fs::remove_file(&path);
    image::sweep_staging_temps(bx.get_dir(), |_| false);
    let listener = LocalListener::bind(&path)
        .with_context(|| format!("binding the agent socket {}", path.display()))?;
    sys::set_owner_only(&path, false).with_context(|| format!("securing {}", path.display()))?;
    Ok(listener)
}

fn stop_listener(bx: &BoxRef) -> Result<LocalListener> {
    let path = bx.get_dir().join(crate::state::CONTROL_SOCKET);
    let _ = std::fs::remove_file(&path);
    let listener = LocalListener::bind(&path)
        .with_context(|| format!("binding the stop socket {}", path.display()))?;
    sys::set_owner_only(&path, false).with_context(|| format!("securing {}", path.display()))?;
    Ok(listener)
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
pub async fn run(spec: &BootSpec, bx: &BoxRef, lock: &File) -> Result<ExitCode> {
    logs::init(bx)?;
    let component_memory_limits = spec.cfg.components.memory_limits()?;
    let _resources = super::resources::admit(
        u64::from(spec.cfg.hw.mem_mib) << 20,
        component_memory_limits.total_bytes(),
    )?;
    if spec.mode == PlanMode::Run {
        sys::install_stop_signal_handlers();
    }

    let kernel = image::load_kernel()?;
    let boot_disk = image::load_boot_image()?;
    let root_disk = bx.get_dir().join(crate::state::ROOTFS_FILE);
    let (volume_disks, volumes) = volume_disks(spec, bx)?;
    let (shares, plan_shares) = shares(spec)?;
    let plan = build_plan(spec, plan_shares, volumes);
    let plan = encode_frame_with_limit(&plan, MAX_PLAN_BYTES - MAX_PLAN_HOST_STATE_BYTES)
        .context("serializing the boot plan")?;
    let listener = Some(agent_listener(bx)?);
    let port_mappings = if spec.mode == PlanMode::Run {
        rules::parse_port_mappings(&spec.cfg.network.ports)?
    } else {
        Vec::new()
    };
    let (component_memory_limits, policy_memory_bytes) =
        component_memory_limits
            .reserve_policy()
            .map_err(|error| anyhow::anyhow!("{error:#}"))?;
    let policy = Arc::new(runtime::BoxPolicy::with_memory_limit(
        &spec.cfg.network,
        policy_memory_bytes,
    )?);

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
    image::staged_write(&diagnostics_path, |_| Ok(()))?;
    let diagnostics = Some(sys::create_regular_file(&diagnostics_path)?);
    let control = if spec.mode == PlanMode::Run {
        let (host, worker) = LocalStream::pair().context("creating the VM stop channel")?;
        #[cfg(unix)]
        sys::register_stop_channel(host.try_clone()?.into());
        relay_stop(stop_listener(bx)?, host);
        Some(worker)
    } else {
        None
    };

    bx.publish_pid(lock, std::process::id(), spec.mode == PlanMode::Create);
    let prepared = terra_runtime::orchestration::prepare(VmInput {
        component_memory_limits,
        kernel,
        boot_disk,
        root_disk,
        volume_disks,
        shares,
        plan,
        artifacts: ARTIFACTS,
        network_policy: policy,
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
            prepared
                .run(|| {
                    let mut startup = std::io::stdout().lock();
                    let _ = startup
                        .write_all(&[terra_protocol::AGENT_READY_NOTIFICATION])
                        .and_then(|()| startup.flush());
                })
                .await
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Mount};
    use std::path::PathBuf;

    #[test]
    fn stop_socket_relays_the_request_to_the_vm_control_channel() {
        let dir = tempfile::tempdir().unwrap();
        let bx = BoxRef::from_state_dir(dir.path().join("state"), dir.path());
        std::fs::create_dir(bx.get_dir()).unwrap();
        let listener = stop_listener(&bx).unwrap();
        let (host, mut worker) = LocalStream::pair().unwrap();
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
        };
        let (grants, plan) = shares(&spec).unwrap();

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
        };
        assert!(shares(&spec).is_ok());
        std::fs::remove_dir(&share).unwrap();
        crate::sys::symlink_dir(bx.get_dir(), &share).unwrap();
        let error = shares(&spec).err().unwrap().to_string();
        assert!(error.contains("opening share"), "{error}");

        crate::sys::remove_directory_symlink(&share).unwrap();
        std::fs::create_dir(&share).unwrap();
        let child = share.join("child");
        std::fs::create_dir(&child).unwrap();
        let mut spec = spec;
        spec.cfg.mounts[0].host = child;
        assert!(shares(&spec).is_ok());
        std::fs::remove_dir_all(&share).unwrap();
        std::fs::create_dir(bx.get_dir().join("child")).unwrap();
        crate::sys::symlink_dir(bx.get_dir(), &share).unwrap();
        assert!(shares(&spec).is_err());
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
        };
        let (grants, plan) = shares(&spec).unwrap();

        assert!(grants.is_empty());
        assert!(plan.is_empty());
    }
}
