use super::VmInput;
use crate::component::AccessMode;
use crate::machine::DeviceKind;
use std::path::PathBuf;

pub(crate) fn assemble_devices(
    runtime: &mut crate::box_runtime::BoxRuntime,
    input: &mut VmInput,
    ram: crate::component::vmm::RamGrant,
    disks: &[PathBuf],
    bind_interrupt: impl Fn(DeviceKind, usize) -> Result<crate::component::InterruptCallback, String>,
) -> Result<(), String> {
    blocks(runtime, ram.clone(), input, disks, |index| {
        bind_interrupt(DeviceKind::Block, index)
    })?;
    filesystems(runtime, ram.clone(), input, |index| {
        bind_interrupt(DeviceKind::Fs, index)
    })?;
    memory(
        runtime,
        ram.clone(),
        input,
        bind_interrupt(DeviceKind::Memory, 0)?,
    )?;
    let (streams, agent_endpoint) = crate::component::vsock::streams::FrontendStreams::new();
    agent(runtime, input, agent_endpoint)?;
    crate::component::vsock::register_device(
        runtime,
        ram,
        input.artifacts.vsock_frontend,
        streams,
        input.network_backend.take(),
        input.port_mappings.clone(),
        bind_interrupt(DeviceKind::Vsock, 0)?,
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

pub(crate) fn disk_paths(input: &VmInput) -> Vec<PathBuf> {
    std::iter::once(&input.root_disk)
        .chain(&input.volume_disks)
        .cloned()
        .collect()
}

fn blocks(
    runtime: &mut crate::box_runtime::BoxRuntime,
    ram: impl Into<crate::component::vmm::RamGrant> + Send,
    input: &mut VmInput,
    disks: &[PathBuf],
    interrupt: impl Fn(usize) -> Result<crate::component::InterruptCallback, String>,
) -> Result<(), String> {
    use crate::component::block::BlockHost;
    use crate::component::block::backing::{DiskGrant, FileDisk};
    let component = input
        .artifacts
        .block
        .deserialize(runtime.store.engine())
        .map_err(|error| error.to_string())?;
    let disks = disks
        .iter()
        .map(|path| {
            FileDisk::open(path, AccessMode::ReadWrite)
                .map(DiskGrant::File)
                .map_err(|error| format!("opening block backing {}: {error}", path.display()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let boot_disk = DiskGrant::Mem(
        crate::component::block::backing::BoundedDisk::from_readonly_bytes(std::mem::take(
            &mut input.boot_disk,
        )),
    );
    let ram = ram.into();
    for (index, disk) in std::iter::once(boot_disk).chain(disks).enumerate() {
        let ram = ram.clone();
        crate::component::block::register_device_with_host_factory(
            runtime,
            move || Ok(BlockHost::new(ram.resolve()?, disk)),
            &component,
            interrupt(index)?,
        )
        .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn filesystems(
    runtime: &mut crate::box_runtime::BoxRuntime,
    ram: impl Into<crate::component::vmm::RamGrant> + Send,
    input: &VmInput,
    interrupt: impl Fn(usize) -> Result<crate::component::InterruptCallback, String>,
) -> Result<(), String> {
    use crate::component::context::DeviceContext;
    if input.shares.is_empty() {
        return Ok(());
    }
    let component = input
        .artifacts
        .fs
        .deserialize(runtime.store.engine())
        .map_err(|error| error.to_string())?;
    let resource_capacity = filesystem_resource_capacity(input.shares.len());
    let max_nodes = u32::try_from(resource_capacity.saturating_sub(16) / 2).unwrap_or(u32::MAX);
    if max_nodes == 0 {
        return Err("file descriptor limit is too low for configured shares; raise the host open-file limit or reduce shares".into());
    }
    let mut grants = input.shares.clone();
    crate::component::fs::share_notification_budgets(&mut grants);
    let ram = ram.into();
    for (index, grant) in grants.into_iter().enumerate() {
        let ram = ram.clone();
        crate::component::fs::register_device_with_host_factory(
            runtime,
            move || {
                Ok(crate::component::fs::FsHost::with_resource_capacity(
                    DeviceContext::with_ram(ram.resolve()?),
                    grant,
                    resource_capacity,
                ))
            },
            &component,
            &crate::component::fs::share_tag(index),
            max_nodes,
            interrupt(index)?,
        )
        .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn filesystem_resource_capacity(shares: usize) -> usize {
    let limit = terra_platform::filesystem::open_file_limit()
        .unwrap_or(terra_limits::MAX_VM_OPEN_FILES as u64)
        .min(terra_limits::MAX_VM_OPEN_FILES as u64);
    filesystem_resource_capacity_for(usize::try_from(limit).unwrap_or(usize::MAX), shares)
}

fn filesystem_resource_capacity_for(limit: usize, shares: usize) -> usize {
    limit.saturating_sub(128) / 4 * 3 / shares
}

fn memory(
    runtime: &mut crate::box_runtime::BoxRuntime,
    ram: impl Into<crate::component::vmm::RamGrant> + Send,
    input: &VmInput,
    interrupt: crate::component::InterruptCallback,
) -> Result<(), String> {
    use crate::component::context::DeviceContext;
    let component = input
        .artifacts
        .mem
        .deserialize(runtime.store.engine())
        .map_err(|error| error.to_string())?;
    let ram = ram.into();
    crate::component::mem::register_device_with_host_factory(
        runtime,
        move || Ok(DeviceContext::with_ram(ram.resolve()?)),
        &component,
        interrupt,
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

fn agent(
    runtime: &mut crate::box_runtime::BoxRuntime,
    input: &mut VmInput,
    endpoint: crate::component::vsock::streams::StreamEndpoint,
) -> Result<(), String> {
    crate::component::agent::Agent::from_trusted_artifact(
        runtime,
        endpoint,
        input.artifacts.agent,
        std::mem::take(&mut input.plan),
        input.listener.take(),
        input.control.take(),
        input.diagnostics.take(),
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    #[test]
    fn filesystem_resources_stay_within_the_vm_file_limit() {
        assert_eq!(super::filesystem_resource_capacity_for(4096, 1), 2976);
        assert_eq!(super::filesystem_resource_capacity_for(4096, 32), 93);
        assert_eq!(super::filesystem_resource_capacity_for(128, 32), 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn empty_shares_do_not_load_the_filesystem_artifact() {
        let fixtures = crate::test_fixtures::trusted_artifacts();
        let artifacts = crate::TrustedArtifacts {
            fs: fixtures.block,
            ..fixtures
        };
        let input = super::VmInput {
            component_memory_limits: crate::box_runtime::ComponentMemoryLimits::default(),
            kernel: Vec::new(),
            boot_disk: Vec::new(),
            root_disk: PathBuf::new(),
            volume_disks: Vec::new(),
            shares: Vec::new(),
            plan: Vec::new(),
            artifacts,
            network_backend: None,
            port_mappings: Vec::new(),
            ram_bytes: 4096,
            vcpus: 1,
            deadline: None,
            hard_stop: None,
            listener: None,
            control: None,
            diagnostics: None,
        };
        let engine = crate::engine::device_engine().unwrap();
        let mut runtime =
            crate::box_runtime::BoxRuntime::new(&engine, crate::box_runtime::BoxHost::new())
                .unwrap();
        super::filesystems(
            &mut runtime,
            crate::memory::GuestRam::new(4096).unwrap(),
            &input,
            |_| Ok(std::sync::Arc::new(|_| Ok(()))),
        )
        .unwrap();
    }
}
