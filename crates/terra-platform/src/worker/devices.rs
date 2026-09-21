//! Device grants and resource budgets for a platform worker.

use super::WorkerInput;
use std::path::PathBuf;

pub(crate) fn assemble_devices(
    runtime: &mut terra_runtime::box_runtime::BoxRuntime,
    input: &mut WorkerInput,
    ram: terra_runtime::component::vmm::RamGrant,
    disks: &[(PathBuf, bool)],
    bind_interrupt: impl Fn(
        terra_runtime::component::vmm::DeviceKind,
        usize,
    ) -> Result<terra_runtime::component::InterruptCallback, String>,
) -> Result<(), String> {
    use terra_runtime::component::vmm::DeviceKind;
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
    network(
        runtime,
        ram.clone(),
        input,
        bind_interrupt(DeviceKind::Net, 0)?,
    )?;
    vsock(runtime, ram, input, bind_interrupt(DeviceKind::Vsock, 0)?)?;
    Ok(())
}

pub(crate) fn disk_paths(input: &WorkerInput) -> Vec<(PathBuf, bool)> {
    let mut disks = Vec::with_capacity(1 + input.volume_disks.len());
    disks.push((input.root_disk.clone(), false));
    disks.extend(input.volume_disks.iter().cloned().map(|path| (path, false)));
    disks
}

fn blocks(
    runtime: &mut terra_runtime::box_runtime::BoxRuntime,
    ram: impl Into<terra_runtime::component::vmm::RamGrant> + Send,
    input: &mut WorkerInput,
    disks: &[(PathBuf, bool)],
    interrupt: impl Fn(usize) -> Result<terra_runtime::component::InterruptCallback, String>,
) -> Result<Vec<terra_runtime::component::DeviceChannel>, String> {
    use terra_runtime::component::block::backing::{DiskGrant, FileDisk};
    use terra_runtime::component::block::host::BlockHost;

    let component = input
        .artifacts
        .block()
        .deserialize(runtime.store.engine())
        .map_err(|error| error.to_string())?;
    let disks = disks
        .iter()
        .map(|(path, readonly)| {
            FileDisk::open(path, *readonly)
                .map(|disk| (DiskGrant::File(disk), *readonly))
                .map_err(|error| format!("opening block backing {}: {error}", path.display()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let boot_disk = DiskGrant::Mem(
        terra_runtime::component::block::backing::BoundedDisk::from_readonly_bytes(std::mem::take(
            &mut input.boot_disk,
        )),
    );
    let disks = std::iter::once((boot_disk, true)).chain(disks);
    let ram = ram.into();
    let mut channels = Vec::with_capacity(2 + input.volume_disks.len());
    for (index, (disk, readonly)) in disks.enumerate() {
        let ram = ram.clone();
        let host = move || Ok(BlockHost::new(ram.resolve()?, disk));
        let channel = terra_runtime::component::block::register_device_with_host_factory(
            runtime,
            host,
            &component,
            readonly,
            interrupt(index)?,
        )
        .map_err(|error| error.to_string())?;
        channels.push(channel);
    }
    Ok(channels)
}

fn network(
    runtime: &mut terra_runtime::box_runtime::BoxRuntime,
    ram: impl Into<terra_runtime::component::vmm::RamGrant> + Send,
    input: &WorkerInput,
    interrupt: terra_runtime::component::InterruptCallback,
) -> Result<terra_runtime::component::DeviceChannel, String> {
    use terra_runtime::component::context::DeviceContext;

    let component = input
        .artifacts
        .network()
        .deserialize(runtime.store.engine())
        .map_err(|error| error.to_string())?;
    let ram = ram.into();
    terra_runtime::component::network::register_device_with_host_factory(
        runtime,
        move || Ok(DeviceContext::with_ram(ram.resolve()?)),
        &component,
        input.network_policy.clone(),
        input.port_mappings.clone(),
        terra_network::GuestNetworkConfig::default(),
        interrupt,
    )
    .map_err(|error| error.to_string())
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn filesystems(
    runtime: &mut terra_runtime::box_runtime::BoxRuntime,
    ram: impl Into<terra_runtime::component::vmm::RamGrant> + Send,
    input: &WorkerInput,
    interrupt: impl Fn(usize) -> Result<terra_runtime::component::InterruptCallback, String>,
) -> Result<Vec<terra_runtime::component::DeviceChannel>, String> {
    use terra_runtime::component::context::DeviceContext;

    if input.shares.is_empty() {
        return Ok(Vec::new());
    }
    let component = input
        .artifacts
        .fs()
        .deserialize(runtime.store.engine())
        .map_err(|error| error.to_string())?;
    let ram = ram.into();
    let mut channels = Vec::with_capacity(input.shares.len());
    let resource_capacity = filesystem_resource_capacity(input.shares.len());
    let max_nodes = u32::try_from(resource_capacity.saturating_sub(16) / 2).unwrap_or(u32::MAX);
    if max_nodes == 0 {
        return Err(
            "file descriptor limit is too low for configured shares; raise the host open-file limit or reduce shares"
                .into(),
        );
    }
    let mut grants = input.shares.clone();
    terra_runtime::component::fs::share_notification_budgets(&mut grants);
    for (index, grant) in grants.into_iter().enumerate() {
        let ram = ram.clone();
        let host = move || {
            Ok(
                terra_runtime::component::fs::FsHost::with_resource_capacity(
                    DeviceContext::with_ram(ram.resolve()?),
                    grant,
                    resource_capacity,
                ),
            )
        };
        let channel = terra_runtime::component::fs::register_device_with_host_factory(
            runtime,
            host,
            &component,
            &terra_runtime::component::fs::share_tag(index),
            max_nodes,
            interrupt(index)?,
        )
        .map_err(|error| error.to_string())?;
        channels.push(channel);
    }
    Ok(channels)
}

fn filesystem_resource_capacity(shares: usize) -> usize {
    #[cfg(unix)]
    let limit = rustix::process::getrlimit(rustix::process::Resource::Nofile)
        .current
        .unwrap_or(terra_limits::MAX_VM_OPEN_FILES as u64)
        .min(terra_limits::MAX_VM_OPEN_FILES as u64);
    #[cfg(not(unix))]
    let limit = terra_limits::MAX_VM_OPEN_FILES as u64;
    filesystem_resource_capacity_for(usize::try_from(limit).unwrap_or(usize::MAX), shares)
}

fn filesystem_resource_capacity_for(limit: usize, shares: usize) -> usize {
    const FIXED_HEADROOM: usize = 128;

    limit.saturating_sub(FIXED_HEADROOM) / 4 * 3 / shares
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn memory(
    runtime: &mut terra_runtime::box_runtime::BoxRuntime,
    ram: impl Into<terra_runtime::component::vmm::RamGrant> + Send,
    input: &WorkerInput,
    interrupt: terra_runtime::component::InterruptCallback,
) -> Result<terra_runtime::component::DeviceChannel, String> {
    use terra_runtime::component::context::DeviceContext;

    let component = input
        .artifacts
        .mem()
        .deserialize(runtime.store.engine())
        .map_err(|error| error.to_string())?;
    let ram = ram.into();
    let host = move || Ok(DeviceContext::with_ram(ram.resolve()?));
    terra_runtime::component::mem::register_device_with_host_factory(
        runtime, host, &component, interrupt,
    )
    .map_err(|error| error.to_string())
}

fn vsock(
    runtime: &mut terra_runtime::box_runtime::BoxRuntime,
    ram: impl Into<terra_runtime::component::vmm::RamGrant> + Send,
    input: &mut WorkerInput,
    interrupt: terra_runtime::component::InterruptCallback,
) -> Result<terra_runtime::component::vsock::VsockChannel, String> {
    let listener = input.listener.take();
    let control = input.control.take();
    let diagnostics = input.diagnostics.take();
    terra_runtime::component::vsock::VsockChannel::from_trusted_artifact(
        runtime,
        ram,
        input.artifacts.vsock(),
        std::mem::take(&mut input.plan),
        listener,
        control,
        diagnostics,
        interrupt,
    )
    .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    struct DenyAll;

    impl terra_network::Policy for DenyAll {
        fn allows(&self, _: std::net::IpAddr, _: Option<u16>) -> bool {
            false
        }
    }

    #[test]
    fn filesystem_resources_stay_within_the_vm_file_limit() {
        assert_eq!(super::filesystem_resource_capacity_for(4096, 1), 2976);
        assert_eq!(super::filesystem_resource_capacity_for(4096, 32), 93);
        assert_eq!(super::filesystem_resource_capacity_for(128, 32), 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn empty_shares_do_not_load_the_filesystem_artifact() {
        // SAFETY: every field is trusted AOT output for this Wasmtime build.
        // A block artifact in the filesystem field proves that it is not used.
        #[allow(unsafe_code)]
        let artifacts = unsafe {
            terra_runtime::TrustedArtifacts::new(
                include_bytes!("../../../../build/terra-block-component.cwasm"),
                include_bytes!("../../../../build/terra-vsock-component.cwasm"),
                include_bytes!("../../../../build/terra-network-component.cwasm"),
                include_bytes!("../../../../build/terra-block-component.cwasm"),
                include_bytes!("../../../../build/terra-mem-component.cwasm"),
                include_bytes!("../../../../build/terra-boot-component.cwasm"),
                include_bytes!("../../../../build/terra-vmm-component.cwasm"),
            )
        };
        let input = super::WorkerInput {
            component_memory_limits: terra_runtime::box_runtime::ComponentMemoryLimits::default(),
            kernel: Vec::new(),
            boot_disk: Vec::new(),
            root_disk: std::path::PathBuf::new(),
            volume_disks: Vec::new(),
            shares: Vec::new(),
            plan: Vec::new(),
            artifacts,
            network_policy: std::sync::Arc::new(DenyAll),
            port_mappings: Vec::new(),
            ram_bytes: 4096,
            vcpus: 1,
            deadline: None,
            hard_stop: None,
            listener: None,
            control: None,
            diagnostics: None,
        };
        let engine = terra_runtime::engine::device_engine().unwrap();
        let mut runtime = terra_runtime::box_runtime::BoxRuntime::new(
            &engine,
            terra_runtime::box_runtime::BoxHost::new(),
        )
        .unwrap();
        let shares = super::filesystems(
            &mut runtime,
            terra_runtime::memory::GuestRam::new(4096).unwrap(),
            &input,
            |_| Ok(std::sync::Arc::new(|_| Ok(()))),
        )
        .unwrap();
        assert!(shares.is_empty());
    }
}
