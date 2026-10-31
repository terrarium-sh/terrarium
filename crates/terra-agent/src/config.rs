use super::bootstrap::mount;
use super::hooks::wait_for_child;
use anyhow::{Context, Result, ensure};
use rustix::mount::MountFlags;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt as _;
use std::path::Path;
use std::process::Command;
use tokio_util::sync::CancellationToken;

#[repr(C)]
#[derive(Clone, Copy)]
struct InterfaceRequest {
    name: [u8; 16],
    data: [u8; 24],
}

#[allow(unsafe_code)]
pub(super) fn enable_loopback() -> Result<()> {
    let socket = rustix::net::socket_with(
        rustix::net::AddressFamily::INET,
        rustix::net::SocketType::DGRAM,
        rustix::net::SocketFlags::CLOEXEC,
        None,
    )
    .context("opening the guest interface control socket")?;
    let mut interface = InterfaceRequest {
        name: [0; 16],
        data: [0; 24],
    };
    interface.name[..2].copy_from_slice(b"lo");
    // SAFETY: SIOCGIFFLAGS reads the terminated name and writes the flags at offset 16 in Linux ifreq.
    unsafe {
        let request = rustix::ioctl::Updater::<{ linux_raw_sys::ioctl::SIOCGIFFLAGS }, _>::new(
            &mut interface,
        );
        rustix::ioctl::ioctl(&socket, request)
    }
    .context("reading guest loopback flags")?;
    let flags = i16::from_ne_bytes([interface.data[0], interface.data[1]])
        | i16::try_from(linux_raw_sys::net::net_device_flags::IFF_UP as u32)
            .context("encoding the guest loopback flag")?;
    interface.data[..2].copy_from_slice(&flags.to_ne_bytes());
    // SAFETY: SIOCSIFFLAGS reads the same initialized Linux ifreq name and updated flags.
    unsafe {
        let request =
            rustix::ioctl::Setter::<{ linux_raw_sys::ioctl::SIOCSIFFLAGS }, _>::new(interface);
        rustix::ioctl::ioctl(&socket, request)
    }
    .context("enabling guest loopback")?;
    Ok(())
}

#[allow(unsafe_code)]
pub(super) fn configure_loopback_address(name: &str, address: std::net::Ipv4Addr) -> Result<()> {
    let socket = rustix::net::socket_with(
        rustix::net::AddressFamily::INET,
        rustix::net::SocketType::DGRAM,
        rustix::net::SocketFlags::CLOEXEC,
        None,
    )?;
    let mut interface = InterfaceRequest {
        name: [0; 16],
        data: [0; 24],
    };
    interface.name[..name.len()].copy_from_slice(name.as_bytes());
    interface.data[..16].copy_from_slice(&encode_interface_address(address));
    // SAFETY: SIOCSIFADDR reads a terminated alias name and an initialized IPv4 sockaddr at offset 16.
    unsafe {
        let request =
            rustix::ioctl::Setter::<{ linux_raw_sys::ioctl::SIOCSIFADDR }, _>::new(interface);
        rustix::ioctl::ioctl(&socket, request)
    }
    .with_context(|| format!("assigning the guest loopback address {address}"))?;
    interface.data[..16].copy_from_slice(&encode_interface_address(std::net::Ipv4Addr::BROADCAST));
    // SAFETY: SIOCSIFNETMASK reads the same alias name and an initialized IPv4 sockaddr netmask.
    unsafe {
        let request =
            rustix::ioctl::Setter::<{ linux_raw_sys::ioctl::SIOCSIFNETMASK }, _>::new(interface);
        rustix::ioctl::ioctl(&socket, request)
    }
    .with_context(|| format!("setting the guest loopback address {address} prefix"))?;
    Ok(())
}

pub(super) async fn configure_publication_addresses(
    cancellation: &CancellationToken,
) -> Result<()> {
    for (name, address) in [
        ("lo:terra-src", crate::network::RELAY_SOURCE),
        ("lo:terra-dst", crate::network::PUBLISHED_DESTINATION),
    ] {
        configure_loopback_address(name, address)?;
    }
    let relay_route = format!("{}/32", crate::network::RELAY_SOURCE);
    let service_source = crate::network::PUBLISHED_DESTINATION.to_string();
    let mut command = Command::new("ip");
    command
        .args([
            "route",
            "replace",
            "local",
            &relay_route,
            "dev",
            "lo",
            "src",
            &service_source,
            "table",
            "local",
        ])
        .process_group(0);
    let (_, pidfd) = crate::reap::spawn_owned(|| command.spawn())
        .context("configuring the guest publication reply source")?;
    let timeout = std::time::Duration::from_secs(terra_protocol::application::OPEN_TIMEOUT_SECS);
    let status = wait_for_child(&pidfd, timeout, cancellation)
        .await
        .context("configuring the guest publication reply source")?;
    ensure!(
        status.success(),
        "guest publication reply route exited {status}"
    );
    Ok(())
}

fn encode_interface_address(address: std::net::Ipv4Addr) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[..2].copy_from_slice(&rustix::net::AddressFamily::INET.as_raw().to_ne_bytes());
    bytes[4..8].copy_from_slice(&address.octets());
    bytes
}

pub(super) const VOLUME_MOUNT_FLAGS: MountFlags = MountFlags::NOSUID.union(MountFlags::NODEV);

pub(super) fn mount_filesystems(plan: &terra_protocol::Plan) -> Result<()> {
    for share in &plan.shares {
        mount_share(share)?;
    }
    mount_volumes(plan)
}

pub(super) fn mount_volumes(plan: &terra_protocol::Plan) -> Result<()> {
    for volume in &plan.volumes {
        // Setup made the mount points in the root image; this creates the ones nested
        // inside an already-mounted share (`/work/node_modules` under `/work`).
        prepare_mount_point(&volume.guest)?;
        mount(
            Some(&volume.dev),
            &volume.guest,
            Some("ext4"),
            VOLUME_MOUNT_FLAGS,
        )
        .with_context(|| format!("mounting volume at {}", volume.guest))?;
        let (uid, gid) = crate::workload::workload_owner();
        if !plan.root
            && let Err(error) = rustix::fs::chown(&volume.guest, uid, gid)
        {
            eprintln!(
                "terra-agent: warning: could not chown {}: {error}",
                volume.guest
            );
        }
    }
    Ok(())
}

fn mount_share(share: &terra_protocol::Share) -> Result<()> {
    prepare_mount_point(&share.guest)?;
    let flags = if share.readonly {
        MountFlags::RDONLY
    } else {
        MountFlags::empty()
    };
    mount(
        Some(&share.tag),
        &share.guest,
        Some("virtiofs"),
        flags | MountFlags::NOSUID | MountFlags::NODEV,
    )
    .with_context(|| format!("mounting share at {}", share.guest))
}

pub(super) fn prepare_mount_points(plan: &terra_protocol::Plan) -> Result<()> {
    for path in plan
        .shares
        .iter()
        .map(|share| &share.guest)
        .chain(plan.volumes.iter().map(|volume| &volume.guest))
    {
        prepare_mount_point(path)?;
    }
    Ok(())
}

fn prepare_mount_point(path: &str) -> Result<()> {
    crate::sync::ensure_directory(Path::new(path), crate::sync::Owner::Root)
        .with_context(|| format!("creating mount point {path}"))
}

pub(super) fn prepare_runtime_dir() -> Result<()> {
    let runtime_dir = format!("/run/user/{}", terra_protocol::WORKLOAD_ID);
    fs::create_dir_all(&runtime_dir).with_context(|| format!("creating {runtime_dir}"))?;
    fs::set_permissions(&runtime_dir, fs::Permissions::from_mode(0o700))?;
    let (uid, gid) = crate::workload::workload_owner();
    rustix::fs::chown(&runtime_dir, uid, gid)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    #[test]
    fn a_symlinked_mount_point_is_supported() {
        let real = crate::create_scratch_path("init", "mp-real");
        let link = crate::create_scratch_path("init", "mp-link");
        let fresh = crate::create_scratch_path("init", "mp-fresh");
        let _ = fs::remove_dir_all(&real);
        let _ = fs::remove_file(&link);
        let _ = fs::remove_dir_all(&fresh);
        fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();

        prepare_mount_point(&link.to_string_lossy()).unwrap();
        prepare_mount_point(&link.join("src").to_string_lossy()).unwrap();
        assert!(real.join("src").is_dir());
        assert!(prepare_mount_point(&real.to_string_lossy()).is_ok());
        assert!(prepare_mount_point(&fresh.join("a/b").to_string_lossy()).is_ok());
        assert!(fresh.join("a/b").is_dir());

        let _ = fs::remove_file(&link);
        let _ = fs::remove_dir_all(&real);
        let _ = fs::remove_dir_all(&fresh);
    }
}
