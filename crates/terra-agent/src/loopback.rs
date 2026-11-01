//! The guest loopback interface: bringing it up and the alias addresses the network services use.

use anyhow::{Context, Result, ensure};
use rustix::fd::OwnedFd;
use std::net::Ipv4Addr;
use std::process::Command;
use tokio_util::sync::CancellationToken;

/// A Linux `struct ifreq`: an interface name and the request's 24-byte union.
#[repr(C)]
struct InterfaceRequest {
    name: [u8; 16],
    data: [u8; 24],
}

impl InterfaceRequest {
    fn named(name: &str) -> Result<Self> {
        let mut request = Self {
            name: [0; 16],
            data: [0; 24],
        };
        // The kernel reads a NUL-terminated name.
        ensure!(
            name.len() < request.name.len(),
            "interface name {name} is too long"
        );
        request.name[..name.len()].copy_from_slice(name.as_bytes());
        Ok(request)
    }
}

fn interface_socket() -> Result<OwnedFd> {
    rustix::net::socket_with(
        rustix::net::AddressFamily::INET,
        rustix::net::SocketType::DGRAM,
        rustix::net::SocketFlags::CLOEXEC,
        None,
    )
    .context("opening the guest interface control socket")
}

#[allow(unsafe_code)]
fn interface_ioctl<const OPCODE: rustix::ioctl::Opcode>(
    socket: &OwnedFd,
    request: &mut InterfaceRequest,
) -> rustix::io::Result<()> {
    // SAFETY: callers pass `SIOC[GS]IF*` opcodes, which read the terminated name and the union
    // at offset 16 of a Linux ifreq and write back at most that union.
    unsafe { rustix::ioctl::ioctl(socket, rustix::ioctl::Updater::<OPCODE, _>::new(request)) }
}

pub(crate) fn enable() -> Result<()> {
    let socket = interface_socket()?;
    let mut request = InterfaceRequest::named("lo")?;
    interface_ioctl::<{ linux_raw_sys::ioctl::SIOCGIFFLAGS }>(&socket, &mut request)
        .context("reading guest loopback flags")?;
    let flags = i16::from_ne_bytes([request.data[0], request.data[1]])
        | i16::try_from(linux_raw_sys::net::net_device_flags::IFF_UP as u32)
            .context("encoding the guest loopback flag")?;
    request.data[..2].copy_from_slice(&flags.to_ne_bytes());
    interface_ioctl::<{ linux_raw_sys::ioctl::SIOCSIFFLAGS }>(&socket, &mut request)
        .context("enabling guest loopback")
}

pub(crate) fn add_alias_address(name: &str, address: Ipv4Addr) -> Result<()> {
    let socket = interface_socket()?;
    let mut request = InterfaceRequest::named(name)?;
    request.data[..16].copy_from_slice(&encode_interface_address(address));
    interface_ioctl::<{ linux_raw_sys::ioctl::SIOCSIFADDR }>(&socket, &mut request)
        .with_context(|| format!("assigning the guest loopback address {address}"))?;
    request.data[..16].copy_from_slice(&encode_interface_address(Ipv4Addr::BROADCAST));
    interface_ioctl::<{ linux_raw_sys::ioctl::SIOCSIFNETMASK }>(&socket, &mut request)
        .with_context(|| format!("setting the guest loopback address {address} prefix"))
}

fn encode_interface_address(address: Ipv4Addr) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[..2].copy_from_slice(&rustix::net::AddressFamily::INET.as_raw().to_ne_bytes());
    bytes[4..8].copy_from_slice(&address.octets());
    bytes
}

pub(crate) async fn configure_publication_addresses(
    cancellation: &CancellationToken,
) -> Result<()> {
    for (name, address) in [
        ("lo:terra-src", crate::network::RELAY_SOURCE),
        ("lo:terra-dst", crate::network::PUBLISHED_DESTINATION),
    ] {
        add_alias_address(name, address)?;
    }
    let relay_route = format!("{}/32", crate::network::RELAY_SOURCE);
    let service_source = crate::network::PUBLISHED_DESTINATION.to_string();
    let mut command = Command::new("ip");
    command.args([
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
    ]);
    let timeout = std::time::Duration::from_secs(terra_protocol::application::OPEN_TIMEOUT_SECS);
    let status = crate::reap::run_or_kill(&mut command, timeout, cancellation)
        .await
        .context("configuring the guest publication reply source")?;
    ensure!(
        status.success(),
        "guest publication reply route exited {status}"
    );
    Ok(())
}
