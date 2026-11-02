//! Guest vsock sockets bound to terra's fixed host endpoints.

use anyhow::{Context as _, Result};
use std::os::fd::OwnedFd;

#[allow(unsafe_code)]
pub(crate) fn vsock_address(cid: u32, port: u32) -> rustix::net::SocketAddrAny {
    #[repr(C)]
    struct VsockAddress {
        family: u16,
        reserved: u16,
        port: u32,
        cid: u32,
        flags: u8,
        padding: [u8; 3],
    }

    const _: () = assert!(std::mem::size_of::<VsockAddress>() == 16);

    let address = VsockAddress {
        family: rustix::net::AddressFamily::VSOCK.as_raw(),
        reserved: 0,
        port,
        cid,
        flags: 0,
        padding: [0; 3],
    };
    // SAFETY: the initialized C layout is Linux sockaddr_vm; read copies exactly its 16 bytes.
    unsafe { rustix::net::SocketAddrAny::read(std::ptr::from_ref(&address).cast(), 16) }
}

pub(crate) fn create_vsock_socket() -> std::io::Result<OwnedFd> {
    Ok(rustix::net::socket_with(
        rustix::net::AddressFamily::VSOCK,
        rustix::net::SocketType::STREAM,
        rustix::net::SocketFlags::CLOEXEC,
        None,
    )?)
}

/// Binds the guest side of `port`, then connects to the host side. `prepare` runs before either.
pub(crate) fn connect_vsock(
    port: u32,
    endpoint: &str,
    prepare: impl FnOnce(&OwnedFd) -> std::io::Result<()>,
) -> Result<OwnedFd> {
    let socket = create_vsock_socket().with_context(|| format!("creating the {endpoint} vsock"))?;
    prepare(&socket).with_context(|| format!("configuring the {endpoint} vsock"))?;
    rustix::net::bind(
        &socket,
        &vsock_address(terra_protocol::vsock::GUEST_CID, port),
    )
    .with_context(|| format!("binding the fixed guest {endpoint} endpoint"))?;
    rustix::net::connect(
        &socket,
        &vsock_address(terra_protocol::vsock::HOST_CID, port),
    )
    .with_context(|| format!("connecting the fixed host {endpoint} endpoint"))?;
    Ok(socket)
}
