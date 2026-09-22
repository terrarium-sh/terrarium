use wasmtime::component::Resource;
use wasmtime_wasi::p3::bindings::sockets::types::{HostTcpSocket, HostUdpSocket, IpAddressFamily};
use wasmtime_wasi::sockets::{TcpSocket, UdpSocket, WasiSocketsCtxView};

const MAX_SOCKET_BUFFER_BYTES: u64 = 256 << 10;
const MAX_LISTEN_BACKLOG: u64 = 64;
pub(super) fn create_tcp(
    mut view: WasiSocketsCtxView<'_>,
    family: IpAddressFamily,
) -> wasmtime_wasi::p3::sockets::SocketResult<Resource<TcpSocket>> {
    let socket = HostTcpSocket::create(&mut view, family)?;
    let configured = (|| {
        HostTcpSocket::set_send_buffer_size(
            &mut view,
            Resource::new_borrow(socket.rep()),
            MAX_SOCKET_BUFFER_BYTES,
        )?;
        HostTcpSocket::set_receive_buffer_size(
            &mut view,
            Resource::new_borrow(socket.rep()),
            MAX_SOCKET_BUFFER_BYTES,
        )?;
        view.set_listen_backlog_size(Resource::new_borrow(socket.rep()), MAX_LISTEN_BACKLOG)
    })();
    if let Err(error) = configured {
        HostTcpSocket::drop(&mut view, socket)
            .map_err(wasmtime_wasi::p3::sockets::SocketError::trap)?;
        return Err(error);
    }
    Ok(socket)
}

pub(super) async fn create_udp(
    mut view: WasiSocketsCtxView<'_>,
    family: IpAddressFamily,
) -> wasmtime_wasi::p3::sockets::SocketResult<Resource<UdpSocket>> {
    let socket = HostUdpSocket::create(&mut view, family).await?;
    let configured = (|| {
        HostUdpSocket::set_send_buffer_size(
            &mut view,
            Resource::new_borrow(socket.rep()),
            MAX_SOCKET_BUFFER_BYTES,
        )?;
        HostUdpSocket::set_receive_buffer_size(
            &mut view,
            Resource::new_borrow(socket.rep()),
            MAX_SOCKET_BUFFER_BYTES,
        )
    })();
    if let Err(error) = configured {
        HostUdpSocket::drop(&mut view, socket)
            .map_err(wasmtime_wasi::p3::sockets::SocketError::trap)?;
        return Err(error);
    }
    Ok(socket)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::component::network::NetworkHost;
    use wasmtime_wasi::sockets::WasiSocketsView;

    struct Deny;
    impl terra_network::Policy for Deny {
        fn allows(&self, _: std::net::IpAddr, _: Option<u16>) -> bool {
            false
        }
    }

    #[tokio::test]
    async fn socket_defaults_and_resource_exhaustion_are_enforced() {
        let mut host = NetworkHost::new(
            crate::component::context::DeviceContext::new(4096).unwrap(),
            std::sync::Arc::new(Deny),
            vec![],
        );
        host.sockets().table.set_max_capacity(2);
        let tcp = create_tcp(host.sockets(), IpAddressFamily::Ipv4).unwrap();
        let udp = create_udp(host.sockets(), IpAddressFamily::Ipv4)
            .await
            .unwrap();
        assert!(create_tcp(host.sockets(), IpAddressFamily::Ipv4).is_err());
        let send = HostTcpSocket::get_send_buffer_size(
            &mut host.sockets(),
            Resource::new_borrow(tcp.rep()),
        )
        .unwrap();
        assert!(send > 0 && send <= MAX_SOCKET_BUFFER_BYTES * 2);
        let receive = HostUdpSocket::get_receive_buffer_size(
            &mut host.sockets(),
            Resource::new_borrow(udp.rep()),
        )
        .unwrap();
        assert!(receive > 0 && receive <= MAX_SOCKET_BUFFER_BYTES * 2);
        HostTcpSocket::drop(&mut host.sockets(), tcp).unwrap();
        let replacement = create_tcp(host.sockets(), IpAddressFamily::Ipv4).unwrap();
        HostTcpSocket::drop(&mut host.sockets(), replacement).unwrap();
        HostUdpSocket::drop(&mut host.sockets(), udp).unwrap();
    }
}
