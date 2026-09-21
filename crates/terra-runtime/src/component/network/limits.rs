use wasmtime::component::{Linker, Resource};
use wasmtime_wasi::p3::bindings::sockets::types::{
    ErrorCode, HostTcpSocket, HostUdpSocket, IpAddressFamily,
};
use wasmtime_wasi::sockets::{TcpSocket, UdpSocket, WasiSocketsCtxView};

const MAX_SOCKET_BUFFER_BYTES: u64 = 256 << 10;
const MAX_LISTEN_BACKLOG: u64 = 64;
const SOCKETS_TYPES_INTERFACE: &str = "wasi:sockets/types@0.3.0";

pub(super) fn add_socket_limits<T: Send + 'static>(
    linker: &mut Linker<T>,
    sockets: for<'a> fn(&'a mut T) -> WasiSocketsCtxView<'a>,
) -> wasmtime::Result<()> {
    linker.allow_shadowing(true);
    let result = (|| {
        // Wasmtime's 0.3.0 resources satisfy the component's 0.3.1 semver import.
        let mut types = linker.instance(SOCKETS_TYPES_INTERFACE)?;
        types.func_wrap(
            "[static]tcp-socket.create",
            move |mut store, (family,): (IpAddressFamily,)| {
                socket_result(create_tcp(sockets(store.data_mut()), family))
            },
        )?;
        types.func_wrap_async(
            "[static]udp-socket.create",
            move |mut store, (family,): (IpAddressFamily,)| {
                Box::new(async move {
                    socket_result(create_udp(sockets(store.data_mut()), family).await)
                })
            },
        )?;
        for (name, operation) in [
            (
                "[method]tcp-socket.set-send-buffer-size",
                (|view, socket, value| HostTcpSocket::set_send_buffer_size(view, socket, value))
                    as SocketOption<TcpSocket>,
            ),
            (
                "[method]tcp-socket.set-receive-buffer-size",
                (|view, socket, value| HostTcpSocket::set_receive_buffer_size(view, socket, value))
                    as SocketOption<TcpSocket>,
            ),
        ] {
            types.func_wrap(
                name,
                move |mut store, (socket, value): (Resource<TcpSocket>, u64)| {
                    set_option(
                        sockets(store.data_mut()),
                        socket,
                        value,
                        MAX_SOCKET_BUFFER_BYTES,
                        operation,
                    )
                },
            )?;
        }
        for (name, operation) in [
            (
                "[method]udp-socket.set-send-buffer-size",
                (|view, socket, value| HostUdpSocket::set_send_buffer_size(view, socket, value))
                    as SocketOption<UdpSocket>,
            ),
            (
                "[method]udp-socket.set-receive-buffer-size",
                (|view, socket, value| HostUdpSocket::set_receive_buffer_size(view, socket, value))
                    as SocketOption<UdpSocket>,
            ),
        ] {
            types.func_wrap(
                name,
                move |mut store, (socket, value): (Resource<UdpSocket>, u64)| {
                    set_option(
                        sockets(store.data_mut()),
                        socket,
                        value,
                        MAX_SOCKET_BUFFER_BYTES,
                        operation,
                    )
                },
            )?;
        }
        types.func_wrap(
            "[method]tcp-socket.set-listen-backlog-size",
            move |mut store, (socket, value): (Resource<TcpSocket>, u64)| {
                set_option(
                    sockets(store.data_mut()),
                    socket,
                    value,
                    MAX_LISTEN_BACKLOG,
                    |view, socket, value| view.set_listen_backlog_size(socket, value),
                )
            },
        )?;
        Ok(())
    })();
    linker.allow_shadowing(false);
    result
}

fn socket_result<S>(
    result: wasmtime_wasi::p3::sockets::SocketResult<Resource<S>>,
) -> wasmtime::Result<(Result<Resource<S>, ErrorCode>,)> {
    Ok((match result {
        Ok(socket) => Ok(socket),
        Err(error) => Err(error.downcast()?),
    },))
}

fn create_tcp(
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

async fn create_udp(
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

type SocketOption<S> = for<'a> fn(
    &mut WasiSocketsCtxView<'a>,
    Resource<S>,
    u64,
) -> wasmtime_wasi::p3::sockets::SocketResult<()>;

fn set_option<S>(
    mut view: WasiSocketsCtxView<'_>,
    socket: Resource<S>,
    value: u64,
    ceiling: u64,
    operation: SocketOption<S>,
) -> wasmtime::Result<(Result<(), ErrorCode>,)> {
    if value > ceiling {
        return Ok((Err(ErrorCode::InvalidArgument),));
    }
    Ok((match operation(&mut view, socket, value) {
        Ok(()) => Ok(()),
        Err(error) => Err(error.downcast()?),
    },))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::component::network::NetworkHost;
    use crate::engine::device_engine;
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

    #[test]
    fn oversized_socket_options_fail_before_host_allocation() {
        let mut host = NetworkHost::new(
            crate::component::context::DeviceContext::new(4096).unwrap(),
            std::sync::Arc::new(Deny),
            vec![],
        );
        let result = set_option(
            host.sockets(),
            Resource::<TcpSocket>::new_borrow(u32::MAX),
            u64::MAX,
            MAX_SOCKET_BUFFER_BYTES,
            |view, socket, value| HostTcpSocket::set_send_buffer_size(view, socket, value),
        )
        .unwrap();
        assert!(matches!(result.0, Err(ErrorCode::InvalidArgument)));
        assert!(
            set_option(
                host.sockets(),
                Resource::<TcpSocket>::new_borrow(u32::MAX),
                1,
                MAX_SOCKET_BUFFER_BYTES,
                |view, socket, value| HostTcpSocket::set_send_buffer_size(view, socket, value)
            )
            .is_err()
        );
        let engine = device_engine().unwrap();
        let mut upstream = Linker::<NetworkHost>::new(&engine);
        wasmtime_wasi::p3::bindings::sockets::types::add_to_linker::<
            NetworkHost,
            wasmtime_wasi::sockets::WasiSockets,
        >(&mut upstream, NetworkHost::sockets)
        .unwrap();
        let mut types = upstream.instance(SOCKETS_TYPES_INTERFACE).unwrap();
        assert!(
            types
                .func_wrap(
                    "[static]tcp-socket.create",
                    |mut store, (family,): (IpAddressFamily,)| {
                        socket_result(create_tcp(NetworkHost::sockets(store.data_mut()), family))
                    },
                )
                .is_err()
        );
        let linker =
            super::super::network_component_linker::<crate::component::network::NetworkHost>(
                &engine,
            )
            .unwrap();
        let component = wasmtime::component::Component::new(
            &engine,
            r#"
            (component
                (import "wasi:sockets/types@0.3.1"
                    (instance $types (export "tcp-socket" (type (sub resource)))))
                (alias export $types "tcp-socket" (type $socket))
                (core func $drop (canon resource.drop $socket))
                (func (export "drop") (param "socket" (own $socket))
                    (canon lift (core func $drop))))
        "#,
        )
        .unwrap();
        linker.instantiate_pre(&component).unwrap();
    }
}
