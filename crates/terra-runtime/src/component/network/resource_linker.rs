use wasmtime::component::{Access, Resource, ResourceType, StreamReader};
use wasmtime_wasi::{
    p3::bindings::sockets::types::{
        self, HostTcpSocket, HostTcpSocketWithStore, HostUdpSocket, HostUdpSocketWithStore,
    },
    sockets::{TcpSocket, UdpSocket, WasiSockets, WasiSocketsView},
};

macro_rules! socket_concurrent {
    ($interface:expr, $name:literal, $trait:ident::$method:ident, ($($arg:ident: $type:ty),+ $(,)?)) => {
        $interface.func_wrap_concurrent($name, move |accessor, ($($arg,)+): ($($type,)+)| {
            Box::pin(async move {
                let sockets = accessor.with_getter::<WasiSockets>(T::sockets);
                match <WasiSockets as $trait<T>>::$method(&sockets, $($arg),+).await {
                    Ok(value) => Ok((Ok(value),)),
                    Err(error) => Ok((Err(error.downcast()?),)),
                }
            })
        })?;
    };
}

#[allow(clippy::too_many_lines)]
pub(super) fn add<T: WasiSocketsView + Send + 'static>(
    linker: &mut wasmtime::component::Linker<T>,
) -> wasmtime::Result<()> {
    let mut interface = linker.instance("wasi:sockets/types@0.3.0")?;
    interface.resource(
        "tcp-socket",
        ResourceType::host::<TcpSocket>(),
        |mut store, representation| {
            <_ as HostTcpSocket>::drop(
                &mut T::sockets(store.data_mut()),
                Resource::new_own(representation),
            )
        },
    )?;
    interface.resource(
        "udp-socket",
        ResourceType::host::<UdpSocket>(),
        |mut store, representation| {
            <_ as HostUdpSocket>::drop(
                &mut T::sockets(store.data_mut()),
                Resource::new_own(representation),
            )
        },
    )?;
    interface.func_wrap(
        "[static]tcp-socket.create",
        |mut store, (family,): (types::IpAddressFamily,)| match super::limits::create_tcp(
            T::sockets(store.data_mut()),
            family,
        ) {
            Ok(socket) => Ok((Ok(socket),)),
            Err(error) => Ok((Err(error.downcast()?),)),
        },
    )?;
    interface.func_wrap_async(
        "[method]tcp-socket.bind",
        |mut store, (socket, address): (Resource<TcpSocket>, types::IpSocketAddress)| {
            Box::new(async move {
                match <_ as HostTcpSocket>::bind(&mut T::sockets(store.data_mut()), socket, address)
                    .await
                {
                    Ok(()) => Ok((Ok(()),)),
                    Err(error) => Ok((Err(error.downcast()?),)),
                }
            })
        },
    )?;
    socket_concurrent!(interface, "[method]tcp-socket.connect", HostTcpSocketWithStore::connect, (socket: Resource<TcpSocket>, address: types::IpSocketAddress));
    interface.func_wrap_async(
        "[method]tcp-socket.listen",
        |store, (socket,): (Resource<TcpSocket>,)| {
            Box::new(async move {
                match <WasiSockets as HostTcpSocketWithStore<T>>::listen(
                    Access::<T, WasiSockets>::new(store, T::sockets),
                    socket,
                )
                .await
                {
                    Ok(stream) => Ok((Ok(stream),)),
                    Err(error) => Ok((Err(error.downcast()?),)),
                }
            })
        },
    )?;
    interface.func_wrap(
        "[method]tcp-socket.send",
        |store, (socket, data): (Resource<TcpSocket>, StreamReader<u8>)| {
            Ok((<WasiSockets as HostTcpSocketWithStore<T>>::send(
                Access::<T, WasiSockets>::new(store, T::sockets),
                socket,
                data,
            )?,))
        },
    )?;
    interface.func_wrap(
        "[method]tcp-socket.receive",
        |store, (socket,): (Resource<TcpSocket>,)| {
            Ok((<WasiSockets as HostTcpSocketWithStore<T>>::receive(
                Access::<T, WasiSockets>::new(store, T::sockets),
                socket,
            )?,))
        },
    )?;
    interface.func_wrap_async(
        "[static]udp-socket.create",
        |mut store, (family,): (types::IpAddressFamily,)| {
            Box::new(async move {
                match super::limits::create_udp(T::sockets(store.data_mut()), family).await {
                    Ok(socket) => Ok((Ok(socket),)),
                    Err(error) => Ok((Err(error.downcast()?),)),
                }
            })
        },
    )?;
    interface.func_wrap_async(
        "[method]udp-socket.connect",
        |mut store, (socket, address): (Resource<UdpSocket>, types::IpSocketAddress)| {
            Box::new(async move {
                match <_ as HostUdpSocket>::connect(
                    &mut T::sockets(store.data_mut()),
                    socket,
                    address,
                )
                .await
                {
                    Ok(()) => Ok((Ok(()),)),
                    Err(error) => Ok((Err(error.downcast()?),)),
                }
            })
        },
    )?;
    socket_concurrent!(interface, "[method]udp-socket.send", HostUdpSocketWithStore::send, (socket: Resource<UdpSocket>, data: Vec<u8>, address: Option<types::IpSocketAddress>));
    socket_concurrent!(interface, "[method]udp-socket.receive", HostUdpSocketWithStore::receive, (socket: Resource<UdpSocket>));
    Ok(())
}
