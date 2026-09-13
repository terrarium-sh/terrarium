//! Native authority for standard WASI name lookups in the network component.

use std::{marker::PhantomData, sync::Arc, time::Duration};
use terra_network::{NameLookup, PolicyHandle};
use tokio::sync::Semaphore;
use wasmtime::component::Accessor;
use wasmtime_wasi::sockets::{WasiSockets, WasiSocketsView};

use crate::engine::{DeviceHost, device_component_linker};

pub(crate) const MAX_NAME_LOOKUPS: usize = 8;
use crate::component::policy::MAX_NAME_BYTES;
pub(crate) const MAX_POLICY_CALLS: usize = 8;
const MAX_NAME_ADDRESSES: usize = 32;
const NAME_LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(wasmtime::component::ComponentType, wasmtime::component::Lower)]
#[component(record)]
pub struct NetworkConfig {
    #[component(name = "gateway-mac")]
    pub gateway_mac: Vec<u8>,
    #[component(name = "gateway-ip")]
    pub gateway_ip: Vec<u8>,
    #[component(name = "gateway-ip6")]
    pub gateway_ip6: Vec<u8>,
    #[component(name = "host-service-ports")]
    pub host_service_ports: Vec<Option<u16>>,
    #[component(name = "published-ports")]
    pub published_ports: Vec<PublishedPort>,
    pub mtu: u32,
}

#[derive(wasmtime::component::ComponentType, wasmtime::component::Lower)]
#[component(record)]
pub struct PublishedPort {
    #[component(name = "host-port")]
    pub host_port: u16,
    #[component(name = "guest-port")]
    pub guest_port: u16,
}

#[derive(Clone, Copy, Debug, wasmtime::component::ComponentType, wasmtime::component::Lift)]
#[component(enum)]
#[repr(u8)]
pub enum NetworkError {
    #[component(name = "malformed")]
    Malformed,
    #[component(name = "backpressure")]
    Backpressure,
    #[component(name = "not-ready")]
    NotReady,
}

pub trait NetworkHostState: Send {
    fn network_sockets(&mut self) -> wasmtime_wasi::sockets::WasiSocketsCtxView<'_>;
    fn network_lookups(&mut self) -> Arc<Semaphore>;
    fn network_policy_calls(&mut self) -> Arc<Semaphore>;
}

impl NetworkHostState for DeviceHost {
    fn network_sockets(&mut self) -> wasmtime_wasi::sockets::WasiSocketsCtxView<'_> {
        Self::sockets(self)
    }

    fn network_lookups(&mut self) -> Arc<Semaphore> {
        Self::network_lookups(self)
    }

    fn network_policy_calls(&mut self) -> Arc<Semaphore> {
        Self::network_policy_calls(self)
    }
}

struct NetworkNameLookupHost<T>(PhantomData<T>);

impl<T: 'static> wasmtime::component::HasData for NetworkNameLookupHost<T> {
    type Data<'a> = &'a mut DeviceHost;
}

struct NetworkMemoryHost;

impl wasmtime::component::HasData for NetworkMemoryHost {
    type Data<'a> = &'a mut DeviceHost;
}

async fn resolve_name<T>(
    policy: PolicyHandle,
    lookups: Arc<Semaphore>,
    policy_calls: Arc<Semaphore>,
    accessor: Accessor<T, WasiSockets>,
    name: String,
) -> Result<
    Vec<wasmtime_wasi::p3::bindings::sockets::types::IpAddress>,
    wasmtime_wasi::p3::bindings::sockets::ip_name_lookup::ErrorCode,
> {
    use wasmtime_wasi::p3::bindings::sockets::ip_name_lookup::ErrorCode;

    let Some(name) = terra_network::dns::normalize_hostname(&name) else {
        return Err(ErrorCode::InvalidArgument);
    };
    if name.len() > MAX_NAME_BYTES {
        return Err(ErrorCode::InvalidArgument);
    }
    let addresses = match crate::component::policy::run_policy_decision(
        Arc::clone(&policy),
        Arc::clone(&policy_calls),
        {
            let name = name.clone();
            move |policy| policy.lookup_name(&name)
        },
    )
    .await
    .ok_or(ErrorCode::TemporaryResolverFailure)?
    {
        NameLookup::Static(addresses) => addresses,
        NameLookup::Denied => return Err(ErrorCode::AccessDenied),
        NameLookup::Resolve => {
            let permit = lookups
                .try_acquire_owned()
                .map_err(|_| ErrorCode::TemporaryResolverFailure)?;
            let resolved = tokio::time::timeout(
                NAME_LOOKUP_TIMEOUT,
                <WasiSockets as wasmtime_wasi::p3::bindings::sockets::ip_name_lookup::HostWithStore<T>>::resolve_addresses(&accessor, name.clone()),
            )
                .await
                .map_err(|_| ErrorCode::TemporaryResolverFailure)?
                .map_err(|_| ErrorCode::Other(None))?
                ?
                .into_iter()
                .take(MAX_NAME_ADDRESSES)
                .map(native_address)
                .collect::<Vec<_>>();
            drop(permit);
            crate::component::policy::run_policy_decision(policy, policy_calls, move |policy| {
                policy.accept_resolved(&name, &resolved)
            })
            .await
            .ok_or(ErrorCode::TemporaryResolverFailure)?
        }
    };
    (!addresses.is_empty() && addresses.len() <= MAX_NAME_ADDRESSES)
        .then_some(addresses.into_iter().map(wasi_address).collect())
        .ok_or(ErrorCode::NameUnresolvable)
}

fn wasi_address(
    address: std::net::IpAddr,
) -> wasmtime_wasi::p3::bindings::sockets::types::IpAddress {
    use wasmtime_wasi::p3::bindings::sockets::types::IpAddress;

    match address {
        std::net::IpAddr::V4(address) => {
            let [a, b, c, d] = address.octets();
            IpAddress::Ipv4((a, b, c, d))
        }
        std::net::IpAddr::V6(address) => IpAddress::Ipv6(address.segments().into()),
    }
}

fn native_address(
    address: wasmtime_wasi::p3::bindings::sockets::types::IpAddress,
) -> std::net::IpAddr {
    match address {
        wasmtime_wasi::p3::bindings::sockets::types::IpAddress::Ipv4((a, b, c, d)) => {
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(a, b, c, d))
        }
        wasmtime_wasi::p3::bindings::sockets::types::IpAddress::Ipv6(segments) => {
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(<[u16; 8]>::from(segments)))
        }
    }
}

impl wasmtime_wasi::p3::bindings::sockets::ip_name_lookup::Host for &mut DeviceHost {}

impl<T: NetworkHostState + 'static>
    wasmtime_wasi::p3::bindings::sockets::ip_name_lookup::HostWithStore<T>
    for NetworkNameLookupHost<T>
{
    async fn resolve_addresses(
        host: &Accessor<T, Self>,
        name: String,
    ) -> wasmtime::Result<
        Result<
            Vec<wasmtime_wasi::p3::bindings::sockets::types::IpAddress>,
            wasmtime_wasi::p3::bindings::sockets::ip_name_lookup::ErrorCode,
        >,
    > {
        let (policy, lookups, policy_calls) = host.with(|mut access| {
            let host = access.get();
            (
                host.network_policy(),
                host.network_lookups(),
                host.network_policy_calls(),
            )
        });
        let resolver = host.with_getter::<WasiSockets>(T::network_sockets);
        Ok(match policy {
            Some(policy) => resolve_name(policy, lookups, policy_calls, resolver, name).await,
            None => {
                Err(wasmtime_wasi::p3::bindings::sockets::ip_name_lookup::ErrorCode::AccessDenied)
            }
        })
    }
}

pub fn network_component_linker(
    engine: &wasmtime::Engine,
) -> wasmtime::Result<wasmtime::component::Linker<DeviceHost>> {
    let mut linker = device_component_linker(engine)?;
    wasmtime_wasi::p3::bindings::sockets::types::add_to_linker::<DeviceHost, WasiSockets>(
        &mut linker,
        DeviceHost::sockets,
    )?;
    super::limits::add_socket_limits(&mut linker, DeviceHost::sockets)?;
    wasmtime_wasi::p3::bindings::sockets::ip_name_lookup::add_to_linker::<
        DeviceHost,
        NetworkNameLookupHost<DeviceHost>,
    >(&mut linker, |host| host)?;
    crate::engine::terra::host::memory::add_to_linker::<DeviceHost, NetworkMemoryHost>(
        &mut linker,
        |host| host,
    )?;
    crate::engine::terra::host::interrupt::add_to_linker::<DeviceHost, NetworkMemoryHost>(
        &mut linker,
        |host| host,
    )?;
    crate::engine::terra::host::diagnostics::add_to_linker::<DeviceHost, NetworkMemoryHost>(
        &mut linker,
        |host| host,
    )?;
    Ok(linker)
}

pub fn network_component_linker_with<T>(
    engine: &wasmtime::Engine,
    wasi: crate::engine::DeviceWasiGetters<T>,
    get_host: for<'a> fn(&'a mut T) -> &'a mut DeviceHost,
) -> wasmtime::Result<wasmtime::component::Linker<T>>
where
    T: NetworkHostState + 'static,
{
    let mut linker = crate::engine::device_component_linker_with_wasi(engine, wasi)?;
    wasmtime_wasi::p3::bindings::sockets::types::add_to_linker::<T, WasiSockets>(
        &mut linker,
        T::network_sockets,
    )?;
    super::limits::add_socket_limits(&mut linker, T::network_sockets)?;
    wasmtime_wasi::p3::bindings::sockets::ip_name_lookup::add_to_linker::<
        T,
        NetworkNameLookupHost<T>,
    >(&mut linker, get_host)?;
    crate::engine::terra::host::memory::add_to_linker::<T, NetworkMemoryHost>(
        &mut linker,
        get_host,
    )?;
    crate::engine::terra::host::interrupt::add_to_linker::<T, NetworkMemoryHost>(
        &mut linker,
        get_host,
    )?;
    crate::engine::terra::host::diagnostics::add_to_linker::<T, NetworkMemoryHost>(
        &mut linker,
        get_host,
    )?;
    Ok(linker)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::thread;
    use terra_network::Policy;

    struct Static;

    impl Policy for Static {
        fn allows(&self, _: IpAddr, _: Option<u16>) -> bool {
            false
        }

        fn lookup_name(&self, name: &str) -> NameLookup {
            if name == "db.test" {
                NameLookup::Static(vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))])
            } else {
                NameLookup::Denied
            }
        }
    }

    #[test]
    fn resolver_policy_hides_ungranted_names() {
        let policy: PolicyHandle = Arc::new(Static);
        assert!(
            matches!(policy.lookup_name("db.test"), NameLookup::Static(addresses) if addresses.len() == 1)
        );
        assert!(matches!(
            policy.lookup_name("blocked.test"),
            NameLookup::Denied
        ));
    }

    #[test]
    fn each_device_host_has_its_own_lookup_budget() {
        let first = DeviceHost::new(1).expect("device host");
        let second = DeviceHost::new(1).expect("device host");
        assert!(!Arc::ptr_eq(
            &first.network_lookups(),
            &second.network_lookups()
        ));
    }

    struct Slow;

    impl Policy for Slow {
        fn allows(&self, _: IpAddr, _: Option<u16>) -> bool {
            false
        }

        fn lookup_name(&self, _: &str) -> NameLookup {
            thread::sleep(Duration::from_millis(50));
            NameLookup::Denied
        }
    }

    #[tokio::test]
    async fn policy_decision_does_not_block_the_event_loop() {
        let policy: PolicyHandle = Arc::new(Slow);
        assert!(
            tokio::time::timeout(
                Duration::from_millis(10),
                crate::component::policy::run_policy_decision(
                    policy,
                    Arc::new(Semaphore::new(1)),
                    |policy| { policy.lookup_name("slow.test") }
                ),
            )
            .await
            .is_err()
        );
    }
}
