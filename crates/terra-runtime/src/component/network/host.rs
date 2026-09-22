//! Native authority for standard WASI name lookups in the network component.

use super::authorization::PolicyClient;
use std::{marker::PhantomData, sync::Arc, time::Duration};
use terra_network::NameLookup;
use tokio::sync::Semaphore;
use wasmtime::component::Accessor;
use wasmtime_wasi::sockets::{WasiSockets, WasiSocketsView};

use crate::component::context::{DeviceContext, DeviceHost};
use wasmtime_wasi::{WasiCtxView, WasiView};

pub struct NetworkHost {
    pub context: DeviceContext,
    network_policy: PolicyClient,
    network_lookups: Arc<tokio::sync::Semaphore>,
}

impl NetworkHost {
    #[must_use]
    pub fn new(
        mut context: DeviceContext,
        policy: terra_network::PolicyHandle,
        published_ports: Vec<terra_network::PortMapping>,
    ) -> Self {
        let host_service_ports = policy.host_service_ports().to_vec();
        let policy = PolicyClient::new(policy, Arc::new(Semaphore::new(super::MAX_POLICY_CALLS)));
        *context.ctx().ctx = super::authorization::build_network_context(
            policy.clone(),
            host_service_ports,
            published_ports,
        );
        Self {
            context,
            network_policy: policy,
            network_lookups: Arc::new(tokio::sync::Semaphore::new(MAX_NAME_LOOKUPS)),
        }
    }

    pub(crate) fn network_policy(&self) -> PolicyClient {
        self.network_policy.clone()
    }

    pub(crate) fn network_lookups(&self) -> Arc<tokio::sync::Semaphore> {
        Arc::clone(&self.network_lookups)
    }
}

impl DeviceHost for NetworkHost {
    fn context(&mut self) -> &mut DeviceContext {
        &mut self.context
    }
}
impl WasiView for NetworkHost {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        self.context.ctx()
    }
}

impl AsMut<NetworkHost> for NetworkHost {
    fn as_mut(&mut self) -> &mut Self {
        self
    }
}

impl crate::box_runtime::store::StoreHost for NetworkHost {}

pub(crate) const MAX_NAME_LOOKUPS: usize = 8;
use crate::component::policy::MAX_NAME_BYTES;
const MAX_NAME_ADDRESSES: usize = 32;
const NAME_LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);

struct NetworkNameLookupHost<T>(PhantomData<T>);

impl<T: 'static> wasmtime::component::HasData for NetworkNameLookupHost<T> {
    type Data<'a> = &'a mut NetworkHost;
}

async fn resolve_name<T>(
    policy: PolicyClient,
    lookups: Arc<Semaphore>,
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
    let addresses = match policy
        .lookup_name(name.clone())
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
            policy
                .accept_resolved(name, resolved)
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

impl wasmtime_wasi::p3::bindings::sockets::ip_name_lookup::Host for &mut NetworkHost {}

impl<T: wasmtime_wasi::WasiView + 'static>
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
        let (policy, lookups) = host.with(|mut access| {
            let host = access.get();
            (host.network_policy(), host.network_lookups())
        });
        let resolver = host.with_getter::<WasiSockets>(T::sockets);
        Ok(resolve_name(policy, lookups, resolver, name).await)
    }
}

pub fn network_component_linker<T: wasmtime_wasi::WasiView + AsMut<NetworkHost> + 'static>(
    engine: &wasmtime::Engine,
) -> wasmtime::Result<wasmtime::component::Linker<T>> {
    let mut linker = crate::component::context::device_component_linker(engine)?;
    crate::component::clocks::add_monotonic_now_and_wait_for(&mut linker)?;
    super::resource_linker::add(&mut linker)?;
    wasmtime_wasi::p3::bindings::sockets::ip_name_lookup::add_to_linker::<
        T,
        NetworkNameLookupHost<T>,
    >(&mut linker, AsMut::as_mut)?;
    crate::component::context::add_device_imports(&mut linker, |host: &mut T| {
        &mut host.as_mut().context
    })?;
    crate::component::bindings::diagnostics::add_to_linker::<
        T,
        wasmtime::component::HasSelf<crate::component::context::DeviceContext>,
    >(&mut linker, |host| &mut host.as_mut().context)?;
    Ok(linker)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::thread;
    use terra_network::Policy;
    use terra_network::PolicyHandle;

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
        let first = NetworkHost::new(
            crate::component::context::DeviceContext::new(1).unwrap(),
            Arc::new(Static),
            vec![],
        );
        let second = NetworkHost::new(
            crate::component::context::DeviceContext::new(1).unwrap(),
            Arc::new(Static),
            vec![],
        );
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
                PolicyClient::new(policy, Arc::new(Semaphore::new(1)))
                    .lookup_name("slow.test".into()),
            )
            .await
            .is_err()
        );
    }
}
