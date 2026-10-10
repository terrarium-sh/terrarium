//! Host name resolution for guest resolve requests.

use crate::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;
use terra_policy::{BoxPolicy, NameLookup};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub(super) async fn resolve(
    name: &str,
    policy: &BoxPolicy,
    admission: Arc<Semaphore>,
) -> Result<Vec<IpAddr>, Error> {
    let addresses = match policy.lookup_name(name) {
        NameLookup::Denied => return Err(Error::AccessDenied),
        NameLookup::Static(addresses) => addresses,
        NameLookup::Resolve(name) => {
            let permit = admission
                .try_acquire_owned()
                .map_err(|_| Error::ResolverBusy)?;
            let addresses = resolve_addresses((name.clone(), 0), permit).await?;
            policy.accept_resolved(&name, &addresses)
        }
    };
    if addresses.is_empty() {
        return Err(Error::NameUnresolvable);
    }
    Ok(addresses)
}

pub(super) async fn resolve_addresses(
    name: impl ToSocketAddrs + Send + 'static,
    permit: OwnedSemaphorePermit,
) -> Result<Vec<IpAddr>, Error> {
    let resolver = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        name.to_socket_addrs().map(|addresses| {
            addresses
                .map(|address| address.ip().to_canonical())
                .filter(|address| has_host_route(*address))
                .take(terra_policy::MAX_RESOLVED_ADDRESSES)
                .collect::<Vec<_>>()
        })
    });
    tokio::time::timeout(Duration::from_secs(2), resolver)
        .await
        .map_err(|_| Error::TimedOut)?
        .map_err(|_| Error::Io)?
        .map_err(|_| Error::NameUnresolvable)
}

/// Guest UDP connect is local, so the guest's address selection cannot probe host routes; answers keep only routable addresses.
fn has_host_route(address: IpAddr) -> bool {
    let local = if address.is_ipv4() {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    };
    std::net::UdpSocket::bind(local).is_ok_and(|socket| socket.connect((address, 53)).is_ok())
}
