//! Host name resolution for guest resolve requests.

use crate::{Error, SocketSource};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;
use terra_policy::{BoxPolicy, NameLookup};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub(super) async fn resolve(
    name: &str,
    policy: &BoxPolicy,
    admission: Arc<Semaphore>,
    sockets: &SocketSource,
) -> Result<Vec<IpAddr>, Error> {
    let addresses = match policy.lookup_name(name) {
        NameLookup::Denied => return Err(Error::AccessDenied),
        NameLookup::Static(addresses) => addresses.to_vec(),
        NameLookup::Resolve(name) => {
            let permit = admission
                .try_acquire_owned()
                .map_err(|_| Error::ResolverBusy)?;
            let addresses = resolve_addresses((name.clone(), 0), permit, sockets.clone()).await?;
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
    sockets: SocketSource,
) -> Result<Vec<IpAddr>, Error> {
    let resolver = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        name.to_socket_addrs().map(|addresses| {
            addresses
                .map(|address| address.ip().to_canonical())
                .filter(|address| has_host_route(&sockets, *address))
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
fn has_host_route(sockets: &SocketSource, address: IpAddr) -> bool {
    sockets
        .bind_udp(socket2::Domain::for_address(SocketAddr::from((address, 0))))
        .is_ok_and(|socket| {
            socket
                .connect(&SocketAddr::from((address, 53)).into())
                .is_ok()
        })
}
