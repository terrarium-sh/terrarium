//! Peer address validation and policy authorization.

use crate::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use terra_policy::BoxPolicy;

pub(super) fn is_host_loopback(address: IpAddr) -> bool {
    address == IpAddr::V4(Ipv4Addr::LOCALHOST) || address == IpAddr::V6(Ipv6Addr::LOCALHOST)
}

pub(super) fn validate_peer(address: SocketAddr) -> Result<(), Error> {
    if address.port() == 0
        || address.ip().is_unspecified()
        || address.ip() != address.ip().to_canonical()
        || matches!(address, SocketAddr::V6(address) if address.scope_id() != 0 || address.flowinfo() != 0)
    {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

pub(super) fn authorize_peer(policy: &BoxPolicy, peer: SocketAddr) -> bool {
    if peer.port() == 53 && policy.blocks_direct_dns() {
        return false;
    }
    is_host_loopback(peer.ip())
        && policy
            .host_service_ports()
            .iter()
            .any(|port| port.is_none_or(|port| port == peer.port()))
        || policy.allows(peer.ip(), Some(peer.port()))
}
