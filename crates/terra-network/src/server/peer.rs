//! Peer address validation and policy authorization.

use crate::Error;
use std::net::SocketAddr;

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
