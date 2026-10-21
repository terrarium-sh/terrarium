//! Peer address validation and policy authorization.

use crate::Error;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

/// Mapped `::ffff:a.b.c.d`, compatible `::a.b.c.d` and translated `::ffff:0:a.b.c.d` forms: a host
/// that routes one to its IPv4 address would bypass the policy's checks of that address.
#[must_use]
pub fn embeds_ipv4(address: Ipv6Addr) -> bool {
    let prefix = &address.segments()[..6];
    address.to_ipv4_mapped().is_some()
        || prefix == [0, 0, 0, 0, 0xffff, 0]
        || (prefix == [0; 6] && !address.is_unspecified() && !address.is_loopback())
}

pub(super) fn validate_peer(address: SocketAddr) -> Result<(), Error> {
    if address.port() == 0
        || address.ip().is_unspecified()
        || matches!(address.ip(), IpAddr::V6(ip) if embeds_ipv4(ip))
        || matches!(address, SocketAddr::V6(address) if address.scope_id() != 0 || address.flowinfo() != 0)
    {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The VM side refuses these forms too; a broker that accepted them would let a compromised
    /// VM process reach `[::<host IP>]` past the host-address check, which matches exact addresses.
    #[test]
    fn peers_embedding_ipv4_are_refused() {
        for peer in [
            "[::ffff:192.0.2.1]:22",
            "[::192.0.2.1]:22",
            "[::ffff:0:192.0.2.1]:22",
        ] {
            assert_eq!(
                validate_peer(peer.parse().unwrap()),
                Err(Error::InvalidArgument),
                "{peer}"
            );
        }
        for peer in ["[::1]:22", "[2001:db8::1]:22", "[64:ff9b::192.0.2.1]:22"] {
            assert_eq!(validate_peer(peer.parse().unwrap()), Ok(()), "{peer}");
        }
    }
}
