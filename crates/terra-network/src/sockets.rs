//! The origin of the broker's outbound sockets.

use futures_util::future::BoxFuture;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

/// Opens outbound sockets for a broker whose host sandbox withholds network authority from the
/// broker's own sockets. Neither operation yields a socket that can still listen.
pub trait OutboundSockets: Send + Sync {
    /// Resolves to a TCP socket connected to `peer`.
    fn connect_tcp(&self, peer: SocketAddr) -> BoxFuture<'static, io::Result<socket2::Socket>>;

    /// Returns a UDP socket bound to an ephemeral port on the unspecified address of `domain`.
    fn bind_udp(&self, domain: socket2::Domain) -> io::Result<socket2::Socket>;
}

#[derive(Clone, Default)]
pub enum SocketSource {
    #[default]
    Native,
    /// A trusted process outside the broker's host sandbox opens each socket.
    Delegated(Arc<dyn OutboundSockets>),
}

impl SocketSource {
    pub(crate) fn bind_udp(&self, domain: socket2::Domain) -> io::Result<socket2::Socket> {
        match self {
            Self::Native => bind_unspecified_udp(domain),
            Self::Delegated(outbound) => outbound.bind_udp(domain),
        }
    }
}

fn bind_unspecified_udp(domain: socket2::Domain) -> io::Result<socket2::Socket> {
    let local = if domain == socket2::Domain::IPV6 {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    };
    crate::server::bind_udp_socket(local)
}
