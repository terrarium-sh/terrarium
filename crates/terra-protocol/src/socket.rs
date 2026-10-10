//! Shared network endpoint layout and defined errors.

use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

pub const VERSION: u16 = 1;
pub const MAX_DATAGRAM_BYTES: usize = super::network::MAX_NETWORK_DATAGRAM_BYTES;
pub const MAX_DNS_BYTES: usize = 4096;
pub const HOST_SERVICE_IPV4: Ipv4Addr = Ipv4Addr::new(100, 96, 0, 1);
pub const HOST_SERVICE_IPV6: Ipv6Addr = Ipv6Addr::new(0xfd53, 0x4d00, 0, 0, 0, 0, 0, 1);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum Error {
    AccessDenied = 1,
    InvalidArgument = 2,
    InvalidState = 3,
    StaleHandle = 4,
    WrongKind = 5,
    Busy = 6,
    LimitExceeded = 7,
    DuplicateRequest = 8,
    Cancelled = 9,
    ConnectionRefused = 10,
    ConnectionReset = 11,
    TimedOut = 12,
    NameUnresolvable = 13,
    ResolverBusy = 14,
    DatagramTooLarge = 15,
    Closed = 16,
    Io = 17,
    NotSupported = 18,
    NotReady = 19,
    Protocol = 20,
}

impl Error {
    const ALL: [Self; 20] = [
        Self::AccessDenied,
        Self::InvalidArgument,
        Self::InvalidState,
        Self::StaleHandle,
        Self::WrongKind,
        Self::Busy,
        Self::LimitExceeded,
        Self::DuplicateRequest,
        Self::Cancelled,
        Self::ConnectionRefused,
        Self::ConnectionReset,
        Self::TimedOut,
        Self::NameUnresolvable,
        Self::ResolverBusy,
        Self::DatagramTooLarge,
        Self::Closed,
        Self::Io,
        Self::NotSupported,
        Self::NotReady,
        Self::Protocol,
    ];

    #[must_use]
    pub fn decode(value: u64) -> Option<Self> {
        let index = usize::try_from(value.checked_sub(1)?).ok()?;
        Self::ALL.get(index).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defined_errors_preserve_codes_and_reject_raw_errno() {
        for (index, expected) in Error::ALL.into_iter().enumerate() {
            let value = index as u64 + 1;
            assert_eq!(u64::from(expected as u16), value);
            assert_eq!(Error::decode(value), Some(expected));
        }
        for value in [0, 21, 111, u64::MAX] {
            assert_eq!(Error::decode(value), None);
        }
    }

    /// Postcard's variant index is the wire code minus one, so the serde and `repr(u16)` encodings agree.
    #[test]
    fn serde_variant_index_matches_wire_code() {
        for expected in Error::ALL {
            let encoded = postcard::to_allocvec(&expected).unwrap();
            assert_eq!(u16::from(encoded[0]), expected as u16 - 1);
        }
    }
}
