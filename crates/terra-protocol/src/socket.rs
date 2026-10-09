//! Shared network endpoint layout and defined errors.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const VERSION: u16 = 1;
pub const ENDPOINT_BYTES: usize = 20;
pub const MAX_DATAGRAM_BYTES: usize = super::network::MAX_NETWORK_DATAGRAM_BYTES;
pub const MAX_DNS_BYTES: usize = 4096;
pub const HOST_SERVICE_IPV4: Ipv4Addr = Ipv4Addr::new(100, 96, 0, 1);
pub const HOST_SERVICE_IPV6: Ipv6Addr = Ipv6Addr::new(0xfd53, 0x4d00, 0, 0, 0, 0, 0, 1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    pub fn decode(value: u64) -> Result<Self, WireError> {
        match value {
            1 => Ok(Self::AccessDenied),
            2 => Ok(Self::InvalidArgument),
            3 => Ok(Self::InvalidState),
            4 => Ok(Self::StaleHandle),
            5 => Ok(Self::WrongKind),
            6 => Ok(Self::Busy),
            7 => Ok(Self::LimitExceeded),
            8 => Ok(Self::DuplicateRequest),
            9 => Ok(Self::Cancelled),
            10 => Ok(Self::ConnectionRefused),
            11 => Ok(Self::ConnectionReset),
            12 => Ok(Self::TimedOut),
            13 => Ok(Self::NameUnresolvable),
            14 => Ok(Self::ResolverBusy),
            15 => Ok(Self::DatagramTooLarge),
            16 => Ok(Self::Closed),
            17 => Ok(Self::Io),
            18 => Ok(Self::NotSupported),
            19 => Ok(Self::NotReady),
            20 => Ok(Self::Protocol),
            _ => Err(WireError::Malformed),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireError {
    Malformed,
}

pub fn encode_peer(peer: SocketAddr) -> Result<Vec<u8>, WireError> {
    let mut bytes = Vec::with_capacity(ENDPOINT_BYTES);
    match peer {
        SocketAddr::V4(peer) => {
            bytes.extend_from_slice(&[4, 0]);
            bytes.extend_from_slice(&peer.port().to_le_bytes());
            bytes.extend_from_slice(&peer.ip().octets());
            bytes.extend_from_slice(&[0; 12]);
        }
        SocketAddr::V6(peer) => {
            if peer.flowinfo() != 0 || peer.scope_id() != 0 {
                return Err(WireError::Malformed);
            }
            bytes.extend_from_slice(&[6, 0]);
            bytes.extend_from_slice(&peer.port().to_le_bytes());
            bytes.extend_from_slice(&peer.ip().octets());
        }
    }
    Ok(bytes)
}

pub fn decode_peer(bytes: &[u8]) -> Result<SocketAddr, WireError> {
    if bytes.len() != ENDPOINT_BYTES || bytes[1] != 0 {
        return Err(WireError::Malformed);
    }
    let port = u16::from_le_bytes([bytes[2], bytes[3]]);
    let address = match bytes[0] {
        4 if bytes[8..20] == [0; 12] => {
            IpAddr::V4(Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]))
        }
        6 => IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(&bytes[4..20]).map_err(|_| WireError::Malformed)?,
        )),
        _ => return Err(WireError::Malformed),
    };
    Ok(SocketAddr::new(address, port))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn endpoints_pin_address_layout_and_reject_native_only_fields() {
        let ipv4: SocketAddr = "203.0.113.1:443".parse().unwrap();
        let bytes = encode_peer(ipv4).unwrap();
        assert_eq!(
            bytes,
            [
                4, 0, 0xbb, 1, 203, 0, 113, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );
        assert_eq!(decode_peer(&bytes), Ok(ipv4));
        for peer in [ipv4, "[2001:db8::1]:53".parse().unwrap()] {
            assert_eq!(decode_peer(&encode_peer(peer).unwrap()), Ok(peer));
        }
        for (offset, value) in [(0, 5), (1, 1), (8, 1)] {
            let mut malformed = bytes.clone();
            malformed[offset] = value;
            assert_eq!(decode_peer(&malformed), Err(WireError::Malformed));
        }
        for length in 0..ENDPOINT_BYTES {
            assert!(decode_peer(&bytes[..length]).is_err());
        }
        assert!(encode_peer("[fe80::1%1]:53".parse().unwrap()).is_err());
        let flowinfo = std::net::SocketAddrV6::new(Ipv6Addr::LOCALHOST, 53, 1, 0);
        assert!(encode_peer(SocketAddr::V6(flowinfo)).is_err());
    }

    #[test]
    fn defined_errors_preserve_codes_and_reject_raw_errno() {
        for (value, expected) in [
            (1, Error::AccessDenied),
            (2, Error::InvalidArgument),
            (3, Error::InvalidState),
            (4, Error::StaleHandle),
            (5, Error::WrongKind),
            (6, Error::Busy),
            (7, Error::LimitExceeded),
            (8, Error::DuplicateRequest),
            (9, Error::Cancelled),
            (10, Error::ConnectionRefused),
            (11, Error::ConnectionReset),
            (12, Error::TimedOut),
            (13, Error::NameUnresolvable),
            (14, Error::ResolverBusy),
            (15, Error::DatagramTooLarge),
            (16, Error::Closed),
            (17, Error::Io),
            (18, Error::NotSupported),
            (19, Error::NotReady),
            (20, Error::Protocol),
        ] {
            assert_eq!(Error::decode(value), Ok(expected));
            assert_eq!(u64::from(expected as u16), value);
        }
        for value in [0, 21, 111, u64::MAX] {
            assert_eq!(Error::decode(value), Err(WireError::Malformed));
        }
    }
}
