//! Socket error codes and the host-service addresses guests see.

use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

pub const HOST_SERVICE_IPV4: Ipv4Addr = Ipv4Addr::new(100, 96, 0, 1);
pub const HOST_SERVICE_IPV6: Ipv6Addr = Ipv6Addr::new(0xfd53, 0x4d00, 0, 0, 0, 0, 0, 1);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum Error {
    AccessDenied = 1,
    InvalidArgument = 2,
    InvalidState = 3,
    LimitExceeded = 4,
    Cancelled = 5,
    ConnectionRefused = 6,
    ConnectionReset = 7,
    TimedOut = 8,
    NameUnresolvable = 9,
    ResolverBusy = 10,
    DatagramTooLarge = 11,
    Closed = 12,
    Io = 13,
    NotReady = 14,
    Protocol = 15,
}

impl Error {
    /// Postcard encodes a variant as its declaration index, which is the wire code minus one.
    #[must_use]
    pub(crate) fn decode(value: u16) -> Option<Self> {
        let index = u8::try_from(value.checked_sub(1)?).ok()?;
        postcard::from_bytes(&[index]).ok()
    }

    /// The errno the guest kernel's terra sockets report for this error.
    pub(crate) const fn errno_name(self) -> &'static str {
        match self {
            Self::AccessDenied => "EACCES",
            Self::InvalidArgument => "EINVAL",
            Self::InvalidState => "ENOTCONN",
            Self::ResolverBusy => "EAGAIN",
            Self::LimitExceeded => "ENOBUFS",
            Self::Cancelled => "ECANCELED",
            Self::ConnectionRefused => "ECONNREFUSED",
            Self::ConnectionReset => "ECONNRESET",
            Self::TimedOut => "ETIMEDOUT",
            Self::NameUnresolvable => "EHOSTUNREACH",
            Self::DatagramTooLarge => "EMSGSIZE",
            Self::Closed => "EPIPE",
            Self::Io => "EIO",
            Self::NotReady => "ENETDOWN",
            Self::Protocol => "EPROTO",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Codes run from 1 without gaps, each matching its `repr(u16)` value, so serde's variant
    /// index and the wire code agree; raw errno values beyond the last code are rejected.
    #[test]
    fn defined_errors_preserve_codes_and_reject_raw_errno() {
        let mut code = 1;
        while let Some(error) = Error::decode(code) {
            assert_eq!(error as u16, code);
            assert_eq!(
                postcard::to_allocvec(&error).unwrap(),
                [u8::try_from(code - 1).unwrap()]
            );
            code += 1;
        }
        assert_eq!(code, 16);
        for value in [0, 16, 111, 129, u16::MAX] {
            assert_eq!(Error::decode(value), None);
        }
    }
}
