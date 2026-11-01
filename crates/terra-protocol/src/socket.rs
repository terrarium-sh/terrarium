//! Shared network endpoint layout and defined errors.

use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

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
    /// Postcard encodes a variant as its declaration index, which is the wire code minus one.
    #[must_use]
    pub fn decode(value: u64) -> Option<Self> {
        let index = u8::try_from(value.checked_sub(1)?).ok()?;
        postcard::from_bytes(&[index]).ok()
    }

    /// The errno the guest kernel's terra sockets report for this error.
    pub(crate) const fn errno_name(self) -> &'static str {
        match self {
            Self::AccessDenied => "EACCES",
            Self::InvalidArgument => "EINVAL",
            Self::InvalidState => "ENOTCONN",
            Self::StaleHandle => "ESTALE",
            Self::WrongKind => "EPROTOTYPE",
            Self::Busy | Self::ResolverBusy => "EAGAIN",
            Self::LimitExceeded => "ENOBUFS",
            Self::DuplicateRequest => "EALREADY",
            Self::Cancelled => "ECANCELED",
            Self::ConnectionRefused => "ECONNREFUSED",
            Self::ConnectionReset => "ECONNRESET",
            Self::TimedOut => "ETIMEDOUT",
            Self::NameUnresolvable => "EHOSTUNREACH",
            Self::DatagramTooLarge => "EMSGSIZE",
            Self::Closed => "EPIPE",
            Self::Io => "EIO",
            Self::NotSupported => "EOPNOTSUPP",
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
            assert_eq!(u64::from(error as u16), code);
            assert_eq!(
                postcard::to_allocvec(&error).unwrap(),
                [u8::try_from(code - 1).unwrap()]
            );
            code += 1;
        }
        assert_eq!(code, 21);
        for value in [0, 21, 111, 129, u64::MAX] {
            assert_eq!(Error::decode(value), None);
        }
    }
}
