//! Frames for per-socket TCP/UDP streams, network control, and publication headers.

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use crate::socket::{self, Error as ProtocolError};

pub const VERSION: u16 = 1;
pub const HEADER_BYTES: usize = 8;
const DNS_PREFIX_BYTES: usize = 8;
const STATUS_BYTES: usize = 4;
const ENDPOINT_BYTES: usize = 20;
pub const MAX_PAYLOAD_BYTES: usize = ENDPOINT_BYTES + socket::MAX_DATAGRAM_BYTES;
pub const MAX_FRAME_BYTES: usize = HEADER_BYTES + MAX_PAYLOAD_BYTES;
pub const MAX_OPENING_BYTES: usize = 64;
pub const OPEN_TIMEOUT_SECS: u64 = 30;
/// Concurrent DNS queries the agent may have outstanding on the control stream.
pub const MAX_DNS_QUERIES: usize = 16;
const _: () = assert!(DNS_PREFIX_BYTES + socket::MAX_DNS_BYTES + 2 <= MAX_PAYLOAD_BYTES);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    GuestToHost,
    HostToGuest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
enum Opcode {
    TcpOpen = 0x01,
    UdpOpen = 0x02,
    UdpSend = 0x03,
    Hello = 0x04,
    DnsQuery = 0x05,
    TcpOpened = 0x101,
    UdpOpened = 0x102,
    UdpDatagram = 0x103,
    UdpError = 0x104,
    Ready = 0x105,
    DnsResult = 0x106,
    Publication = 0x107,
    PublicationUdp = 0x108,
}

impl TryFrom<u16> for Opcode {
    type Error = ErrorCode;
    fn try_from(value: u16) -> Result<Self, ErrorCode> {
        Ok(match value {
            0x01 => Self::TcpOpen,
            0x02 => Self::UdpOpen,
            0x03 => Self::UdpSend,
            0x04 => Self::Hello,
            0x05 => Self::DnsQuery,
            0x101 => Self::TcpOpened,
            0x102 => Self::UdpOpened,
            0x103 => Self::UdpDatagram,
            0x104 => Self::UdpError,
            0x105 => Self::Ready,
            0x106 => Self::DnsResult,
            0x107 => Self::Publication,
            0x108 => Self::PublicationUdp,
            _ => return Err(ErrorCode::UnknownOpcode),
        })
    }
}

impl Opcode {
    const fn direction(self) -> Direction {
        match self {
            Self::TcpOpen | Self::UdpOpen | Self::UdpSend | Self::Hello | Self::DnsQuery => {
                Direction::GuestToHost
            }
            Self::TcpOpened
            | Self::UdpOpened
            | Self::UdpDatagram
            | Self::UdpError
            | Self::Ready
            | Self::DnsResult
            | Self::Publication
            | Self::PublicationUdp => Direction::HostToGuest,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum ErrorCode {
    InvalidFrame = 1,
    UnsupportedVersion = 2,
    WrongDirection = 3,
    UnknownOpcode = 4,
    LimitExceeded = 5,
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidFrame => "invalid network frame",
            Self::UnsupportedVersion => "unsupported network ABI version",
            Self::WrongDirection => "wrong network frame direction",
            Self::UnknownOpcode => "unknown network frame opcode",
            Self::LimitExceeded => "network frame limit exceeded",
        })
    }
}

impl std::error::Error for ErrorCode {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpTarget {
    Peer(SocketAddr),
    HostService(u16),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    TcpOpen {
        target: TcpTarget,
        inline_urgent: bool,
    },
    TcpOpened(Result<SocketAddr, ProtocolError>),
    UdpOpen,
    UdpOpened(Result<(), ProtocolError>),
    UdpSend {
        peer: SocketAddr,
        bytes: Vec<u8>,
    },
    UdpDatagram {
        peer: SocketAddr,
        bytes: Vec<u8>,
    },
    UdpError {
        peer: SocketAddr,
        error: ProtocolError,
    },
    Hello,
    Ready,
    DnsQuery {
        id: u32,
        stream: bool,
        bytes: Vec<u8>,
    },
    DnsResult {
        id: u32,
        stream: bool,
        bytes: Vec<u8>,
    },
    Publication {
        guest_port: u16,
        peer: SocketAddr,
    },
    PublicationUdp {
        guest_port: u16,
    },
}

impl Message {
    #[must_use]
    const fn opcode(&self) -> Opcode {
        match self {
            Self::TcpOpen { .. } => Opcode::TcpOpen,
            Self::TcpOpened(_) => Opcode::TcpOpened,
            Self::UdpOpen => Opcode::UdpOpen,
            Self::UdpOpened(_) => Opcode::UdpOpened,
            Self::UdpSend { .. } => Opcode::UdpSend,
            Self::UdpDatagram { .. } => Opcode::UdpDatagram,
            Self::UdpError { .. } => Opcode::UdpError,
            Self::Hello => Opcode::Hello,
            Self::Ready => Opcode::Ready,
            Self::DnsQuery { .. } => Opcode::DnsQuery,
            Self::DnsResult { .. } => Opcode::DnsResult,
            Self::Publication { .. } => Opcode::Publication,
            Self::PublicationUdp { .. } => Opcode::PublicationUdp,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, ErrorCode> {
        let mut frame = Vec::with_capacity(HEADER_BYTES + ENDPOINT_BYTES);
        frame.resize(HEADER_BYTES, 0);
        match self {
            Self::TcpOpen {
                target,
                inline_urgent,
            } => {
                frame.extend_from_slice(&VERSION.to_le_bytes());
                let kind: u16 = match target {
                    TcpTarget::Peer(_) => 1,
                    TcpTarget::HostService(_) => 2,
                };
                frame.extend_from_slice(&kind.to_le_bytes());
                frame.extend_from_slice(&u16::from(*inline_urgent).to_le_bytes());
                frame.extend_from_slice(&0_u16.to_le_bytes());
                match target {
                    TcpTarget::Peer(peer) => encode_peer(&mut frame, *peer)?,
                    TcpTarget::HostService(0) => return Err(ErrorCode::InvalidFrame),
                    TcpTarget::HostService(port) => {
                        frame.extend_from_slice(&port.to_le_bytes());
                        frame.extend_from_slice(&0_u16.to_le_bytes());
                    }
                }
            }
            Self::TcpOpened(outcome) => {
                append_status(&mut frame, outcome.as_ref().err().copied());
                if let Ok(peer) = outcome {
                    encode_peer(&mut frame, *peer)?;
                }
            }
            Self::UdpOpen | Self::Hello | Self::Ready => {
                frame.extend_from_slice(&VERSION.to_le_bytes());
                frame.extend_from_slice(&0_u16.to_le_bytes());
            }
            Self::UdpOpened(outcome) => append_status(&mut frame, outcome.err()),
            Self::UdpSend { peer, bytes } | Self::UdpDatagram { peer, bytes } => {
                encode_peer(&mut frame, *peer)?;
                frame.extend_from_slice(datagram(bytes)?);
            }
            Self::UdpError { peer, error } => {
                append_status(&mut frame, Some(*error));
                encode_peer(&mut frame, *peer)?;
            }
            Self::DnsQuery { id, stream, bytes } | Self::DnsResult { id, stream, bytes } => {
                frame.extend_from_slice(&id.to_le_bytes());
                frame.extend_from_slice(&u16::from(*stream).to_le_bytes());
                frame.extend_from_slice(&0_u16.to_le_bytes());
                frame.extend_from_slice(dns(bytes, *stream)?);
            }
            Self::Publication { guest_port, .. } | Self::PublicationUdp { guest_port } => {
                if *guest_port == 0 {
                    return Err(ErrorCode::InvalidFrame);
                }
                frame.extend_from_slice(&VERSION.to_le_bytes());
                frame.extend_from_slice(&guest_port.to_le_bytes());
                if let Self::Publication { peer, .. } = self {
                    encode_peer(&mut frame, *peer)?;
                }
            }
        }
        let length =
            u32::try_from(frame.len() - HEADER_BYTES).map_err(|_| ErrorCode::LimitExceeded)?;
        frame[..2].copy_from_slice(&(self.opcode() as u16).to_le_bytes());
        frame[4..HEADER_BYTES].copy_from_slice(&length.to_le_bytes());
        Ok(frame)
    }

    /// Return the next complete frame and its encoded length, or `Ok(None)` while more bytes are needed.
    pub fn decode(bytes: &[u8], direction: Direction) -> Result<Option<(Self, usize)>, ErrorCode> {
        let Some(header) = bytes.get(..HEADER_BYTES) else {
            return Ok(None);
        };
        let opcode = Opcode::try_from(u16::from_le_bytes([header[0], header[1]]))?;
        if header[2..4] != [0, 0] {
            return Err(ErrorCode::InvalidFrame);
        }
        if opcode.direction() != direction {
            return Err(ErrorCode::WrongDirection);
        }
        let length = usize::try_from(u32::from_le_bytes([
            header[4], header[5], header[6], header[7],
        ]))
        .map_err(|_| ErrorCode::LimitExceeded)?;
        if length > MAX_PAYLOAD_BYTES {
            return Err(ErrorCode::LimitExceeded);
        }
        let Some(payload) = bytes.get(HEADER_BYTES..HEADER_BYTES + length) else {
            return Ok(None);
        };
        Ok(Some((
            Self::decode_payload(opcode, payload)?,
            HEADER_BYTES + length,
        )))
    }

    fn decode_payload(opcode: Opcode, payload: &[u8]) -> Result<Self, ErrorCode> {
        let mut body = Body(payload);
        let message = match opcode {
            Opcode::TcpOpen => {
                body.version()?;
                let kind = body.u16()?;
                let flags = body.u16()?;
                if flags > 1 || body.u16()? != 0 {
                    return Err(ErrorCode::InvalidFrame);
                }
                let target = match kind {
                    1 => TcpTarget::Peer(body.peer()?),
                    2 => {
                        let port = body.u16()?;
                        if port == 0 || body.u16()? != 0 {
                            return Err(ErrorCode::InvalidFrame);
                        }
                        TcpTarget::HostService(port)
                    }
                    _ => return Err(ErrorCode::InvalidFrame),
                };
                Self::TcpOpen {
                    target,
                    inline_urgent: flags != 0,
                }
            }
            Opcode::TcpOpened => Self::TcpOpened(match body.status()? {
                Some(error) => Err(error),
                None => Ok(body.peer()?),
            }),
            Opcode::UdpOpen | Opcode::Hello | Opcode::Ready => {
                body.version()?;
                if body.u16()? != 0 {
                    return Err(ErrorCode::InvalidFrame);
                }
                match opcode {
                    Opcode::UdpOpen => Self::UdpOpen,
                    Opcode::Hello => Self::Hello,
                    _ => Self::Ready,
                }
            }
            Opcode::UdpOpened => Self::UdpOpened(body.status()?.map_or(Ok(()), Err)),
            Opcode::UdpSend | Opcode::UdpDatagram => {
                let peer = body.peer()?;
                let bytes = datagram(body.remaining())?.to_vec();
                if opcode == Opcode::UdpSend {
                    Self::UdpSend { peer, bytes }
                } else {
                    Self::UdpDatagram { peer, bytes }
                }
            }
            Opcode::UdpError => {
                let error = body.status()?.ok_or(ErrorCode::InvalidFrame)?;
                Self::UdpError {
                    peer: body.peer()?,
                    error,
                }
            }
            Opcode::DnsQuery | Opcode::DnsResult => {
                let id = body.u32()?;
                let flags = body.u16()?;
                if flags > 1 || body.u16()? != 0 {
                    return Err(ErrorCode::InvalidFrame);
                }
                let stream = flags != 0;
                let bytes = dns(body.remaining(), stream)?.to_vec();
                if opcode == Opcode::DnsQuery {
                    Self::DnsQuery { id, stream, bytes }
                } else {
                    Self::DnsResult { id, stream, bytes }
                }
            }
            Opcode::Publication | Opcode::PublicationUdp => {
                body.version()?;
                let guest_port = body.u16()?;
                if guest_port == 0 {
                    return Err(ErrorCode::InvalidFrame);
                }
                if opcode == Opcode::Publication {
                    Self::Publication {
                        guest_port,
                        peer: body.peer()?,
                    }
                } else {
                    Self::PublicationUdp { guest_port }
                }
            }
        };
        body.finish()?;
        Ok(message)
    }
}

/// Bounded reassembly for frame streams whose reads may split or combine frames.
#[derive(Default)]
pub struct StreamDecoder {
    bytes: Vec<u8>,
}

impl StreamDecoder {
    #[must_use]
    pub fn remaining_capacity(&self) -> usize {
        MAX_FRAME_BYTES.saturating_sub(self.bytes.len())
    }

    pub fn push(&mut self, bytes: &[u8]) -> Result<(), ErrorCode> {
        if bytes.len() > self.remaining_capacity() {
            return Err(ErrorCode::LimitExceeded);
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    pub fn next(&mut self, direction: Direction) -> Result<Option<Message>, ErrorCode> {
        let Some((message, length)) = Message::decode(&self.bytes, direction)? else {
            return Ok(None);
        };
        self.bytes.drain(..length);
        Ok(Some(message))
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

fn encode_peer(frame: &mut Vec<u8>, peer: SocketAddr) -> Result<(), ErrorCode> {
    match peer {
        SocketAddr::V4(peer) => {
            frame.extend_from_slice(&[4, 0]);
            frame.extend_from_slice(&peer.port().to_le_bytes());
            frame.extend_from_slice(&peer.ip().octets());
            frame.extend_from_slice(&[0; 12]);
        }
        SocketAddr::V6(peer) => {
            if peer.flowinfo() != 0 || peer.scope_id() != 0 {
                return Err(ErrorCode::InvalidFrame);
            }
            frame.extend_from_slice(&[6, 0]);
            frame.extend_from_slice(&peer.port().to_le_bytes());
            frame.extend_from_slice(&peer.ip().octets());
        }
    }
    Ok(())
}

fn decode_peer(bytes: &[u8; ENDPOINT_BYTES]) -> Result<SocketAddr, ErrorCode> {
    if bytes[1] != 0 {
        return Err(ErrorCode::InvalidFrame);
    }
    let port = u16::from_le_bytes([bytes[2], bytes[3]]);
    let address = match bytes[0] {
        4 if bytes[8..] == [0; 12] => {
            IpAddr::V4(Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]))
        }
        6 => IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(&bytes[4..]).map_err(|_| ErrorCode::InvalidFrame)?,
        )),
        _ => return Err(ErrorCode::InvalidFrame),
    };
    Ok(SocketAddr::new(address, port))
}

fn append_status(body: &mut Vec<u8>, error: Option<ProtocolError>) {
    body.extend_from_slice(&error.map_or(0, |error| error as u16).to_le_bytes());
    body.extend_from_slice(&0_u16.to_le_bytes());
}

fn datagram(bytes: &[u8]) -> Result<&[u8], ErrorCode> {
    if bytes.len() > socket::MAX_DATAGRAM_BYTES {
        return Err(ErrorCode::LimitExceeded);
    }
    Ok(bytes)
}

fn dns(bytes: &[u8], stream: bool) -> Result<&[u8], ErrorCode> {
    if bytes.is_empty() || bytes.len() > socket::MAX_DNS_BYTES + usize::from(stream) * 2 {
        return Err(ErrorCode::LimitExceeded);
    }
    if stream
        && (bytes.len() < 3
            || usize::from(u16::from_be_bytes([bytes[0], bytes[1]])) != bytes.len() - 2)
    {
        return Err(ErrorCode::InvalidFrame);
    }
    Ok(bytes)
}

struct Body<'a>(&'a [u8]);

impl<'a> Body<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], ErrorCode> {
        let bytes = self.0.get(..length).ok_or(ErrorCode::InvalidFrame)?;
        self.0 = &self.0[length..];
        Ok(bytes)
    }
    fn u16(&mut self) -> Result<u16, ErrorCode> {
        let bytes = self.take(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }
    fn u32(&mut self) -> Result<u32, ErrorCode> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
    fn version(&mut self) -> Result<(), ErrorCode> {
        if self.u16()? == VERSION {
            Ok(())
        } else {
            Err(ErrorCode::UnsupportedVersion)
        }
    }
    fn peer(&mut self) -> Result<SocketAddr, ErrorCode> {
        let bytes = <&[u8; ENDPOINT_BYTES]>::try_from(self.take(ENDPOINT_BYTES)?)
            .map_err(|_| ErrorCode::InvalidFrame)?;
        decode_peer(bytes)
    }
    fn status(&mut self) -> Result<Option<ProtocolError>, ErrorCode> {
        let status = self.u16()?;
        if self.u16()? != 0 {
            return Err(ErrorCode::InvalidFrame);
        }
        if status == 0 {
            return Ok(None);
        }
        ProtocolError::decode(u64::from(status))
            .map(Some)
            .ok_or(ErrorCode::InvalidFrame)
    }
    fn remaining(&mut self) -> &'a [u8] {
        std::mem::take(&mut self.0)
    }
    fn finish(self) -> Result<(), ErrorCode> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(ErrorCode::InvalidFrame)
        }
    }
}

const _: () = assert!(HEADER_BYTES + 8 + ENDPOINT_BYTES <= MAX_OPENING_BYTES);
const _: () = assert!(HEADER_BYTES + STATUS_BYTES + ENDPOINT_BYTES <= MAX_OPENING_BYTES);

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn round_trip(message: &Message) {
        let bytes = message.encode().unwrap();
        let direction = message.opcode().direction();
        assert_eq!(
            Message::decode(&bytes, direction).unwrap(),
            Some((message.clone(), bytes.len()))
        );
        let other = if direction == Direction::GuestToHost {
            Direction::HostToGuest
        } else {
            Direction::GuestToHost
        };
        assert_eq!(
            Message::decode(&bytes, other),
            Err(ErrorCode::WrongDirection)
        );
        for length in 0..bytes.len() {
            assert_eq!(Message::decode(&bytes[..length], direction), Ok(None));
        }
        let mut trailing = bytes.clone();
        trailing[4] = trailing[4].wrapping_add(1);
        trailing.push(0);
        assert_ne!(
            Message::decode(&trailing, direction)
                .ok()
                .flatten()
                .map(|(decoded, _)| decoded),
            Some(message.clone())
        );
    }

    #[test]
    fn endpoints_pin_address_layout_and_reject_native_only_fields() {
        let ipv4: SocketAddr = "203.0.113.1:443".parse().unwrap();
        let mut bytes = Vec::new();
        encode_peer(&mut bytes, ipv4).unwrap();
        assert_eq!(
            bytes,
            [
                4, 0, 0xbb, 1, 203, 0, 113, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );
        let decode =
            |bytes: &[u8]| decode_peer(bytes.try_into().map_err(|_| ErrorCode::InvalidFrame)?);
        assert_eq!(decode(&bytes), Ok(ipv4));
        for peer in [ipv4, "[2001:db8::1]:53".parse().unwrap()] {
            let mut encoded = Vec::new();
            encode_peer(&mut encoded, peer).unwrap();
            assert_eq!(decode(&encoded), Ok(peer));
        }
        for (offset, value) in [(0, 5), (1, 1), (8, 1)] {
            let mut malformed = bytes.clone();
            malformed[offset] = value;
            assert_eq!(decode(&malformed), Err(ErrorCode::InvalidFrame));
        }
        for length in 0..ENDPOINT_BYTES {
            assert!(decode(&bytes[..length]).is_err());
        }
        let mut scratch = Vec::new();
        assert!(encode_peer(&mut scratch, "[fe80::1%1]:53".parse().unwrap()).is_err());
        let flowinfo = std::net::SocketAddrV6::new(Ipv6Addr::LOCALHOST, 53, 1, 0);
        assert!(encode_peer(&mut scratch, SocketAddr::V6(flowinfo)).is_err());
    }

    #[test]
    fn udp_datagram_wire_layout_pins_header_endpoint_and_payload() {
        let frame = Message::UdpDatagram {
            peer: "192.0.2.1:48879".parse().unwrap(),
            bytes: vec![0xaa, 0xbb],
        }
        .encode()
        .unwrap();
        assert_eq!(
            frame,
            [
                0x03, 0x01, 0, 0, 22, 0, 0, 0, 4, 0, 0xef, 0xbe, 192, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0xaa, 0xbb,
            ]
        );
    }

    #[test]
    fn every_frame_round_trips_and_rejects_the_wrong_direction() {
        let peer: SocketAddr = "[2001:db8::1]:53".parse().unwrap();
        for message in [
            Message::TcpOpen {
                target: TcpTarget::Peer(peer),
                inline_urgent: true,
            },
            Message::TcpOpen {
                target: TcpTarget::HostService(443),
                inline_urgent: false,
            },
            Message::TcpOpened(Ok(peer)),
            Message::TcpOpened(Err(ProtocolError::AccessDenied)),
            Message::UdpOpen,
            Message::UdpOpened(Ok(())),
            Message::UdpOpened(Err(ProtocolError::LimitExceeded)),
            Message::UdpSend {
                peer,
                bytes: vec![42; socket::MAX_DATAGRAM_BYTES],
            },
            Message::UdpDatagram {
                peer,
                bytes: Vec::new(),
            },
            Message::UdpError {
                peer,
                error: ProtocolError::ConnectionRefused,
            },
            Message::Hello,
            Message::Ready,
            Message::DnsQuery {
                id: 7,
                stream: false,
                bytes: vec![1; socket::MAX_DNS_BYTES],
            },
            Message::DnsResult {
                id: u32::MAX,
                stream: true,
                bytes: vec![0, 1, 42],
            },
            Message::Publication {
                guest_port: 80,
                peer,
            },
            Message::PublicationUdp { guest_port: 53 },
        ] {
            round_trip(&message);
        }
    }

    #[test]
    fn tcp_opening_pins_layout_and_fits_the_opening_bound() {
        let peer: SocketAddr = "203.0.113.1:443".parse().unwrap();
        let bytes = Message::TcpOpen {
            target: TcpTarget::Peer(peer),
            inline_urgent: true,
        }
        .encode()
        .unwrap();
        assert_eq!(
            bytes,
            [
                1, 0, 0, 0, 28, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 4, 0, 0xbb, 1, 203, 0, 113, 1, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );
        assert!(bytes.len() <= MAX_OPENING_BYTES);
        let opened = Message::TcpOpened(Ok(peer)).encode().unwrap();
        assert_eq!(opened.len(), 32);
        assert!(opened.len() <= MAX_OPENING_BYTES);
        assert_eq!(
            Message::TcpOpened(Err(ProtocolError::TimedOut))
                .encode()
                .unwrap()
                .len(),
            12
        );
        for (offset, value) in [(2, 1), (8, 4), (10, 3), (12, 2), (14, 1)] {
            let mut forged = bytes.clone();
            forged[offset] = value;
            assert!(Message::decode(&forged, Direction::GuestToHost).is_err());
        }
        let mut stale = bytes;
        stale[8] = 4;
        assert_eq!(
            Message::decode(&stale, Direction::GuestToHost),
            Err(ErrorCode::UnsupportedVersion)
        );
    }

    #[test]
    fn udp_publication_opening_pins_version_port_and_direction() {
        let frame = Message::PublicationUdp { guest_port: 53 }.encode().unwrap();
        assert_eq!(frame, [8, 1, 0, 0, 4, 0, 0, 0, 1, 0, 53, 0]);
        assert!(frame.len() <= MAX_OPENING_BYTES);
        for version in [0, VERSION - 1, VERSION + 1] {
            let mut stale = frame.clone();
            stale[8..10].copy_from_slice(&version.to_le_bytes());
            assert_eq!(
                Message::decode(&stale, Direction::HostToGuest),
                Err(ErrorCode::UnsupportedVersion)
            );
        }
        assert!(Message::PublicationUdp { guest_port: 0 }.encode().is_err());
        let mut invalid = frame;
        invalid[10..12].fill(0);
        assert_eq!(
            Message::decode(&invalid, Direction::HostToGuest),
            Err(ErrorCode::InvalidFrame)
        );
    }

    #[test]
    fn hostile_lengths_and_payloads_are_rejected() {
        let mut oversized = Message::Hello.encode().unwrap();
        oversized[4..8]
            .copy_from_slice(&u32::try_from(MAX_PAYLOAD_BYTES + 1).unwrap().to_le_bytes());
        assert_eq!(
            Message::decode(&oversized, Direction::GuestToHost),
            Err(ErrorCode::LimitExceeded)
        );
        assert_eq!(
            Message::decode(&[0xff, 0xff, 0, 0, 0, 0, 0, 0], Direction::GuestToHost),
            Err(ErrorCode::UnknownOpcode)
        );
        assert!(
            Message::UdpSend {
                peer: "127.0.0.1:1".parse().unwrap(),
                bytes: vec![0; socket::MAX_DATAGRAM_BYTES + 1],
            }
            .encode()
            .is_err()
        );
        assert!(
            Message::DnsQuery {
                id: 1,
                stream: true,
                bytes: vec![0, 5, 1],
            }
            .encode()
            .is_err()
        );
        let error = Message::UdpError {
            peer: "127.0.0.1:1".parse().unwrap(),
            error: ProtocolError::Closed,
        }
        .encode()
        .unwrap();
        for (offset, value) in [(8, 0), (8, 21), (10, 1)] {
            let mut forged = error.clone();
            forged[offset] = value;
            forged[offset + 1] = 0;
            assert!(Message::decode(&forged, Direction::HostToGuest).is_err());
        }
    }

    #[test]
    fn stream_decoder_handles_split_coalesced_and_hostile_frames_with_bounded_storage() {
        let first = Message::UdpDatagram {
            peer: "127.0.0.1:9".parse().unwrap(),
            bytes: b"first".to_vec(),
        };
        let second = Message::UdpError {
            peer: "127.0.0.1:9".parse().unwrap(),
            error: ProtocolError::ConnectionRefused,
        };
        let mut bytes = first.encode().unwrap();
        bytes.extend_from_slice(&second.encode().unwrap());
        for split in 0..bytes.len() {
            let mut decoder = StreamDecoder::default();
            decoder.push(&bytes[..split]).unwrap();
            let mut messages = Vec::new();
            while let Some(message) = decoder.next(Direction::HostToGuest).unwrap() {
                messages.push(message);
            }
            decoder.push(&bytes[split..]).unwrap();
            while let Some(message) = decoder.next(Direction::HostToGuest).unwrap() {
                messages.push(message);
            }
            assert_eq!(messages, [first.clone(), second.clone()]);
            assert!(decoder.is_empty());
        }
        let mut decoder = StreamDecoder::default();
        assert!(decoder.push(&vec![0; MAX_FRAME_BYTES + 1]).is_err());
    }
}
