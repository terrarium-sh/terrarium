//! Frames for per-socket TCP/UDP streams, network control, and publication headers.

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use serde::{Deserialize, Serialize};

use crate::socket::{self, Error as ProtocolError};

pub const VERSION: u16 = 1;
pub const HEADER_BYTES: usize = 8;
const DNS_PREFIX_BYTES: usize = 8;
const STATUS_BYTES: usize = 4;
pub(crate) const ENDPOINT_BYTES: usize = 20;
pub const MAX_PAYLOAD_BYTES: usize = ENDPOINT_BYTES + socket::MAX_DATAGRAM_BYTES;
pub const MAX_FRAME_BYTES: usize = HEADER_BYTES + MAX_PAYLOAD_BYTES;
pub(crate) const UDP_SEGMENT_HEADER_BYTES: usize = 4;
/// Segments one UDP frame may carry, matching the kernel's UDP GSO and GRO limit.
pub const MAX_DATAGRAM_SEGMENTS: usize = 64;
/// Largest UDP frame: the guest carrier buffer and the host flow upstream buffer are both this size.
pub const MAX_UDP_FRAME_BYTES: usize = 64 * 1024;
/// Largest datagram run one UDP frame can carry.
pub const MAX_UDP_RUN_BYTES: usize =
    MAX_UDP_FRAME_BYTES - HEADER_BYTES - ENDPOINT_BYTES - UDP_SEGMENT_HEADER_BYTES;
const MAX_UDP_PAYLOAD_BYTES: usize = MAX_UDP_FRAME_BYTES - HEADER_BYTES;
const _: () = assert!(MAX_UDP_FRAME_BYTES == crate::vsock::FLOW_UPSTREAM_BYTES);
const _: () = assert!(MAX_UDP_FRAME_BYTES <= crate::vsock::FLOW_REPLY_BYTES);
pub const MAX_OPENING_BYTES: usize = 64;
pub const OPEN_TIMEOUT_SECS: u64 = 30;
/// Concurrent DNS queries the agent may have outstanding on the control stream.
pub const MAX_DNS_QUERIES: usize = 16;
/// Linux `MAX_TCP_KEEPIDLE` and `MAX_TCP_KEEPINTVL`, in seconds.
pub const MAX_KEEPALIVE_SECS: u16 = 32767;
/// Linux `MAX_TCP_KEEPCNT`.
pub const MAX_KEEPALIVE_PROBES: u16 = 127;
const TCP_OPEN_INLINE_URGENT_FLAG: u16 = 1;
const TCP_OPEN_KEEPALIVE_FLAG: u16 = 2;
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

    const fn max_payload_bytes(self) -> usize {
        match self {
            Self::UdpSend | Self::UdpDatagram => MAX_UDP_PAYLOAD_BYTES,
            Self::TcpOpen
            | Self::UdpOpen
            | Self::Hello
            | Self::DnsQuery
            | Self::TcpOpened
            | Self::UdpOpened
            | Self::UdpError
            | Self::Ready
            | Self::DnsResult
            | Self::Publication
            | Self::PublicationUdp => MAX_PAYLOAD_BYTES,
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

/// Guest-chosen TCP keepalive; construction and deserialization enforce the Linux limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "TcpKeepaliveFields")]
pub struct TcpKeepalive {
    idle_secs: u16,
    interval_secs: u16,
    probe_count: u16,
}

#[derive(Deserialize)]
struct TcpKeepaliveFields {
    idle_secs: u16,
    interval_secs: u16,
    probe_count: u16,
}

impl TryFrom<TcpKeepaliveFields> for TcpKeepalive {
    type Error = &'static str;
    fn try_from(fields: TcpKeepaliveFields) -> Result<Self, Self::Error> {
        Self::new(fields.idle_secs, fields.interval_secs, fields.probe_count)
            .ok_or("keepalive timing out of range")
    }
}

impl TcpKeepalive {
    #[must_use]
    pub fn new(idle_secs: u16, interval_secs: u16, probe_count: u16) -> Option<Self> {
        let is_valid = (1..=MAX_KEEPALIVE_SECS).contains(&idle_secs)
            && (1..=MAX_KEEPALIVE_SECS).contains(&interval_secs)
            && (1..=MAX_KEEPALIVE_PROBES).contains(&probe_count);
        is_valid.then_some(Self {
            idle_secs,
            interval_secs,
            probe_count,
        })
    }

    #[must_use]
    pub fn idle_secs(self) -> u16 {
        self.idle_secs
    }

    #[must_use]
    pub fn interval_secs(self) -> u16 {
        self.interval_secs
    }

    #[must_use]
    pub fn probe_count(self) -> u16 {
        self.probe_count
    }
}

/// Socket options the guest chose before `connect`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpOpenOptions {
    pub inline_urgent: bool,
    pub keepalive: Option<TcpKeepalive>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpTarget {
    Peer(SocketAddr),
    HostService(u16),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    TcpOpen {
        target: TcpTarget,
        options: TcpOpenOptions,
    },
    TcpOpened(Result<SocketAddr, ProtocolError>),
    UdpOpen,
    UdpOpened(Result<(), ProtocolError>),
    /// One datagram when `segment` is 0, else equal `segment`-byte datagrams, the last possibly shorter.
    UdpSend {
        peer: SocketAddr,
        segment: u16,
        bytes: Vec<u8>,
    },
    UdpDatagram {
        peer: SocketAddr,
        segment: u16,
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
            Self::TcpOpen { target, options } => {
                frame.extend_from_slice(&VERSION.to_le_bytes());
                let kind: u16 = match target {
                    TcpTarget::Peer(_) => 1,
                    TcpTarget::HostService(_) => 2,
                };
                frame.extend_from_slice(&kind.to_le_bytes());
                let mut flags = 0;
                if options.inline_urgent {
                    flags |= TCP_OPEN_INLINE_URGENT_FLAG;
                }
                let (probe_count, idle_secs, interval_secs) = match options.keepalive {
                    Some(keepalive) => {
                        flags |= TCP_OPEN_KEEPALIVE_FLAG;
                        (
                            keepalive.probe_count,
                            keepalive.idle_secs,
                            keepalive.interval_secs,
                        )
                    }
                    None => (0, 0, 0),
                };
                frame.extend_from_slice(&flags.to_le_bytes());
                for field in [probe_count, idle_secs, interval_secs] {
                    frame.extend_from_slice(&field.to_le_bytes());
                }
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
            Self::UdpSend {
                peer,
                segment,
                bytes,
            }
            | Self::UdpDatagram {
                peer,
                segment,
                bytes,
            } => append_udp_body(&mut frame, *peer, *segment, bytes)?,
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
        seal_frame(&mut frame, self.opcode())?;
        Ok(frame)
    }

    /// Return the next complete frame and its encoded length, or `Ok(None)` while more bytes are needed.
    pub fn decode(bytes: &[u8], direction: Direction) -> Result<Option<(Self, usize)>, ErrorCode> {
        let Some(frame) = split_frame(bytes, direction, None)? else {
            return Ok(None);
        };
        Ok(Some((
            Self::decode_payload(frame.opcode, frame.payload)?,
            frame.frame_bytes,
        )))
    }

    fn decode_payload(opcode: Opcode, payload: &[u8]) -> Result<Self, ErrorCode> {
        let mut body = Body(payload);
        let message = match opcode {
            Opcode::TcpOpen => decode_tcp_open(&mut body)?,
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
                let (peer, segment, bytes) = udp_body(&mut body)?;
                let bytes = bytes.to_vec();
                if opcode == Opcode::UdpSend {
                    Self::UdpSend {
                        peer,
                        segment,
                        bytes,
                    }
                } else {
                    Self::UdpDatagram {
                        peer,
                        segment,
                        bytes,
                    }
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

struct SplitFrame<'a> {
    opcode: Opcode,
    payload: &'a [u8],
    frame_bytes: usize,
}

/// A guest UDP send frame; `segment` is 0 for a single datagram.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UdpSendFrame<'a> {
    pub peer: SocketAddr,
    pub segment: u16,
    pub bytes: &'a [u8],
    pub frame_bytes: usize,
}

/// Splits off the next complete frame; `Ok(None)` while more bytes are needed. With `only`, any
/// other opcode is rejected as soon as its header is whole.
fn split_frame<'a>(
    bytes: &'a [u8],
    direction: Direction,
    only: Option<&[Opcode]>,
) -> Result<Option<SplitFrame<'a>>, ErrorCode> {
    let Some(header) = bytes.first_chunk::<HEADER_BYTES>() else {
        return Ok(None);
    };
    let opcode = Opcode::try_from(u16::from_le_bytes([header[0], header[1]]))?;
    if header[2..4] != [0, 0] {
        return Err(ErrorCode::InvalidFrame);
    }
    if opcode.direction() != direction {
        return Err(ErrorCode::WrongDirection);
    }
    if only.is_some_and(|only| !only.contains(&opcode)) {
        return Err(ErrorCode::InvalidFrame);
    }
    let length = decode_payload_length(header)?;
    if length > opcode.max_payload_bytes() {
        return Err(ErrorCode::LimitExceeded);
    }
    Ok(bytes
        .get(HEADER_BYTES..HEADER_BYTES + length)
        .map(|payload| SplitFrame {
            opcode,
            payload,
            frame_bytes: HEADER_BYTES + length,
        }))
}

/// Reads the payload length a frame header declares, without checking it against any limit.
pub fn decode_payload_length(header: &[u8; HEADER_BYTES]) -> Result<usize, ErrorCode> {
    usize::try_from(u32::from_le_bytes([
        header[4], header[5], header[6], header[7],
    ]))
    .map_err(|_| ErrorCode::LimitExceeded)
}

/// Borrowed [`Message::decode`] of a guest `UdpSend` frame; any other frame is an error.
pub fn decode_udp_send(bytes: &[u8]) -> Result<Option<UdpSendFrame<'_>>, ErrorCode> {
    let Some(frame) = split_frame(bytes, Direction::GuestToHost, Some(&[Opcode::UdpSend]))? else {
        return Ok(None);
    };
    let (peer, segment, bytes) = udp_body(&mut Body(frame.payload))?;
    Ok(Some(UdpSendFrame {
        peer,
        segment,
        bytes,
        frame_bytes: frame.frame_bytes,
    }))
}

/// Appends one host-to-guest `UdpDatagram` frame to `out`, leaving `out` unchanged on error.
pub fn append_udp_datagram(
    out: &mut Vec<u8>,
    peer: SocketAddr,
    segment: u16,
    bytes: &[u8],
) -> Result<(), ErrorCode> {
    let start = out.len();
    out.resize(start + HEADER_BYTES, 0);
    let sealed = append_udp_body(out, peer, segment, bytes)
        .and_then(|()| seal_frame(&mut out[start..], Opcode::UdpDatagram));
    if sealed.is_err() {
        out.truncate(start);
    }
    sealed
}

/// Appends endpoint, segment field and data. A `segment` that does not split `bytes` into more
/// than one datagram is written as 0, so every datagram has one encoding.
fn append_udp_body(
    frame: &mut Vec<u8>,
    peer: SocketAddr,
    segment: u16,
    bytes: &[u8],
) -> Result<(), ErrorCode> {
    let segment = if bytes.len() > usize::from(segment) {
        segment
    } else {
        0
    };
    let data = udp_data(bytes, segment)?;
    encode_peer(frame, peer)?;
    frame.extend_from_slice(&segment.to_le_bytes());
    frame.extend_from_slice(&0_u16.to_le_bytes());
    frame.extend_from_slice(data);
    Ok(())
}

fn udp_body<'a>(body: &mut Body<'a>) -> Result<(SocketAddr, u16, &'a [u8]), ErrorCode> {
    let peer = body.peer()?;
    let segment = body.u16()?;
    if body.u16()? != 0 {
        return Err(ErrorCode::InvalidFrame);
    }
    Ok((peer, segment, udp_data(body.remaining(), segment)?))
}

fn udp_data(bytes: &[u8], segment: u16) -> Result<&[u8], ErrorCode> {
    if segment == 0 {
        datagram(bytes)
    } else {
        segmented(bytes, segment)
    }
}

/// Fills the opcode and payload length of the frame that starts at `frame[0]`.
fn seal_frame(frame: &mut [u8], opcode: Opcode) -> Result<(), ErrorCode> {
    let length = u32::try_from(frame.len() - HEADER_BYTES).map_err(|_| ErrorCode::LimitExceeded)?;
    frame[..2].copy_from_slice(&(opcode as u16).to_le_bytes());
    frame[4..HEADER_BYTES].copy_from_slice(&length.to_le_bytes());
    Ok(())
}

/// Bounded reassembly for frame streams whose reads may split or combine frames.
#[derive(Default)]
pub struct StreamDecoder {
    bytes: Vec<u8>,
}

impl StreamDecoder {
    #[must_use]
    pub fn remaining_capacity(&self) -> usize {
        MAX_UDP_FRAME_BYTES.saturating_sub(self.bytes.len())
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

/// Whether `length` bytes split into `segment`-byte datagrams, the last possibly shorter, that
/// fit one UDP frame.
#[must_use]
pub const fn is_valid_segmented_run(length: usize, segment: usize) -> bool {
    segment >= 1
        && segment <= socket::MAX_DATAGRAM_BYTES
        && length > segment
        && length <= MAX_UDP_RUN_BYTES
        && length.div_ceil(segment) <= MAX_DATAGRAM_SEGMENTS
}

fn segmented(bytes: &[u8], segment: u16) -> Result<&[u8], ErrorCode> {
    if is_valid_segmented_run(bytes.len(), usize::from(segment)) {
        Ok(bytes)
    } else {
        Err(ErrorCode::InvalidFrame)
    }
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

fn decode_tcp_open(body: &mut Body<'_>) -> Result<Message, ErrorCode> {
    body.version()?;
    let kind = body.u16()?;
    let flags = body.u16()?;
    if flags & !(TCP_OPEN_INLINE_URGENT_FLAG | TCP_OPEN_KEEPALIVE_FLAG) != 0 {
        return Err(ErrorCode::InvalidFrame);
    }
    let (probe_count, idle_secs, interval_secs) = (body.u16()?, body.u16()?, body.u16()?);
    let keepalive = if flags & TCP_OPEN_KEEPALIVE_FLAG == 0 {
        if probe_count | idle_secs | interval_secs != 0 {
            return Err(ErrorCode::InvalidFrame);
        }
        None
    } else {
        Some(
            TcpKeepalive::new(idle_secs, interval_secs, probe_count)
                .ok_or(ErrorCode::InvalidFrame)?,
        )
    };
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
    Ok(Message::TcpOpen {
        target,
        options: TcpOpenOptions {
            inline_urgent: flags & TCP_OPEN_INLINE_URGENT_FLAG != 0,
            keepalive,
        },
    })
}

const _: () = assert!(HEADER_BYTES + 12 + ENDPOINT_BYTES <= MAX_OPENING_BYTES);
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
            segment: 0,
            peer: "192.0.2.1:48879".parse().unwrap(),
            bytes: vec![0xaa, 0xbb],
        }
        .encode()
        .unwrap();
        assert_eq!(
            frame,
            [
                0x03, 0x01, 0, 0, 26, 0, 0, 0, 4, 0, 0xef, 0xbe, 192, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0xaa, 0xbb,
            ]
        );
    }

    #[test]
    fn every_frame_round_trips_and_rejects_the_wrong_direction() {
        let peer: SocketAddr = "[2001:db8::1]:53".parse().unwrap();
        for message in [
            Message::TcpOpen {
                target: TcpTarget::Peer(peer),
                options: TcpOpenOptions {
                    inline_urgent: true,
                    keepalive: TcpKeepalive::new(60, 15, 9),
                },
            },
            Message::TcpOpen {
                target: TcpTarget::Peer(peer),
                options: TcpOpenOptions::default(),
            },
            Message::TcpOpen {
                target: TcpTarget::HostService(443),
                options: TcpOpenOptions {
                    inline_urgent: false,
                    keepalive: TcpKeepalive::new(MAX_KEEPALIVE_SECS, 1, MAX_KEEPALIVE_PROBES),
                },
            },
            Message::TcpOpen {
                target: TcpTarget::HostService(443),
                options: TcpOpenOptions::default(),
            },
            Message::TcpOpened(Ok(peer)),
            Message::TcpOpened(Err(ProtocolError::AccessDenied)),
            Message::UdpOpen,
            Message::UdpOpened(Ok(())),
            Message::UdpOpened(Err(ProtocolError::LimitExceeded)),
            Message::UdpSend {
                segment: 0,
                peer,
                bytes: vec![42; socket::MAX_DATAGRAM_BYTES],
            },
            Message::UdpDatagram {
                segment: 0,
                peer,
                bytes: Vec::new(),
            },
            Message::UdpSend {
                peer,
                segment: 1024,
                bytes: vec![1; MAX_UDP_RUN_BYTES],
            },
            Message::UdpDatagram {
                peer,
                segment: 1,
                bytes: vec![2; 64],
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
            options: TcpOpenOptions {
                inline_urgent: true,
                keepalive: TcpKeepalive::new(60, 15, 9),
            },
        }
        .encode()
        .unwrap();
        assert_eq!(
            bytes,
            [
                1, 0, 0, 0, 32, 0, 0, 0, 1, 0, 1, 0, 3, 0, 9, 0, 60, 0, 15, 0, 4, 0, 0xbb, 1, 203,
                0, 113, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );
        let service = Message::TcpOpen {
            target: TcpTarget::HostService(443),
            options: TcpOpenOptions::default(),
        }
        .encode()
        .unwrap();
        assert_eq!(
            service,
            [
                1, 0, 0, 0, 16, 0, 0, 0, 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbb, 1, 0, 0
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
        for (offset, value) in [
            (2, 1),
            (8, 4),
            (10, 3),
            (12, 4),
            (12, 8),
            (14, 0),
            (16, 0),
            (18, 0),
        ] {
            let mut forged = bytes.clone();
            forged[offset] = value;
            assert!(Message::decode(&forged, Direction::GuestToHost).is_err());
        }
        let mut forged = bytes.clone();
        forged[18..20].copy_from_slice(&(MAX_KEEPALIVE_SECS + 1).to_le_bytes());
        assert_eq!(
            Message::decode(&forged, Direction::GuestToHost),
            Err(ErrorCode::InvalidFrame)
        );
        let mut forged = bytes.clone();
        forged[14..16].copy_from_slice(&(MAX_KEEPALIVE_PROBES + 1).to_le_bytes());
        assert_eq!(
            Message::decode(&forged, Direction::GuestToHost),
            Err(ErrorCode::InvalidFrame)
        );
        let mut without_flag = bytes.clone();
        without_flag[12] = 1;
        assert_eq!(
            Message::decode(&without_flag, Direction::GuestToHost),
            Err(ErrorCode::InvalidFrame)
        );
        let mut short = bytes.clone();
        short.truncate(HEADER_BYTES + 28);
        short[4] = 28;
        assert_eq!(
            Message::decode(&short, Direction::GuestToHost),
            Err(ErrorCode::InvalidFrame)
        );
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
                segment: 0,
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

    fn send_frame(
        peer: SocketAddr,
        segment: u16,
        bytes: &[u8],
        frame_bytes: usize,
    ) -> UdpSendFrame<'_> {
        UdpSendFrame {
            peer,
            segment,
            bytes,
            frame_bytes,
        }
    }

    #[test]
    fn borrowed_udp_codecs_agree_with_message() {
        let peer: SocketAddr = "[2001:db8::1]:53".parse().unwrap();
        let direction = Direction::GuestToHost;
        for payload in [vec![], vec![1, 2, 3], vec![9; socket::MAX_DATAGRAM_BYTES]] {
            let message = Message::UdpSend {
                segment: 0,
                peer,
                bytes: payload.clone(),
            };
            let frame = message.encode().unwrap();
            assert_eq!(
                decode_udp_send(&frame),
                Ok(Some(send_frame(peer, 0, &payload, frame.len())))
            );
            for length in 0..frame.len() {
                assert_eq!(decode_udp_send(&frame[..length]), Ok(None));
            }
            let mut coalesced = frame.clone();
            coalesced.extend_from_slice(&frame);
            assert_eq!(
                decode_udp_send(&coalesced),
                Ok(Some(send_frame(peer, 0, &payload, frame.len())))
            );
            let mut sent = Vec::new();
            append_udp_datagram(&mut sent, peer, 0, &payload).unwrap();
            let datagram = Message::UdpDatagram {
                segment: 0,
                peer,
                bytes: payload,
            };
            assert_eq!(sent, datagram.encode().unwrap());
        }
        for message in [Message::Hello, Message::UdpOpen] {
            let frame = message.encode().unwrap();
            assert!(Message::decode(&frame, direction).is_ok());
            assert_eq!(decode_udp_send(&frame), Err(ErrorCode::InvalidFrame));
        }
        let datagram = Message::UdpDatagram {
            segment: 0,
            peer,
            bytes: vec![1],
        }
        .encode()
        .unwrap();
        assert_eq!(
            decode_udp_send(&datagram),
            Err(Message::decode(&datagram, direction).unwrap_err())
        );
        let mut oversized = Message::UdpSend {
            segment: 0,
            peer,
            bytes: vec![0; 4],
        }
        .encode()
        .unwrap();
        oversized.resize(
            HEADER_BYTES
                + ENDPOINT_BYTES
                + UDP_SEGMENT_HEADER_BYTES
                + socket::MAX_DATAGRAM_BYTES
                + 1,
            0,
        );
        let length = u32::try_from(oversized.len() - HEADER_BYTES).unwrap();
        oversized[4..HEADER_BYTES].copy_from_slice(&length.to_le_bytes());
        assert_eq!(
            decode_udp_send(&oversized),
            Message::decode(&oversized, direction).map(|_| None)
        );
        assert!(decode_udp_send(&oversized).is_err());
        let mut failed = vec![5];
        assert!(
            append_udp_datagram(
                &mut failed,
                peer,
                0,
                &vec![0; socket::MAX_DATAGRAM_BYTES + 1]
            )
            .is_err()
        );
        assert_eq!(failed, [5]);
    }

    #[test]
    fn segmented_frames_pin_layout_and_the_frame_cap() {
        let peer: SocketAddr = "192.0.2.1:48879".parse().unwrap();
        let frame = Message::UdpSend {
            peer,
            segment: 2,
            bytes: vec![0xaa, 0xbb, 0xcc],
        }
        .encode()
        .unwrap();
        assert_eq!(
            frame,
            [
                0x03, 0, 0, 0, 27, 0, 0, 0, 4, 0, 0xef, 0xbe, 192, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 2, 0, 0, 0, 0xaa, 0xbb, 0xcc,
            ]
        );
        let largest = Message::UdpDatagram {
            peer: "[ffff::ffff]:65535".parse().unwrap(),
            segment: 4096,
            bytes: vec![0; MAX_UDP_RUN_BYTES],
        }
        .encode()
        .unwrap();
        assert_eq!(largest.len(), MAX_UDP_FRAME_BYTES);
    }

    #[test]
    fn segmented_frames_reject_invalid_runs_on_encode_and_decode() {
        let peer: SocketAddr = "192.0.2.1:9".parse().unwrap();
        let encode = |segment, length| {
            Message::UdpSend {
                peer,
                segment,
                bytes: vec![0; length],
            }
            .encode()
        };
        assert!(encode(1, 2).is_ok());
        for (segment, length) in [(4097, 8194), (1, 65), (1000, MAX_UDP_RUN_BYTES + 1)] {
            assert_eq!(
                encode(segment, length),
                Err(ErrorCode::InvalidFrame),
                "{segment} {length}"
            );
        }
        let valid = encode(100, 250).unwrap();
        let decode = |frame: &[u8]| Message::decode(frame, Direction::GuestToHost);
        assert!(decode(&valid).is_ok());
        for (offset, value) in [(29, 0x10), (30, 1), (31, 1)] {
            let mut forged = valid.clone();
            forged[offset] = value;
            assert_eq!(decode(&forged), Err(ErrorCode::InvalidFrame), "{offset}");
        }
        let mut oversized = valid.clone();
        oversized.resize(MAX_UDP_FRAME_BYTES + 1, 0);
        let payload = u32::try_from(oversized.len() - HEADER_BYTES).unwrap();
        oversized[4..HEADER_BYTES].copy_from_slice(&payload.to_le_bytes());
        assert_eq!(decode(&oversized), Err(ErrorCode::LimitExceeded));
        let mut plain_oversized = Message::UdpSend {
            peer,
            segment: 0,
            bytes: vec![],
        }
        .encode()
        .unwrap();
        plain_oversized.resize(
            HEADER_BYTES
                + ENDPOINT_BYTES
                + UDP_SEGMENT_HEADER_BYTES
                + socket::MAX_DATAGRAM_BYTES
                + 1,
            0,
        );
        let payload = u32::try_from(plain_oversized.len() - HEADER_BYTES).unwrap();
        plain_oversized[4..HEADER_BYTES].copy_from_slice(&payload.to_le_bytes());
        assert_eq!(decode(&plain_oversized), Err(ErrorCode::LimitExceeded));
        for noncanonical_segment in [250_u16, 251, 4096] {
            let mut forged = valid.clone();
            forged[28..30].copy_from_slice(&noncanonical_segment.to_le_bytes());
            assert_eq!(decode(&forged), Err(ErrorCode::InvalidFrame));
        }
        assert_eq!(
            Message::decode(&valid, Direction::HostToGuest),
            Err(ErrorCode::WrongDirection)
        );
    }

    #[test]
    fn borrowed_codecs_handle_segmented_frames_like_message() {
        let peer: SocketAddr = "[2001:db8::1]:53".parse().unwrap();
        for (segment, length) in [(1_u16, 2_usize), (1000, 1001), (4096, 65_504), (7, 64 * 7)] {
            let bytes = vec![9; length];
            let sent = Message::UdpSend {
                peer,
                segment,
                bytes: bytes.clone(),
            }
            .encode()
            .unwrap();
            assert_eq!(
                decode_udp_send(&sent),
                Ok(Some(send_frame(peer, segment, &bytes, sent.len())))
            );
            for cut in 0..sent.len().min(64) {
                assert_eq!(decode_udp_send(&sent[..cut]), Ok(None));
            }
            let mut appended = Vec::new();
            append_udp_datagram(&mut appended, peer, segment, &bytes).unwrap();
            assert_eq!(
                appended,
                Message::UdpDatagram {
                    peer,
                    segment,
                    bytes
                }
                .encode()
                .unwrap()
            );
        }
        for (segment, length) in [(0, 100), (100, 100), (100, 50), (5000, 10)] {
            let mut appended = Vec::new();
            append_udp_datagram(&mut appended, peer, segment, &vec![1; length]).unwrap();
            assert_eq!(
                appended,
                Message::UdpDatagram {
                    segment: 0,
                    peer,
                    bytes: vec![1; length]
                }
                .encode()
                .unwrap()
            );
        }
        let mut failed = vec![5];
        for (segment, length) in [(100, 65_505), (0, 4097), (5000, 5001)] {
            assert!(append_udp_datagram(&mut failed, peer, segment, &vec![0; length]).is_err());
        }
        assert_eq!(failed, [5]);
        let datagram = Message::UdpDatagram {
            peer,
            segment: 1,
            bytes: vec![1, 2],
        }
        .encode()
        .unwrap();
        assert_eq!(
            decode_udp_send(&datagram),
            Err(Message::decode(&datagram, Direction::GuestToHost).unwrap_err())
        );
        let mut forged = Message::UdpSend {
            peer,
            segment: 1,
            bytes: vec![1, 2],
        }
        .encode()
        .unwrap();
        forged[30] = 1;
        assert_eq!(decode_udp_send(&forged), Err(ErrorCode::InvalidFrame));
    }

    #[test]
    fn udp_frames_carry_one_datagram_at_segment_zero_including_empty_and_largest() {
        let peer: SocketAddr = "192.0.2.1:9".parse().unwrap();
        for length in [0, 1, socket::MAX_DATAGRAM_BYTES] {
            let sent = Message::UdpSend {
                peer,
                segment: 0,
                bytes: vec![7; length],
            };
            round_trip(&sent);
            let datagram = Message::UdpDatagram {
                peer,
                segment: 0,
                bytes: vec![7; length],
            };
            round_trip(&datagram);
        }
        for run in [(1, 2), (4096, 4097), (1024, MAX_UDP_RUN_BYTES), (1, 64)] {
            round_trip(&Message::UdpDatagram {
                peer,
                segment: run.0,
                bytes: vec![1; run.1],
            });
        }
        let too_large = Message::UdpSend {
            peer,
            segment: 0,
            bytes: vec![0; socket::MAX_DATAGRAM_BYTES + 1],
        };
        assert_eq!(too_large.encode(), Err(ErrorCode::LimitExceeded));
    }

    #[test]
    fn encode_and_append_write_segment_zero_when_the_run_is_one_datagram() {
        let peer: SocketAddr = "192.0.2.1:9".parse().unwrap();
        for (segment, length) in [(100, 100), (100, 50), (5000, 10), (1, 0), (1, 1)] {
            let bytes = vec![1; length];
            let canonical = Message::UdpDatagram {
                peer,
                segment: 0,
                bytes: bytes.clone(),
            }
            .encode()
            .unwrap();
            let mut appended = Vec::new();
            append_udp_datagram(&mut appended, peer, segment, &bytes).unwrap();
            assert_eq!(appended, canonical);
            let encoded = Message::UdpDatagram {
                peer,
                segment,
                bytes,
            }
            .encode()
            .unwrap();
            assert_eq!(encoded, canonical);
        }
    }

    #[test]
    fn the_retired_segmented_opcodes_are_unknown() {
        for (opcode, direction) in [
            (0x06_u16, Direction::GuestToHost),
            (0x109, Direction::HostToGuest),
        ] {
            let mut frame = vec![0; HEADER_BYTES];
            frame[..2].copy_from_slice(&opcode.to_le_bytes());
            assert_eq!(
                Message::decode(&frame, direction),
                Err(ErrorCode::UnknownOpcode)
            );
        }
    }

    #[test]
    fn only_udp_frames_may_exceed_the_ordinary_payload_limit() {
        let peer: SocketAddr = "192.0.2.1:9".parse().unwrap();
        let big = MAX_PAYLOAD_BYTES + 1;
        let udp = Message::UdpDatagram {
            peer,
            segment: 1024,
            bytes: vec![0; MAX_UDP_RUN_BYTES],
        }
        .encode()
        .unwrap();
        assert!(udp.len() - HEADER_BYTES > MAX_PAYLOAD_BYTES);
        assert!(Message::decode(&udp, Direction::HostToGuest).is_ok());
        for message in [Message::Hello, Message::Ready, Message::UdpOpen] {
            let mut frame = message.encode().unwrap();
            frame.resize(HEADER_BYTES + big, 0);
            frame[4..HEADER_BYTES].copy_from_slice(&u32::try_from(big).unwrap().to_le_bytes());
            assert_eq!(
                Message::decode(&frame, message.opcode().direction()),
                Err(ErrorCode::LimitExceeded)
            );
        }
    }

    #[test]
    fn stream_decoder_buffers_a_whole_segmented_frame() {
        let frame = Message::UdpDatagram {
            peer: "127.0.0.1:9".parse().unwrap(),
            segment: 4096,
            bytes: vec![3; MAX_UDP_RUN_BYTES],
        };
        let bytes = frame.encode().unwrap();
        let mut decoder = StreamDecoder::default();
        for chunk in bytes.chunks(10_000) {
            assert_eq!(decoder.next(Direction::HostToGuest), Ok(None));
            decoder.push(chunk).unwrap();
        }
        assert_eq!(decoder.next(Direction::HostToGuest), Ok(Some(frame)));
        assert!(decoder.is_empty());
    }

    #[test]
    fn stream_decoder_handles_split_coalesced_and_hostile_frames_with_bounded_storage() {
        let first = Message::UdpDatagram {
            segment: 0,
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
        assert!(decoder.push(&vec![0; MAX_UDP_FRAME_BYTES + 1]).is_err());
    }
}
