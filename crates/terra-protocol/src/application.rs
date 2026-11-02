//! The binary frames the guest kernel's terra sockets exchange with the network frontend, which
//! UDP publication relays reuse; `kernel/overlay/net/terra/socket.c` implements the same layout.

use std::{
    fmt,
    net::{IpAddr, SocketAddr},
};

use serde::{Deserialize, Serialize};

use crate::socket::Error as SocketError;

pub const HEADER_BYTES: usize = 8;
pub(crate) const ENDPOINT_BYTES: usize = 20;
/// A UDP frame's segment size and its reserved field.
pub(crate) const UDP_SEGMENT_FIELD_BYTES: usize = 4;
/// A reply's status code and its reserved field.
pub(crate) const STATUS_BYTES: usize = 4;
/// `TcpOpen`'s flags and three keepalive fields, before its peer endpoint.
pub(crate) const TCP_OPEN_FIELDS_BYTES: usize = 8;
/// The whole `TcpOpen` frame.
pub(crate) const TCP_OPEN_FRAME_BYTES: usize =
    HEADER_BYTES + TCP_OPEN_FIELDS_BYTES + ENDPOINT_BYTES;
pub(crate) const ENDPOINT_IPV4: u8 = 4;
pub(crate) const ENDPOINT_IPV6: u8 = 6;
pub(crate) const ENDPOINT_PORT_OFFSET: usize = 2;
pub(crate) const ENDPOINT_ADDRESS_OFFSET: usize = 4;
/// Bytes a UDP frame spends before its datagram run: header, peer endpoint, and segment field.
pub(crate) const UDP_FRAME_OVERHEAD_BYTES: usize =
    HEADER_BYTES + ENDPOINT_BYTES + UDP_SEGMENT_FIELD_BYTES;
/// Segments one UDP frame may carry, within the kernel's UDP GSO and GRO limit.
pub const MAX_DATAGRAM_SEGMENTS: usize = 64;
/// Largest datagram the kernel frames carry.
pub const MAX_NETWORK_DATAGRAM_BYTES: usize = 4096;
/// The guest carrier buffer and the host flow upstream buffer are both this size.
pub const MAX_FRAME_BYTES: usize = 64 * 1024;
/// Largest datagram run one UDP frame can carry.
pub(crate) const MAX_UDP_RUN_BYTES: usize = MAX_FRAME_BYTES - UDP_FRAME_OVERHEAD_BYTES;
const _: () = assert!(MAX_FRAME_BYTES == crate::vsock::FLOW_UPSTREAM_BYTES as usize);
const _: () = assert!(MAX_FRAME_BYTES <= crate::vsock::FLOW_REPLY_BYTES as usize);
pub const OPEN_TIMEOUT_SECS: u64 = 30;
/// Linux `MAX_TCP_KEEPIDLE` and `MAX_TCP_KEEPINTVL`, in seconds.
pub(crate) const MAX_KEEPALIVE_SECS: u16 = 32767;
/// Linux `MAX_TCP_KEEPCNT`.
pub(crate) const MAX_KEEPALIVE_PROBES: u16 = 127;
pub(crate) const TCP_OPEN_INLINE_URGENT_FLAG: u16 = 1;
pub(crate) const TCP_OPEN_KEEPALIVE_FLAG: u16 = 2;

/// Declares [`Opcode`], its decoder, and the kernel header's list from one list of codes.
macro_rules! opcodes {
    ($($name:ident = $code:literal,)*) => {
        pub(crate) const OPCODES: &[(&str, u16)] = &[$((stringify!($name), $code),)*];

        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        #[repr(u16)]
        enum Opcode {
            $($name = $code,)*
        }

        impl TryFrom<u16> for Opcode {
            type Error = FrameError;
            fn try_from(value: u16) -> Result<Self, FrameError> {
                match value {
                    $($code => Ok(Self::$name),)*
                    _ => Err(FrameError),
                }
            }
        }
    };
}

opcodes! {
    TcpOpen = 0x01,
    UdpSend = 0x03,
    Opened = 0x101,
    UdpDatagram = 0x103,
    UdpError = 0x104,
}

/// A frame that is malformed, over a limit, of an unknown opcode, or sent the wrong way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameError;

impl fmt::Display for FrameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid network frame")
    }
}

impl std::error::Error for FrameError {}

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

/// Datagrams to or from `peer`: one when `segment` is 0, else equal `segment`-byte datagrams,
/// the last possibly shorter. `B` is `&[u8]` when the bytes are borrowed from a frame buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UdpRun<B = Vec<u8>> {
    pub peer: SocketAddr,
    pub segment: u16,
    pub bytes: B,
}

impl UdpRun<&[u8]> {
    #[must_use]
    pub fn into_owned(self) -> UdpRun {
        UdpRun {
            peer: self.peer,
            segment: self.segment,
            bytes: self.bytes.to_vec(),
        }
    }
}

/// A frame type decoded from bytes it borrows.
pub trait Frame<'a>: Sized {
    /// The next complete frame and its encoded length, or `Ok(None)` while more bytes are
    /// needed; a datagram run stays borrowed from `bytes`.
    fn decode(bytes: &'a [u8]) -> Result<Option<(Self, usize)>, FrameError>;
}

/// Frames the guest sends to the host. A UDP stream needs no opening frame: connecting to the
/// UDP port asks for the socket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GuestFrame<B = Vec<u8>> {
    TcpOpen {
        peer: SocketAddr,
        options: TcpOpenOptions,
    },
    UdpSend(UdpRun<B>),
}

/// Frames the host sends to the guest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostFrame<B = Vec<u8>> {
    /// The outcome of opening the stream's TCP or UDP socket.
    Opened(Result<(), SocketError>),
    UdpDatagram(UdpRun<B>),
    UdpError {
        peer: SocketAddr,
        error: SocketError,
    },
}

impl<B: AsRef<[u8]>> GuestFrame<B> {
    const fn opcode(&self) -> Opcode {
        match self {
            Self::TcpOpen { .. } => Opcode::TcpOpen,
            Self::UdpSend(_) => Opcode::UdpSend,
        }
    }

    /// Appends this frame to `out`, leaving `out` unchanged on error.
    pub fn append(&self, out: &mut Vec<u8>) -> Result<(), FrameError> {
        append_frame(out, self.opcode(), |writer| {
            match self {
                Self::TcpOpen { peer, options } => writer.put_tcp_open(*peer, *options)?,
                Self::UdpSend(run) => writer.put_udp_body(run)?,
            }
            Ok(())
        })
    }
}

impl GuestFrame {
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let mut frame = Vec::new();
        self.append(&mut frame)?;
        Ok(frame)
    }
}

impl<'a> GuestFrame<&'a [u8]> {
    #[must_use]
    pub fn into_owned(self) -> GuestFrame {
        match self {
            Self::TcpOpen { peer, options } => GuestFrame::TcpOpen { peer, options },
            Self::UdpSend(run) => GuestFrame::UdpSend(run.into_owned()),
        }
    }

    fn decode_payload(opcode: Opcode, body: &mut Body<'a>) -> Result<Self, FrameError> {
        Ok(match opcode {
            Opcode::UdpSend => Self::UdpSend(read_udp_body(body)?),
            Opcode::TcpOpen => {
                let (peer, options) = body.tcp_open()?;
                Self::TcpOpen { peer, options }
            }
            Opcode::Opened | Opcode::UdpDatagram | Opcode::UdpError => return Err(FrameError),
        })
    }
}

impl<'a> Frame<'a> for GuestFrame<&'a [u8]> {
    fn decode(bytes: &'a [u8]) -> Result<Option<(Self, usize)>, FrameError> {
        decode_frame(bytes, Self::decode_payload)
    }
}

impl<B: AsRef<[u8]>> HostFrame<B> {
    const fn opcode(&self) -> Opcode {
        match self {
            Self::Opened(_) => Opcode::Opened,
            Self::UdpDatagram(_) => Opcode::UdpDatagram,
            Self::UdpError { .. } => Opcode::UdpError,
        }
    }

    /// Appends this frame to `out`, leaving `out` unchanged on error.
    pub fn append(&self, out: &mut Vec<u8>) -> Result<(), FrameError> {
        append_frame(out, self.opcode(), |writer| {
            match self {
                Self::Opened(outcome) => writer.put_status(outcome.err()),
                Self::UdpDatagram(run) => writer.put_udp_body(run)?,
                Self::UdpError { peer, error } => {
                    writer.put_status(Some(*error));
                    writer.put_peer(*peer)?;
                }
            }
            Ok(())
        })
    }
}

impl HostFrame {
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let mut frame = Vec::new();
        self.append(&mut frame)?;
        Ok(frame)
    }
}

impl<'a> HostFrame<&'a [u8]> {
    #[must_use]
    pub fn into_owned(self) -> HostFrame {
        match self {
            Self::Opened(outcome) => HostFrame::Opened(outcome),
            Self::UdpDatagram(run) => HostFrame::UdpDatagram(run.into_owned()),
            Self::UdpError { peer, error } => HostFrame::UdpError { peer, error },
        }
    }

    fn decode_payload(opcode: Opcode, body: &mut Body<'a>) -> Result<Self, FrameError> {
        Ok(match opcode {
            Opcode::UdpDatagram => Self::UdpDatagram(read_udp_body(body)?),
            Opcode::Opened => Self::Opened(body.status()?.map_or(Ok(()), Err)),
            Opcode::UdpError => {
                let error = body.status()?.ok_or(FrameError)?;
                Self::UdpError {
                    peer: body.peer()?,
                    error,
                }
            }
            Opcode::TcpOpen | Opcode::UdpSend => return Err(FrameError),
        })
    }
}

impl<'a> Frame<'a> for HostFrame<&'a [u8]> {
    fn decode(bytes: &'a [u8]) -> Result<Option<(Self, usize)>, FrameError> {
        decode_frame(bytes, Self::decode_payload)
    }
}

fn decode_frame<'a, F>(
    bytes: &'a [u8],
    decode_payload: fn(Opcode, &mut Body<'a>) -> Result<F, FrameError>,
) -> Result<Option<(F, usize)>, FrameError> {
    let Some((header, rest)) = bytes.split_first_chunk() else {
        return Ok(None);
    };
    let (opcode, length) = read_header(*header)?;
    let Some(payload) = rest.get(..length) else {
        return Ok(None);
    };
    let mut body = Body(payload);
    let frame = decode_payload(opcode, &mut body)?;
    body.finish()?;
    Ok(Some((frame, HEADER_BYTES + length)))
}

/// The whole length of the frame `header` starts, refused past [`MAX_FRAME_BYTES`] or for an
/// unknown opcode.
pub fn frame_len(header: [u8; HEADER_BYTES]) -> Result<usize, FrameError> {
    Ok(HEADER_BYTES + read_header(header)?.1)
}

/// The opcode and payload length a frame header declares; each opcode's payload reader bounds
/// the payload more tightly once it has arrived.
fn read_header(bytes: [u8; HEADER_BYTES]) -> Result<(Opcode, usize), FrameError> {
    let mut header = Body(&bytes);
    let opcode = Opcode::try_from(header.u16()?)?;
    header.reserved()?;
    let length = header.u32()? as usize;
    // Subtracting keeps a forged length from wrapping a 32-bit usize, as on the wasm frontend.
    if length > MAX_FRAME_BYTES - HEADER_BYTES {
        return Err(FrameError);
    }
    Ok((opcode, length))
}

/// Appends one `opcode` frame whose payload `write_payload` writes, leaving `out` unchanged on
/// error.
#[allow(clippy::cast_possible_truncation)] // the MAX_FRAME_BYTES check bounds the length
fn append_frame(
    out: &mut Vec<u8>,
    opcode: Opcode,
    write_payload: impl FnOnce(&mut BodyWriter<'_>) -> Result<(), FrameError>,
) -> Result<(), FrameError> {
    let start = out.len();
    out.resize(start + HEADER_BYTES, 0);
    let mut written = write_payload(&mut BodyWriter(out));
    if written.is_ok() && out.len() - start > MAX_FRAME_BYTES {
        written = Err(FrameError);
    }
    if let Err(error) = written {
        out.truncate(start);
        return Err(error);
    }
    let length = (out.len() - start - HEADER_BYTES) as u32;
    out[start..start + 2].copy_from_slice(&(opcode as u16).to_le_bytes());
    out[start + 4..start + HEADER_BYTES].copy_from_slice(&length.to_le_bytes());
    Ok(())
}

fn read_udp_body<'a>(body: &mut Body<'a>) -> Result<UdpRun<&'a [u8]>, FrameError> {
    let peer = body.peer()?;
    let segment = body.u16()?;
    body.reserved()?;
    let bytes = body.remaining();
    check_udp_run(bytes, segment)?;
    Ok(UdpRun {
        peer,
        segment,
        bytes,
    })
}

fn check_udp_run(bytes: &[u8], segment: u16) -> Result<(), FrameError> {
    is_valid_udp_run(bytes.len(), usize::from(segment))
        .then_some(())
        .ok_or(FrameError)
}

/// Bounded reassembly for frame streams whose reads may split or combine frames.
pub struct StreamDecoder {
    bytes: Box<[u8]>,
    /// The undecoded bytes are `bytes[start..end]`; decoding advances `start` instead of moving them.
    start: usize,
    end: usize,
}

impl Default for StreamDecoder {
    fn default() -> Self {
        Self {
            bytes: vec![0; MAX_FRAME_BYTES].into_boxed_slice(),
            start: 0,
            end: 0,
        }
    }
}

impl StreamDecoder {
    /// Free space a reader fills directly; [`Self::commit`] then takes the bytes it wrote.
    /// Empty only while a whole frame is already waiting.
    pub fn read_buffer(&mut self) -> &mut [u8] {
        if self.end == self.bytes.len() && self.start > 0 {
            self.bytes.copy_within(self.start..self.end, 0);
            (self.start, self.end) = (0, self.end - self.start);
        }
        &mut self.bytes[self.end..]
    }

    pub fn commit(&mut self, count: usize) {
        debug_assert!(count <= self.bytes.len() - self.end);
        self.end += count;
    }

    /// The next whole frame, with a datagram run borrowed from the decoder's buffer.
    pub fn next_frame<'a, F: Frame<'a>>(&'a mut self) -> Result<Option<F>, FrameError> {
        let Some((frame, length)) = F::decode(&self.bytes[self.start..self.end])? else {
            return Ok(None);
        };
        self.start += length;
        if self.start == self.end {
            (self.start, self.end) = (0, 0);
        }
        Ok(Some(frame))
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }
}

/// Whether `length` bytes are one datagram when `segment` is 0, else a valid segmented run.
#[must_use]
pub(crate) const fn is_valid_udp_run(length: usize, segment: usize) -> bool {
    if segment == 0 {
        length <= MAX_NETWORK_DATAGRAM_BYTES
    } else {
        is_valid_segmented_run(length, segment)
    }
}

/// Whether `length` bytes split into `segment`-byte datagrams, the last possibly shorter, that
/// fit one UDP frame.
const fn is_valid_segmented_run(length: usize, segment: usize) -> bool {
    segment >= 1
        && segment <= MAX_NETWORK_DATAGRAM_BYTES
        && length > segment
        && length <= MAX_UDP_RUN_BYTES
        && length.div_ceil(segment) <= MAX_DATAGRAM_SEGMENTS
}

/// Whether a `length`-byte datagram joins a `run_bytes`-byte run of `segment`-byte datagrams as
/// UDP GRO merges them: no longer than the segment, after no shorter one, and within one frame.
#[must_use]
pub const fn extends_udp_run(run_bytes: usize, segment: usize, length: usize) -> bool {
    length != 0
        && length <= segment
        && run_bytes.is_multiple_of(segment)
        && is_valid_segmented_run(run_bytes + length, segment)
}

/// Writes payload fields in the order [`Body`] reads them back.
struct BodyWriter<'a>(&'a mut Vec<u8>);

impl BodyWriter<'_> {
    fn put_u16(&mut self, value: u16) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }
    fn put_reserved(&mut self) {
        self.put_u16(0);
    }
    fn put_tcp_open(
        &mut self,
        peer: SocketAddr,
        options: TcpOpenOptions,
    ) -> Result<(), FrameError> {
        let mut flags = 0;
        if options.inline_urgent {
            flags |= TCP_OPEN_INLINE_URGENT_FLAG;
        }
        let fields = match options.keepalive {
            Some(keepalive) => {
                flags |= TCP_OPEN_KEEPALIVE_FLAG;
                [
                    keepalive.probe_count,
                    keepalive.idle_secs,
                    keepalive.interval_secs,
                ]
            }
            None => [0; 3],
        };
        self.put_u16(flags);
        for field in fields {
            self.put_u16(field);
        }
        self.put_peer(peer)
    }
    fn put_peer(&mut self, peer: SocketAddr) -> Result<(), FrameError> {
        let (family, address) = match peer {
            SocketAddr::V4(peer) => {
                let mut address = [0; 16];
                address[..4].copy_from_slice(&peer.ip().octets());
                (ENDPOINT_IPV4, address)
            }
            SocketAddr::V6(peer) if peer.flowinfo() == 0 && peer.scope_id() == 0 => {
                (ENDPOINT_IPV6, peer.ip().octets())
            }
            SocketAddr::V6(_) => return Err(FrameError),
        };
        self.0.extend_from_slice(&[family, 0]);
        self.put_u16(peer.port());
        self.0.extend_from_slice(&address);
        Ok(())
    }
    fn put_status(&mut self, error: Option<SocketError>) {
        self.put_u16(error.map_or(0, |error| error as u16));
        self.put_reserved();
    }
    /// A `segment` that does not split `bytes` into more than one datagram is written as 0, so
    /// every datagram has one encoding.
    fn put_udp_body(&mut self, run: &UdpRun<impl AsRef<[u8]>>) -> Result<(), FrameError> {
        let bytes = run.bytes.as_ref();
        let segment = if bytes.len() > usize::from(run.segment) {
            run.segment
        } else {
            0
        };
        check_udp_run(bytes, segment)?;
        self.0
            .reserve(ENDPOINT_BYTES + UDP_SEGMENT_FIELD_BYTES + bytes.len());
        self.put_peer(run.peer)?;
        self.put_u16(segment);
        self.put_reserved();
        self.0.extend_from_slice(bytes);
        Ok(())
    }
}

struct Body<'a>(&'a [u8]);

impl<'a> Body<'a> {
    fn take_array<const N: usize>(&mut self) -> Result<&'a [u8; N], FrameError> {
        let (bytes, rest) = self.0.split_first_chunk().ok_or(FrameError)?;
        self.0 = rest;
        Ok(bytes)
    }
    fn u16(&mut self) -> Result<u16, FrameError> {
        Ok(u16::from_le_bytes(*self.take_array()?))
    }
    fn u32(&mut self) -> Result<u32, FrameError> {
        Ok(u32::from_le_bytes(*self.take_array()?))
    }
    fn reserved(&mut self) -> Result<(), FrameError> {
        if self.u16()? == 0 {
            Ok(())
        } else {
            Err(FrameError)
        }
    }
    fn tcp_open(&mut self) -> Result<(SocketAddr, TcpOpenOptions), FrameError> {
        let flags = self.u16()?;
        let [probe_count, idle_secs, interval_secs] = [self.u16()?, self.u16()?, self.u16()?];
        if flags & !(TCP_OPEN_INLINE_URGENT_FLAG | TCP_OPEN_KEEPALIVE_FLAG) != 0 {
            return Err(FrameError);
        }
        let keepalive = if flags & TCP_OPEN_KEEPALIVE_FLAG == 0 {
            if [probe_count, idle_secs, interval_secs] != [0; 3] {
                return Err(FrameError);
            }
            None
        } else {
            Some(TcpKeepalive::new(idle_secs, interval_secs, probe_count).ok_or(FrameError)?)
        };
        let options = TcpOpenOptions {
            inline_urgent: flags & TCP_OPEN_INLINE_URGENT_FLAG != 0,
            keepalive,
        };
        Ok((self.peer()?, options))
    }
    fn peer(&mut self) -> Result<SocketAddr, FrameError> {
        let [family, 0] = *self.take_array()? else {
            return Err(FrameError);
        };
        let port = self.u16()?;
        let address: [u8; 16] = *self.take_array()?;
        let address = match (family, address.split_first_chunk::<4>()) {
            (ENDPOINT_IPV4, Some((ipv4, rest))) if *rest == [0; 12] => IpAddr::from(*ipv4),
            (ENDPOINT_IPV6, _) => IpAddr::from(address),
            _ => return Err(FrameError),
        };
        Ok(SocketAddr::new(address, port))
    }
    fn status(&mut self) -> Result<Option<SocketError>, FrameError> {
        let status = self.u16()?;
        self.reserved()?;
        if status == 0 {
            return Ok(None);
        }
        SocketError::decode(status).map(Some).ok_or(FrameError)
    }
    fn remaining(&mut self) -> &'a [u8] {
        std::mem::take(&mut self.0)
    }
    fn finish(self) -> Result<(), FrameError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(FrameError)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// Copies `bytes` in through the decoder's read buffer, as a reader would.
    fn feed(decoder: &mut StreamDecoder, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            let buffer = decoder.read_buffer();
            let count = buffer.len().min(bytes.len());
            assert_ne!(count, 0, "decoder full");
            buffer[..count].copy_from_slice(&bytes[..count]);
            decoder.commit(count);
            bytes = &bytes[count..];
        }
    }

    fn next_host_frame(decoder: &mut StreamDecoder) -> Option<HostFrame> {
        decoder
            .next_frame::<HostFrame<&[u8]>>()
            .unwrap()
            .map(HostFrame::into_owned)
    }

    type Decoded<F> = Result<Option<(F, usize)>, FrameError>;

    fn decode_guest(bytes: &[u8]) -> Decoded<GuestFrame> {
        Ok(GuestFrame::decode(bytes)?.map(|(frame, length)| (frame.into_owned(), length)))
    }

    fn decode_host(bytes: &[u8]) -> Decoded<HostFrame> {
        Ok(HostFrame::decode(bytes)?.map(|(frame, length)| (frame.into_owned(), length)))
    }

    /// Resizes `frame`'s payload to `payload_bytes` zero bytes and declares that length.
    fn set_payload_bytes(frame: &mut Vec<u8>, payload_bytes: usize) {
        frame.resize(HEADER_BYTES + payload_bytes, 0);
        frame[4..HEADER_BYTES]
            .copy_from_slice(&u32::try_from(payload_bytes).unwrap().to_le_bytes());
    }

    /// `frame`, encoded as `bytes`, survives `decode` and needs every byte, and `decode_other`,
    /// the opposite direction's decoder, refuses it.
    fn round_trip<F: Clone + std::fmt::Debug + PartialEq>(
        frame: &F,
        bytes: &[u8],
        decode: fn(&[u8]) -> Decoded<F>,
        decode_other: fn(&[u8]) -> Result<(), FrameError>,
    ) {
        assert_eq!(decode(bytes).unwrap(), Some((frame.clone(), bytes.len())));
        assert_eq!(decode_other(bytes), Err(FrameError));
        for length in 0..bytes.len() {
            assert_eq!(decode(&bytes[..length]), Ok(None));
        }
        let mut trailing = bytes.to_vec();
        trailing[4] = trailing[4].wrapping_add(1);
        trailing.push(0);
        assert_ne!(
            decode(&trailing).ok().flatten().map(|(decoded, _)| decoded),
            Some(frame.clone())
        );
    }

    #[test]
    fn endpoints_pin_address_layout_and_reject_native_only_fields() {
        let ipv4: SocketAddr = "203.0.113.1:443".parse().unwrap();
        let mut bytes = Vec::new();
        BodyWriter(&mut bytes).put_peer(ipv4).unwrap();
        assert_eq!(
            bytes,
            [
                4, 0, 0xbb, 1, 203, 0, 113, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );
        assert_eq!(bytes[0], ENDPOINT_IPV4);
        assert_eq!(
            bytes[ENDPOINT_PORT_OFFSET..ENDPOINT_ADDRESS_OFFSET],
            443_u16.to_le_bytes()
        );
        assert_eq!(bytes[ENDPOINT_ADDRESS_OFFSET..][..4], [203, 0, 113, 1]);
        let decode = |bytes: &[u8]| -> Result<SocketAddr, FrameError> {
            let mut body = Body(bytes);
            let peer = body.peer()?;
            body.finish()?;
            Ok(peer)
        };
        assert_eq!(decode(&bytes), Ok(ipv4));
        for peer in [ipv4, "[2001:db8::1]:53".parse().unwrap()] {
            let mut encoded = Vec::new();
            BodyWriter(&mut encoded).put_peer(peer).unwrap();
            assert_eq!(decode(&encoded), Ok(peer));
        }
        for (offset, value) in [(0, 5), (1, 1), (8, 1)] {
            let mut malformed = bytes.clone();
            malformed[offset] = value;
            assert_eq!(decode(&malformed), Err(FrameError));
        }
        for length in 0..ENDPOINT_BYTES {
            assert!(decode(&bytes[..length]).is_err());
        }
        let mut scratch = Vec::new();
        let mut writer = BodyWriter(&mut scratch);
        assert!(writer.put_peer("[fe80::1%1]:53".parse().unwrap()).is_err());
        let flowinfo = std::net::SocketAddrV6::new(std::net::Ipv6Addr::LOCALHOST, 53, 1, 0);
        assert!(writer.put_peer(SocketAddr::V6(flowinfo)).is_err());
    }

    #[test]
    fn every_frame_round_trips_and_rejects_the_wrong_direction() {
        let peer: SocketAddr = "[2001:db8::1]:53".parse().unwrap();
        for frame in [
            GuestFrame::TcpOpen {
                peer,
                options: TcpOpenOptions {
                    inline_urgent: true,
                    keepalive: TcpKeepalive::new(60, 15, 9),
                },
            },
            GuestFrame::TcpOpen {
                peer,
                options: TcpOpenOptions::default(),
            },
            GuestFrame::TcpOpen {
                peer: "203.0.113.1:443".parse().unwrap(),
                options: TcpOpenOptions {
                    inline_urgent: false,
                    keepalive: TcpKeepalive::new(MAX_KEEPALIVE_SECS, 1, MAX_KEEPALIVE_PROBES),
                },
            },
            GuestFrame::UdpSend(UdpRun {
                segment: 0,
                peer,
                bytes: Vec::new(),
            }),
            GuestFrame::UdpSend(UdpRun {
                segment: 0,
                peer,
                bytes: vec![42; MAX_NETWORK_DATAGRAM_BYTES],
            }),
            GuestFrame::UdpSend(UdpRun {
                peer,
                segment: 1024,
                bytes: vec![1; MAX_UDP_RUN_BYTES],
            }),
        ] {
            round_trip(&frame, &frame.encode().unwrap(), decode_guest, |bytes| {
                decode_host(bytes).map(|_| ())
            });
        }
        for frame in [
            HostFrame::Opened(Ok(())),
            HostFrame::Opened(Err(SocketError::AccessDenied)),
            HostFrame::UdpError {
                peer,
                error: SocketError::ConnectionRefused,
            },
        ] {
            round_trip(&frame, &frame.encode().unwrap(), decode_host, |bytes| {
                decode_guest(bytes).map(|_| ())
            });
        }
        for (segment, length) in [
            (0, 0),
            (0, MAX_NETWORK_DATAGRAM_BYTES),
            (1, 2),
            (1, 64),
            (4096, 4097),
        ] {
            let frame = HostFrame::UdpDatagram(UdpRun {
                peer,
                segment,
                bytes: vec![2; length],
            });
            round_trip(&frame, &frame.encode().unwrap(), decode_host, |bytes| {
                decode_guest(bytes).map(|_| ())
            });
        }
    }

    #[test]
    fn tcp_opening_pins_layout_and_rejects_forged_fields() {
        let peer: SocketAddr = "203.0.113.1:443".parse().unwrap();
        let bytes = GuestFrame::TcpOpen {
            peer,
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
                1, 0, 0, 0, 28, 0, 0, 0, 3, 0, 9, 0, 60, 0, 15, 0, 4, 0, 0xbb, 1, 203, 0, 113, 1,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ]
        );
        assert_eq!(bytes.len(), TCP_OPEN_FRAME_BYTES);
        assert_eq!(
            u16::from_le_bytes([bytes[HEADER_BYTES], bytes[HEADER_BYTES + 1]]),
            TCP_OPEN_INLINE_URGENT_FLAG | TCP_OPEN_KEEPALIVE_FLAG
        );
        for outcome in [Ok(()), Err(SocketError::TimedOut)] {
            assert_eq!(
                HostFrame::Opened(outcome).encode().unwrap().len(),
                HEADER_BYTES + STATUS_BYTES
            );
        }
        for (offset, value) in [(2, 1), (8, 4), (8, 8), (10, 0), (12, 0), (14, 0)] {
            let mut forged = bytes.clone();
            forged[offset] = value;
            assert!(GuestFrame::decode(&forged).is_err());
        }
        let mut forged = bytes.clone();
        forged[14..16].copy_from_slice(&(MAX_KEEPALIVE_SECS + 1).to_le_bytes());
        assert_eq!(GuestFrame::decode(&forged), Err(FrameError));
        let mut forged = bytes.clone();
        forged[10..12].copy_from_slice(&(MAX_KEEPALIVE_PROBES + 1).to_le_bytes());
        assert_eq!(GuestFrame::decode(&forged), Err(FrameError));
        let mut without_flag = bytes.clone();
        without_flag[8] = 1;
        assert_eq!(GuestFrame::decode(&without_flag), Err(FrameError));
        let mut short = bytes;
        short.truncate(HEADER_BYTES + 24);
        short[4] = 24;
        assert_eq!(GuestFrame::decode(&short), Err(FrameError));
    }

    /// Every opcode shares one length limit at the header; a longer payload than its opcode holds
    /// fails once the frame has arrived. Retired opcodes 0x02, 0x04 to 0x06 and 0x102, 0x105 to
    /// 0x109 are unknown.
    #[test]
    fn hostile_lengths_and_payloads_are_rejected() {
        let mut opened = HostFrame::Opened(Ok(())).encode().unwrap();
        set_payload_bytes(&mut opened, MAX_FRAME_BYTES - HEADER_BYTES + 1);
        assert_eq!(HostFrame::decode(&opened[..HEADER_BYTES]), Err(FrameError));
        set_payload_bytes(&mut opened, MAX_FRAME_BYTES - HEADER_BYTES);
        assert_eq!(HostFrame::decode(&opened[..HEADER_BYTES]), Ok(None));
        assert_eq!(HostFrame::decode(&opened), Err(FrameError));
        let mut forged_length = [0; HEADER_BYTES];
        forged_length[..2].copy_from_slice(&(Opcode::UdpSend as u16).to_le_bytes());
        for length in [u32::MAX, u32::MAX - 7] {
            forged_length[4..].copy_from_slice(&length.to_le_bytes());
            assert_eq!(frame_len(forged_length), Err(FrameError));
        }
        for opcode in [
            0x02_u16, 0x04, 0x05, 0x06, 0x102, 0x105, 0x108, 0x109, 0xffff,
        ] {
            let mut unknown = vec![0; HEADER_BYTES];
            unknown[..2].copy_from_slice(&opcode.to_le_bytes());
            assert_eq!(GuestFrame::decode(&unknown).map(|_| ()), Err(FrameError));
            assert_eq!(HostFrame::decode(&unknown).map(|_| ()), Err(FrameError));
        }
        assert_eq!(
            GuestFrame::UdpSend(UdpRun {
                segment: 0,
                peer: "127.0.0.1:1".parse().unwrap(),
                bytes: vec![0; MAX_NETWORK_DATAGRAM_BYTES + 1],
            })
            .encode(),
            Err(FrameError)
        );
        let error = HostFrame::UdpError {
            peer: "127.0.0.1:1".parse().unwrap(),
            error: SocketError::Closed,
        }
        .encode()
        .unwrap();
        for (offset, value) in [(8, 0), (8, 16), (10, 1)] {
            let mut forged = error.clone();
            forged[offset] = value;
            forged[offset + 1] = 0;
            assert!(HostFrame::decode(&forged).is_err());
        }
    }

    /// A run decodes borrowed, stops at its frame's end, and appending it writes the bytes
    /// `encode` writes, in both directions; a failed append leaves the buffer as it was.
    #[test]
    fn borrowed_udp_frames_decode_in_place_and_append_what_encode_writes() {
        let peer: SocketAddr = "[2001:db8::1]:53".parse().unwrap();
        for (segment, length) in [
            (0_u16, 0_usize),
            (0, 3),
            (0, MAX_NETWORK_DATAGRAM_BYTES),
            (1, 2),
            (1000, 1001),
            (4096, 65_504),
            (7, 64 * 7),
        ] {
            let bytes = vec![9; length];
            let run = UdpRun {
                peer,
                segment,
                bytes: bytes.as_slice(),
            };
            let sent = GuestFrame::UdpSend(run.into_owned()).encode().unwrap();
            assert_eq!(
                GuestFrame::decode(&sent),
                Ok(Some((GuestFrame::UdpSend(run), sent.len())))
            );
            let mut coalesced = sent.clone();
            coalesced.extend_from_slice(&sent);
            assert_eq!(
                GuestFrame::decode(&coalesced),
                Ok(Some((GuestFrame::UdpSend(run), sent.len())))
            );
            let mut appended_send = Vec::new();
            GuestFrame::UdpSend(run).append(&mut appended_send).unwrap();
            assert_eq!(appended_send, sent);
            let mut appended_datagram = Vec::new();
            HostFrame::UdpDatagram(run)
                .append(&mut appended_datagram)
                .unwrap();
            assert_eq!(
                HostFrame::decode(&appended_datagram),
                Ok(Some((HostFrame::UdpDatagram(run), appended_datagram.len())))
            );
            let datagram = HostFrame::UdpDatagram(run.into_owned());
            assert_eq!(appended_datagram, datagram.encode().unwrap());
        }
        let mut failed = vec![5];
        for (segment, length) in [(100, 65_505), (0, 4097), (5000, 5001)] {
            let bytes = vec![0; length];
            let run = UdpRun {
                peer,
                segment,
                bytes: bytes.as_slice(),
            };
            assert!(HostFrame::UdpDatagram(run).append(&mut failed).is_err());
        }
        assert_eq!(failed, [5]);
    }

    #[test]
    fn udp_frames_pin_layout_and_the_frame_cap() {
        let peer: SocketAddr = "192.0.2.1:48879".parse().unwrap();
        let datagram = HostFrame::UdpDatagram(UdpRun {
            segment: 0,
            peer,
            bytes: vec![0xaa, 0xbb],
        })
        .encode()
        .unwrap();
        assert_eq!(
            datagram,
            [
                0x03, 0x01, 0, 0, 26, 0, 0, 0, 4, 0, 0xef, 0xbe, 192, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0xaa, 0xbb,
            ]
        );
        let segmented = GuestFrame::UdpSend(UdpRun {
            peer,
            segment: 2,
            bytes: vec![0xaa, 0xbb, 0xcc],
        })
        .encode()
        .unwrap();
        assert_eq!(
            segmented,
            [
                0x03, 0, 0, 0, 27, 0, 0, 0, 4, 0, 0xef, 0xbe, 192, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 2, 0, 0, 0, 0xaa, 0xbb, 0xcc,
            ]
        );
        let largest = HostFrame::UdpDatagram(UdpRun {
            peer: "[ffff::ffff]:65535".parse().unwrap(),
            segment: 4096,
            bytes: vec![0; MAX_UDP_RUN_BYTES],
        })
        .encode()
        .unwrap();
        assert_eq!(largest.len(), MAX_FRAME_BYTES);
    }

    #[test]
    fn segmented_frames_reject_invalid_runs_on_encode_and_decode() {
        let peer: SocketAddr = "192.0.2.1:9".parse().unwrap();
        let encode = |segment, length| {
            GuestFrame::UdpSend(UdpRun {
                peer,
                segment,
                bytes: vec![0; length],
            })
            .encode()
        };
        assert!(encode(1, 2).is_ok());
        for (segment, length) in [(4097, 8194), (1, 65), (1000, MAX_UDP_RUN_BYTES + 1)] {
            assert_eq!(
                encode(segment, length),
                Err(FrameError),
                "{segment} {length}"
            );
        }
        let valid = encode(100, 250).unwrap();
        let decode = decode_guest;
        assert!(decode(&valid).is_ok());
        for (offset, value) in [(29, 0x10), (30, 1), (31, 1)] {
            let mut forged = valid.clone();
            forged[offset] = value;
            assert_eq!(decode(&forged), Err(FrameError), "{offset}");
        }
        let mut oversized = valid.clone();
        set_payload_bytes(&mut oversized, MAX_FRAME_BYTES + 1 - HEADER_BYTES);
        assert_eq!(decode(&oversized), Err(FrameError));
        let mut plain_oversized = GuestFrame::UdpSend(UdpRun {
            peer,
            segment: 0,
            bytes: vec![],
        })
        .encode()
        .unwrap();
        set_payload_bytes(
            &mut plain_oversized,
            ENDPOINT_BYTES + UDP_SEGMENT_FIELD_BYTES + MAX_NETWORK_DATAGRAM_BYTES + 1,
        );
        assert_eq!(decode(&plain_oversized), Err(FrameError));
        for noncanonical_segment in [250_u16, 251, 4096] {
            let mut forged = valid.clone();
            forged[28..30].copy_from_slice(&noncanonical_segment.to_le_bytes());
            assert_eq!(decode(&forged), Err(FrameError));
        }
        assert_eq!(HostFrame::decode(&valid), Err(FrameError));
    }

    #[test]
    fn encode_and_append_write_segment_zero_when_the_run_is_one_datagram() {
        let peer: SocketAddr = "192.0.2.1:9".parse().unwrap();
        for (segment, length) in [(100, 100), (100, 50), (5000, 10), (1, 0), (1, 1)] {
            let bytes = vec![1; length];
            let canonical = HostFrame::UdpDatagram(UdpRun {
                peer,
                segment: 0,
                bytes: bytes.clone(),
            })
            .encode()
            .unwrap();
            let mut appended = Vec::new();
            let run = UdpRun {
                peer,
                segment,
                bytes: bytes.as_slice(),
            };
            HostFrame::UdpDatagram(run).append(&mut appended).unwrap();
            assert_eq!(appended, canonical);
            let encoded = HostFrame::UdpDatagram(UdpRun {
                peer,
                segment,
                bytes,
            })
            .encode()
            .unwrap();
            assert_eq!(encoded, canonical);
        }
    }

    /// The encoder refuses a frame past the cap the decoder applies, leaving the buffer as it was.
    #[test]
    fn append_frame_refuses_a_frame_over_the_frame_cap() {
        let fill = |payload_bytes: usize| {
            move |writer: &mut BodyWriter<'_>| {
                writer.0.resize(writer.0.len() + payload_bytes, 0);
                Ok(())
            }
        };
        let mut out = vec![5];
        assert_eq!(
            append_frame(
                &mut out,
                Opcode::Opened,
                fill(MAX_FRAME_BYTES - HEADER_BYTES + 1)
            ),
            Err(FrameError)
        );
        assert_eq!(out, [5]);
        append_frame(
            &mut out,
            Opcode::Opened,
            fill(MAX_FRAME_BYTES - HEADER_BYTES),
        )
        .unwrap();
        assert_eq!(out.len(), 1 + MAX_FRAME_BYTES);
    }

    #[test]
    fn stream_decoder_reads_in_place_across_every_split() {
        let peer: SocketAddr = "192.0.2.1:9".parse().unwrap();
        let frames = [
            HostFrame::UdpDatagram(UdpRun {
                peer,
                segment: 1000,
                bytes: vec![1; 40_000],
            }),
            HostFrame::UdpError {
                peer,
                error: SocketError::ConnectionRefused,
            },
            HostFrame::UdpDatagram(UdpRun {
                peer,
                segment: 0,
                bytes: vec![2; 4096],
            }),
            HostFrame::UdpDatagram(UdpRun {
                peer,
                segment: 4096,
                bytes: vec![3; MAX_UDP_RUN_BYTES],
            }),
        ];
        let stream: Vec<u8> = frames
            .iter()
            .flat_map(|frame| frame.encode().unwrap())
            .collect();
        for read_bytes in [1, 7, 4096, 30_001, MAX_FRAME_BYTES] {
            let mut decoder = StreamDecoder::default();
            let mut reader = stream.as_slice();
            let mut read_frames = Vec::new();
            loop {
                while let Some(frame) = next_host_frame(&mut decoder) {
                    read_frames.push(frame);
                }
                let buffer = decoder.read_buffer();
                let count = buffer.len().min(read_bytes).min(reader.len());
                buffer[..count].copy_from_slice(&reader[..count]);
                reader = &reader[count..];
                if count == 0 {
                    break;
                }
                decoder.commit(count);
            }
            assert_eq!(read_frames, frames, "{read_bytes}-byte reads");
            assert!(decoder.is_empty());
        }
    }

    /// A datagram run comes back borrowed from the decoder's buffer.
    #[test]
    fn stream_decoder_borrows_datagram_runs() {
        let peer: SocketAddr = "192.0.2.1:9".parse().unwrap();
        let datagram = HostFrame::UdpDatagram(UdpRun {
            peer,
            segment: 100,
            bytes: vec![5; 250],
        });
        let error = HostFrame::UdpError {
            peer,
            error: SocketError::Closed,
        };
        let mut decoder = StreamDecoder::default();
        feed(&mut decoder, &datagram.encode().unwrap());
        feed(&mut decoder, &error.encode().unwrap());
        assert_eq!(
            decoder.next_frame::<HostFrame<&[u8]>>(),
            Ok(Some(HostFrame::UdpDatagram(UdpRun {
                peer,
                segment: 100,
                bytes: &[5; 250][..],
            })))
        );
        assert_eq!(
            decoder.next_frame::<HostFrame<&[u8]>>(),
            Ok(Some(HostFrame::UdpError {
                peer,
                error: SocketError::Closed
            }))
        );
        assert_eq!(decoder.next_frame::<HostFrame<&[u8]>>(), Ok(None));
        assert!(decoder.is_empty());
    }

    #[test]
    fn stream_decoder_handles_split_coalesced_and_hostile_frames_with_bounded_storage() {
        let first = HostFrame::UdpDatagram(UdpRun {
            segment: 0,
            peer: "127.0.0.1:9".parse().unwrap(),
            bytes: b"first".to_vec(),
        });
        let second = HostFrame::UdpError {
            peer: "127.0.0.1:9".parse().unwrap(),
            error: SocketError::ConnectionRefused,
        };
        let mut bytes = first.encode().unwrap();
        bytes.extend_from_slice(&second.encode().unwrap());
        for split in 0..bytes.len() {
            let mut decoder = StreamDecoder::default();
            feed(&mut decoder, &bytes[..split]);
            let mut frames = Vec::new();
            while let Some(frame) = next_host_frame(&mut decoder) {
                frames.push(frame);
            }
            feed(&mut decoder, &bytes[split..]);
            while let Some(frame) = next_host_frame(&mut decoder) {
                frames.push(frame);
            }
            assert_eq!(frames, [first.clone(), second.clone()]);
            assert!(decoder.is_empty());
        }
        assert_eq!(
            StreamDecoder::default().read_buffer().len(),
            MAX_FRAME_BYTES
        );
    }
}
