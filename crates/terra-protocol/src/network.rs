//! Bounded messages for the network broker, one yamux stream per operation.

use crate::application::{
    MAX_FRAME_BYTES, MAX_NETWORK_DATAGRAM_BYTES, TcpOpenOptions, UDP_FRAME_OVERHEAD_BYTES,
    extends_udp_run, is_valid_udp_run,
};
use crate::socket::Error;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};

/// One switch delivery's largest payload, so a TCP chunk fits one delivery.
pub const MAX_NETWORK_CHUNK_BYTES: usize = crate::vsock::MAX_PACKET_DATA_BYTES as usize;
pub const MAX_NETWORK_NAME_BYTES: usize = 256;
pub const MAX_NETWORK_ADDRESSES: usize = 32;
pub const MAX_NETWORK_PAYLOAD_BYTES: usize = MAX_NETWORK_CHUNK_BYTES + 128;
pub const MAX_UDP_PUBLICATION_PEERS: usize = 16;
pub const MAX_NETWORK_DATAGRAMS: usize = 64;
/// Budget for a datagram batch, counting [`DatagramBatch::batch_bytes`].
pub const MAX_NETWORK_DATAGRAM_BATCH_BYTES: usize = MAX_NETWORK_CHUNK_BYTES;
pub const UDP_PEER_TTL_SECS: u64 = 60;

const _: () = assert!(MAX_NETWORK_DATAGRAM_BATCH_BYTES <= MAX_NETWORK_PAYLOAD_BYTES);
const _: () = assert!(MAX_FRAME_BYTES <= MAX_NETWORK_DATAGRAM_BATCH_BYTES);

/// What a batch of `entries` entries holding `bytes` datagram bytes counts against
/// [`MAX_NETWORK_DATAGRAM_BATCH_BYTES`]: each entry costs the UDP frame it becomes in the guest.
#[must_use]
pub const fn datagram_batch_bytes(entries: usize, bytes: usize) -> usize {
    bytes + entries * UDP_FRAME_OVERHEAD_BYTES
}

/// Whether `entries` entries holding `bytes` datagram bytes fit one batch.
#[must_use]
pub const fn is_within_datagram_batch_limits(entries: usize, bytes: usize) -> bool {
    entries <= MAX_NETWORK_DATAGRAMS
        && datagram_batch_bytes(entries, bytes) <= MAX_NETWORK_DATAGRAM_BATCH_BYTES
}

pub type ListenerGrant = u32;

/// One entry of a [`DatagramBatch`]: `length` bytes to or from `peer`. A `segment` of 0 is one
/// datagram; otherwise the entry is `segment`-byte datagrams, the last possibly shorter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatagramHeader {
    pub peer: SocketAddr,
    pub length: u16,
    pub segment: u16,
}

impl DatagramHeader {
    #[must_use]
    pub fn is_valid(&self) -> bool {
        is_valid_udp_run(usize::from(self.length), usize::from(self.segment))
    }
}

#[derive(Deserialize)]
struct RawDatagramBatch {
    #[serde(deserialize_with = "crate::bounded::vec::<_, _, MAX_NETWORK_DATAGRAMS>")]
    headers: Vec<DatagramHeader>,
    #[serde(deserialize_with = "crate::bounded::bytes::<_, MAX_NETWORK_DATAGRAM_BATCH_BYTES>")]
    bytes: Vec<u8>,
}

/// Datagrams packed into one buffer: entry `i` is the next `headers[i].length` bytes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawDatagramBatch")]
pub struct DatagramBatch {
    headers: Vec<DatagramHeader>,
    #[serde(serialize_with = "serde_bytes::serialize")]
    bytes: Vec<u8>,
}

impl TryFrom<RawDatagramBatch> for DatagramBatch {
    type Error = &'static str;
    fn try_from(raw: RawDatagramBatch) -> Result<Self, Self::Error> {
        Self::from_parts(raw.headers, raw.bytes).ok_or("malformed datagram batch")
    }
}

impl DatagramBatch {
    /// `None` unless every header is valid, the lengths add up to `bytes`, and the batch is within its count and byte limits.
    #[must_use]
    pub fn from_parts(headers: Vec<DatagramHeader>, bytes: Vec<u8>) -> Option<Self> {
        if !headers.iter().all(DatagramHeader::is_valid) {
            return None;
        }
        let total: usize = headers
            .iter()
            .map(|header| usize::from(header.length))
            .sum();
        let batch = Self { headers, bytes };
        (total == batch.bytes.len()
            && is_within_datagram_batch_limits(batch.headers.len(), batch.bytes.len()))
        .then_some(batch)
    }

    #[must_use]
    pub fn into_parts(self) -> (Vec<DatagramHeader>, Vec<u8>) {
        (self.headers, self.bytes)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.headers.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.headers.is_empty()
    }

    #[must_use]
    pub fn batch_bytes(&self) -> usize {
        datagram_batch_bytes(self.len(), self.bytes.len())
    }

    #[must_use]
    pub fn has_room_for_datagram(&self) -> bool {
        self.has_room_for_entry(MAX_NETWORK_DATAGRAM_BYTES)
    }

    fn has_room_for_entry(&self, length: usize) -> bool {
        is_within_datagram_batch_limits(self.len() + 1, self.bytes.len() + length)
    }

    /// Appends one datagram, merging it into the last entry's run where possible. `false` leaves
    /// the batch unchanged because `bytes` is too long or the batch is full.
    pub fn push(&mut self, peer: SocketAddr, bytes: &[u8]) -> bool {
        let Ok(length) = u16::try_from(bytes.len()) else {
            return false;
        };
        let batch_bytes = self.batch_bytes();
        if let Some(last) = self.headers.last_mut() {
            let segment = if last.segment == 0 {
                last.length
            } else {
                last.segment
            };
            if last.peer == peer
                && extends_udp_run(usize::from(last.length), usize::from(segment), bytes.len())
                && batch_bytes + bytes.len() <= MAX_NETWORK_DATAGRAM_BATCH_BYTES
            {
                last.segment = segment;
                last.length += length;
                self.bytes.extend_from_slice(bytes);
                return true;
            }
        }
        if bytes.len() > MAX_NETWORK_DATAGRAM_BYTES || !self.has_room_for_entry(bytes.len()) {
            return false;
        }
        self.bytes.extend_from_slice(bytes);
        self.headers.push(DatagramHeader {
            peer,
            length,
            segment: 0,
        });
        true
    }

    /// Appends `bytes` as `stride`-byte datagrams from `peer`, stopping at the first datagram
    /// that does not fit. Returns how many bytes were taken, always a whole number of datagrams.
    pub fn push_run(&mut self, peer: SocketAddr, bytes: &[u8], stride: usize) -> usize {
        if bytes.is_empty() {
            self.push(peer, bytes);
            return 0;
        }
        let mut taken = 0;
        for datagram in bytes.chunks(stride.max(1)) {
            if !self.push(peer, datagram) {
                break;
            }
            taken += datagram.len();
        }
        taken
    }

    /// Entries as peer, segment (0 for a single datagram), and bytes.
    pub fn entries(&self) -> impl Iterator<Item = (SocketAddr, u16, &[u8])> {
        let mut rest = self.bytes.as_slice();
        self.headers.iter().map(move |header| {
            let (run, tail) = rest.split_at(usize::from(header.length));
            rest = tail;
            (header.peer, header.segment, run)
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn datagrams(&self) -> impl Iterator<Item = (SocketAddr, &[u8])> {
        self.entries().flat_map(|(peer, segment, run)| {
            let size = if segment == 0 {
                run.len().max(1)
            } else {
                usize::from(segment)
            };
            let empty_datagram = run.is_empty().then_some(run);
            run.chunks(size)
                .chain(empty_datagram)
                .map(move |datagram| (peer, datagram))
        })
    }
}

/// A datagram of a batch that was not sent, by its index in the request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SendFailure {
    pub index: u32,
    pub error: Error,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResourceKind {
    Tcp,
    Udp,
}

/// First client frame on every stream.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Open {
    Tcp {
        peer: SocketAddr,
        options: TcpOpenOptions,
    },
    Accept(ListenerGrant),
    Udp,
    PublishedUdp(ListenerGrant),
    Resolve(
        #[serde(deserialize_with = "crate::bounded::string::<_, MAX_NETWORK_NAME_BYTES>")] String,
    ),
}

impl crate::Message for Open {
    const MAX_PAYLOAD_BYTES: usize = MAX_NETWORK_PAYLOAD_BYTES;
}

/// Broker reply to [`Open::Resolve`], sent as `Result<Resolved, Error>`; every other [`Open`] is
/// answered `Result<(), Error>`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resolved(
    #[serde(deserialize_with = "crate::bounded::vec::<_, _, MAX_NETWORK_ADDRESSES>")]
    pub  Vec<IpAddr>,
);

impl crate::Message for Result<Resolved, Error> {
    const MAX_PAYLOAD_BYTES: usize = MAX_NETWORK_PAYLOAD_BYTES;
}

impl crate::Message for Result<(), Error> {
    const MAX_PAYLOAD_BYTES: usize = 2;
}

/// Broker frames on a TCP stream; the client's upload is raw bytes ending in FIN.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TcpEvent {
    Data(
        #[serde(
            serialize_with = "serde_bytes::serialize",
            deserialize_with = "crate::bounded::bytes::<_, MAX_NETWORK_CHUNK_BYTES>"
        )]
        Vec<u8>,
    ),
    Eof,
    /// Result of shutting down the write side after the client's FIN.
    WriteShutdown(Result<(), Error>),
    Failed(Error),
}

impl crate::Message for TcpEvent {
    const MAX_PAYLOAD_BYTES: usize = MAX_NETWORK_PAYLOAD_BYTES;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum UdpRequest {
    Send(DatagramBatch),
    Receive,
}

impl crate::Message for UdpRequest {
    const MAX_PAYLOAD_BYTES: usize = MAX_NETWORK_PAYLOAD_BYTES;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum UdpReply {
    Sent(
        #[serde(deserialize_with = "crate::bounded::vec::<_, _, MAX_NETWORK_DATAGRAMS>")]
        Vec<SendFailure>,
    ),
    Datagrams(DatagramBatch),
    Failed(Error),
}

impl crate::Message for UdpReply {
    const MAX_PAYLOAD_BYTES: usize = MAX_NETWORK_PAYLOAD_BYTES;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::MAX_DATAGRAM_SEGMENTS;
    use crate::frames::frame_bytes;
    use crate::{Message, encode_frame, read_frame};

    fn roundtrips<T: Message + PartialEq>(message: &T) -> bool {
        read_frame::<T>(&mut encode_frame(message).unwrap().as_slice())
            .ok()
            .flatten()
            .is_some_and(|decoded| decoded == *message)
    }

    fn batch_of(lengths: &[usize]) -> DatagramBatch {
        let peer = "[::1]:9".parse().unwrap();
        let mut batch = DatagramBatch::default();
        for length in lengths {
            assert!(batch.push(peer, &vec![7; *length]));
        }
        batch
    }

    #[test]
    fn tcp_open_options_round_trip_and_reject_out_of_range_keepalive() {
        use crate::application::{MAX_KEEPALIVE_PROBES, MAX_KEEPALIVE_SECS, TcpKeepalive};
        let peer: SocketAddr = "203.0.113.1:443".parse().unwrap();
        let open = |options| Open::Tcp { peer, options };
        assert!(roundtrips(&open(TcpOpenOptions::default())));
        assert!(roundtrips(&open(TcpOpenOptions {
            inline_urgent: true,
            keepalive: TcpKeepalive::new(MAX_KEEPALIVE_SECS, 1, MAX_KEEPALIVE_PROBES),
        })));
        for (idle_secs, interval_secs, probe_count) in [
            (0, 1, 1),
            (1, 0, 1),
            (1, 1, 0),
            (MAX_KEEPALIVE_SECS + 1, 1, 1),
            (1, MAX_KEEPALIVE_SECS + 1, 1),
            (1, 1, MAX_KEEPALIVE_PROBES + 1),
        ] {
            let payload = postcard::to_allocvec(&RawKeepaliveForTest {
                idle_secs,
                interval_secs,
                probe_count,
            })
            .unwrap();
            assert!(postcard::from_bytes::<TcpKeepalive>(&payload).is_err());
        }
    }

    #[test]
    fn network_frames_bound_collections_and_preserve_empty_datagrams() {
        for open in [
            Open::PublishedUdp(1),
            Open::Resolve("a".repeat(MAX_NETWORK_NAME_BYTES)),
        ] {
            assert!(roundtrips(&open));
        }
        assert!(!roundtrips(&Open::Resolve(
            "a".repeat(MAX_NETWORK_NAME_BYTES + 1)
        )));
        for request in [
            UdpRequest::Send(batch_of(&[0])),
            UdpRequest::Send(batch_of(&[MAX_NETWORK_DATAGRAM_BYTES])),
            UdpRequest::Receive,
        ] {
            assert!(roundtrips(&request));
        }
        assert!(roundtrips(&TcpEvent::Data(vec![
            0;
            MAX_NETWORK_CHUNK_BYTES
        ])));
        assert!(!roundtrips(&TcpEvent::Data(vec![
            0;
            MAX_NETWORK_CHUNK_BYTES
                + 1
        ])));
        assert!(roundtrips(&Ok::<_, Error>(Resolved(vec![
            "1.1.1.1".parse().unwrap();
            MAX_NETWORK_ADDRESSES
        ]))));
        assert!(!roundtrips(&Ok::<_, Error>(Resolved(vec![
            "1.1.1.1"
                .parse()
                .unwrap();
            MAX_NETWORK_ADDRESSES
                + 1
        ]))));
        assert!(roundtrips(&Ok::<(), Error>(())));
        assert!(roundtrips(&Err::<(), _>(Error::Protocol)));
        let mut malicious = encode_frame(&TcpEvent::Data(vec![])).unwrap();
        malicious.pop();
        malicious.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0x0f]);
        let length = u32::try_from(malicious.len() - 4).unwrap();
        malicious[..4].copy_from_slice(&length.to_le_bytes());
        assert!(read_frame::<TcpEvent>(&mut malicious.as_slice()).is_err());
    }

    /// A batch filled to its byte budget with the largest peer encoding fits one frame, and
    /// batches beyond the element limit are rejected.
    #[test]
    fn full_datagram_batches_fit_one_frame() {
        let peer: SocketAddr = "[ffff::ffff]:65535".parse().unwrap();
        for length in [MAX_NETWORK_DATAGRAM_BYTES, 1, 0] {
            let mut batch = DatagramBatch::default();
            while batch.has_room_for_datagram() {
                assert!(batch.push(peer, &vec![0xff; length]));
            }
            while batch.push(peer, &vec![0xff; length]) {}
            assert!(batch.batch_bytes() <= MAX_NETWORK_DATAGRAM_BATCH_BYTES);
            for frame in [
                encode_frame(&UdpRequest::Send(batch.clone())),
                encode_frame(&UdpReply::Datagrams(batch.clone())),
            ] {
                assert!(frame.is_ok());
            }
            assert!(guest_frames_bytes(&batch) <= MAX_NETWORK_DATAGRAM_BATCH_BYTES);
            assert!(roundtrips(&UdpRequest::Send(batch)));
        }
        for segment in [1, 1000, MAX_NETWORK_DATAGRAM_BYTES] {
            let length = crate::application::MAX_UDP_RUN_BYTES
                .min(segment * crate::application::MAX_DATAGRAM_SEGMENTS);
            let header = DatagramHeader {
                peer,
                length: u16::try_from(length).unwrap(),
                segment: u16::try_from(segment).unwrap(),
            };
            let batch = DatagramBatch::from_parts(vec![header], vec![0xff; length]).unwrap();
            assert!(guest_frames_bytes(&batch) <= MAX_NETWORK_DATAGRAM_BATCH_BYTES);
            assert!(roundtrips(&UdpReply::Datagrams(batch)));
        }
        let maximal = DatagramHeader {
            peer,
            length: u16::try_from(crate::application::MAX_UDP_RUN_BYTES).unwrap(),
            segment: u16::try_from(MAX_NETWORK_DATAGRAM_BYTES).unwrap(),
        };
        let batch = DatagramBatch::from_parts(
            vec![maximal],
            vec![0; crate::application::MAX_UDP_RUN_BYTES],
        )
        .unwrap();
        assert_eq!(batch.batch_bytes(), MAX_NETWORK_DATAGRAM_BATCH_BYTES);
        assert_eq!(guest_frames_bytes(&batch), MAX_NETWORK_DATAGRAM_BATCH_BYTES);
        assert!(!batch.has_room_for_datagram());
        let small = batch_of(&[0; MAX_NETWORK_DATAGRAMS]);
        assert_eq!(small.len(), MAX_NETWORK_DATAGRAMS);
        assert!(roundtrips(&UdpRequest::Send(small.clone())));
        let (mut headers, bytes) = small.into_parts();
        headers.push(headers[0]);
        assert!(DatagramBatch::from_parts(headers.clone(), bytes.clone()).is_none());
        let oversized = RawBatchForTest { headers, bytes };
        assert!(!roundtrips_raw(&oversized));
        assert!(!roundtrips(&UdpReply::Sent(vec![
            SendFailure {
                index: 0,
                error: Error::Io,
            };
            MAX_NETWORK_DATAGRAMS + 1
        ])));
    }

    /// Total size of the guest frames the frontend writes for `batch`.
    fn guest_frames_bytes(batch: &DatagramBatch) -> usize {
        let mut frames = Vec::new();
        for (peer, segment, bytes) in batch.entries() {
            let run = crate::application::UdpRun {
                peer,
                segment,
                bytes,
            };
            crate::application::HostFrame::UdpDatagram(run)
                .append(&mut frames)
                .unwrap();
        }
        frames.len()
    }

    /// The same shape as [`DatagramBatch`] on the wire, but constructible without validation.
    #[derive(Serialize)]
    struct RawBatchForTest {
        headers: Vec<DatagramHeader>,
        #[serde(serialize_with = "serde_bytes::serialize")]
        bytes: Vec<u8>,
    }

    #[derive(Serialize)]
    struct RawKeepaliveForTest {
        idle_secs: u16,
        interval_secs: u16,
        probe_count: u16,
    }

    fn roundtrips_raw(raw: &RawBatchForTest) -> bool {
        let frame = frame_bytes(&(1_u32, raw));
        matches!(read_frame::<UdpRequest>(&mut frame.as_slice()), Ok(Some(_)))
    }

    #[test]
    fn datagram_batches_reject_inconsistent_parts_on_construction_and_decode() {
        let peer: SocketAddr = "192.0.2.1:53".parse().unwrap();
        let header = |length| DatagramHeader {
            peer,
            length,
            segment: 0,
        };
        let segmented = |length, segment| DatagramHeader {
            peer,
            length,
            segment,
        };
        assert!(DatagramBatch::from_parts(vec![], vec![]).is_some());
        assert!(DatagramBatch::from_parts(vec![header(0), header(2)], vec![1, 2]).is_some());
        assert!(
            DatagramBatch::from_parts(vec![segmented(3, 2), segmented(64, 1)], vec![0; 67])
                .is_some()
        );
        for (headers, bytes) in [
            (vec![header(2)], vec![1]),
            (vec![header(1)], vec![1, 2]),
            (vec![], vec![1]),
            (vec![header(4097)], vec![0; 4097]),
            (
                vec![header(1); MAX_NETWORK_DATAGRAMS + 1],
                vec![0; MAX_NETWORK_DATAGRAMS + 1],
            ),
            (vec![header(4096); 16], vec![0; 16 * 4096]),
            (vec![segmented(10, 10)], vec![0; 10]),
            (vec![segmented(5, 10)], vec![0; 5]),
            (vec![segmented(8192, 4097)], vec![0; 8192]),
            (vec![segmented(65, 1)], vec![0; 65]),
            (vec![segmented(2, 1), segmented(1, 1)], vec![0; 3]),
            (vec![segmented(65_505, 4096)], vec![0; 65_505]),
        ] {
            assert!(DatagramBatch::from_parts(headers.clone(), bytes.clone()).is_none());
            assert!(!roundtrips_raw(&RawBatchForTest { headers, bytes }));
        }
        let mut batch = DatagramBatch::default();
        assert!(batch.push(peer, &[]));
        assert!(batch.push(peer, &[9]));
        assert!(!batch.push(peer, &vec![0; MAX_NETWORK_DATAGRAM_BYTES + 1]));
        assert_eq!(batch.len(), 2);
        assert_eq!(
            batch.datagrams().collect::<Vec<_>>(),
            [(peer, &[][..]), (peer, &[9][..])]
        );
        assert!(roundtrips(&UdpReply::Datagrams(batch)));
    }

    fn shapes(batch: &DatagramBatch) -> Vec<(u16, usize)> {
        batch
            .entries()
            .map(|(_, segment, bytes)| (segment, bytes.len()))
            .collect()
    }

    /// A datagram continues the last entry only for the same peer, a size no larger than the
    /// entry's segment, and an entry not yet ended by a shorter datagram.
    #[test]
    fn pushed_datagrams_merge_into_runs_of_one_peer_and_segment_size() {
        let peer: SocketAddr = "192.0.2.1:53".parse().unwrap();
        let other: SocketAddr = "192.0.2.2:53".parse().unwrap();
        let mut batch = DatagramBatch::default();
        for (to, size) in [
            (peer, 10),
            (peer, 10),
            (peer, 10),
            (peer, 4),
            (peer, 10),
            (peer, 0),
            (other, 10),
            (peer, 10),
            (peer, 11),
        ] {
            assert!(batch.push(to, &vec![u8::try_from(size).unwrap(); size]));
        }
        assert_eq!(
            shapes(&batch),
            [(10, 34), (0, 10), (0, 0), (0, 10), (0, 10), (0, 11)]
        );
        assert_eq!(batch.len(), 6);
        assert_eq!(batch.datagrams().count(), 9);
        let sizes: Vec<_> = batch.datagrams().map(|(_, bytes)| bytes.len()).collect();
        assert_eq!(sizes, [10, 10, 10, 4, 10, 0, 10, 10, 11]);
        let (headers, bytes) = batch.into_parts();
        assert!(DatagramBatch::from_parts(headers, bytes).is_some());
    }

    #[test]
    fn merged_runs_stop_at_the_segment_count_and_frame_limits() {
        let peer: SocketAddr = "192.0.2.1:53".parse().unwrap();
        let mut batch = DatagramBatch::default();
        for _ in 0..=MAX_DATAGRAM_SEGMENTS {
            assert!(batch.push(peer, &[1]));
        }
        assert_eq!(shapes(&batch), [(1, MAX_DATAGRAM_SEGMENTS), (0, 1)]);
        let mut batch = DatagramBatch::default();
        while batch.push(peer, &[2; MAX_NETWORK_DATAGRAM_BYTES]) {}
        assert_eq!(batch.len(), 1);
        assert!(batch.batch_bytes() <= MAX_NETWORK_DATAGRAM_BATCH_BYTES);
        assert!(
            batch.batch_bytes() > MAX_NETWORK_DATAGRAM_BATCH_BYTES - MAX_NETWORK_DATAGRAM_BYTES
        );
        assert!(!batch.push(peer, &[2; MAX_NETWORK_DATAGRAM_BYTES]));
    }

    #[test]
    fn pushed_runs_take_whole_datagrams_and_report_how_many_bytes_fit() {
        let peer: SocketAddr = "192.0.2.1:53".parse().unwrap();
        let mut batch = DatagramBatch::default();
        assert_eq!(batch.push_run(peer, &[3; 250], 100), 250);
        assert_eq!(shapes(&batch), [(100, 250)]);
        assert_eq!(batch.push_run(peer, &[], 0), 0);
        assert_eq!(batch.len(), 2);
        let other: SocketAddr = "192.0.2.2:53".parse().unwrap();
        let run = vec![1; 4 * MAX_NETWORK_DATAGRAM_BYTES];
        let mut taken = 0;
        let mut calls = 0;
        while taken < run.len() {
            let mut nearly_full = DatagramBatch::default();
            for _ in 0..14 {
                assert!(nearly_full.push(other, &[0; MAX_NETWORK_DATAGRAM_BYTES]));
            }
            let step = nearly_full.push_run(peer, &run[taken..], MAX_NETWORK_DATAGRAM_BYTES);
            assert_eq!(step, MAX_NETWORK_DATAGRAM_BYTES);
            taken += step;
            calls += 1;
        }
        assert_eq!(calls, 4);
        let mut batch = DatagramBatch::default();
        assert_eq!(batch.push_run(peer, &[1; 5000], 5000), 0);
        assert!(batch.is_empty());
    }

    #[test]
    fn read_events_fit_one_frame() {
        let event = TcpEvent::Data(vec![0x42; MAX_NETWORK_CHUNK_BYTES]);
        assert!(encode_frame(&event).unwrap().len() <= MAX_NETWORK_PAYLOAD_BYTES);
        assert!(roundtrips(&event));
    }

    #[test]
    fn bulk_byte_fields_preserve_the_network_wire_format() {
        let peer: SocketAddr = "192.0.2.1:53".parse().unwrap();
        for length in [0, 1, 127, 128, MAX_NETWORK_DATAGRAM_BYTES] {
            let bytes: Vec<u8> = (0..=255).cycle().take(length).collect();
            let event = TcpEvent::Data(bytes.clone());
            assert_eq!(encode_frame(&event).unwrap(), frame_bytes(&(0_u32, &bytes)));
            assert!(roundtrips(&event));
            let mut batch = DatagramBatch::default();
            assert!(batch.push(peer, &bytes));
            let request = UdpRequest::Send(batch.clone());
            let header = (peer, u16::try_from(length).unwrap(), 0_u16);
            assert_eq!(
                encode_frame(&request).unwrap(),
                frame_bytes(&(0_u32, vec![header], serde_bytes::Bytes::new(&bytes)))
            );
            assert!(roundtrips(&request));
            assert!(roundtrips(&UdpReply::Datagrams(batch)));
        }
        assert_eq!(
            encode_frame(&TcpEvent::WriteShutdown(Ok(()))).unwrap(),
            frame_bytes(&(2_u32, 0_u32))
        );
    }
}
