//! Bounded messages for the network broker, one yamux stream per operation.

pub use crate::socket::Error;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};

/// One vsock packet's largest payload, so a TCP chunk crosses to the guest as one packet.
pub const MAX_NETWORK_CHUNK_BYTES: usize = 64 * 1024;
pub const MAX_NETWORK_READ_BYTES: usize = MAX_NETWORK_CHUNK_BYTES;
pub const MAX_NETWORK_DATAGRAM_BYTES: usize = 4096;
pub const MAX_NETWORK_NAME_BYTES: usize = 256;
pub const MAX_NETWORK_ADDRESSES: usize = 32;
pub const MAX_NETWORK_FRAME_BYTES: usize = MAX_NETWORK_READ_BYTES + 128;
pub const MAX_UDP_PEERS: usize = 16;
pub const MAX_NETWORK_DATAGRAMS: usize = 32;
/// Upper bound on one batched datagram's encoded peer and length prefix.
pub const DATAGRAM_FRAME_OVERHEAD_BYTES: usize = 32;
/// Budget for a datagram batch, counting [`Datagram::batch_bytes`], so the batch fits one frame.
pub const MAX_NETWORK_DATAGRAM_BATCH_BYTES: usize = 32 * 1024 - 64;
pub const UDP_PEER_TTL_SECS: u64 = 60;

pub type ListenerGrant = u32;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Datagram {
    pub peer: SocketAddr,
    #[serde(
        serialize_with = "serde_bytes::serialize",
        deserialize_with = "crate::bounded::bytes::<_, MAX_NETWORK_DATAGRAM_BYTES>"
    )]
    pub bytes: Vec<u8>,
}

impl Datagram {
    #[must_use]
    pub fn batch_bytes(&self) -> usize {
        self.bytes.len() + DATAGRAM_FRAME_OVERHEAD_BYTES
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
        inline_urgent: bool,
    },
    Accept(ListenerGrant),
    Udp,
    PublishedUdp(ListenerGrant),
    Resolve(
        #[serde(deserialize_with = "crate::bounded::string::<_, MAX_NETWORK_NAME_BYTES>")] String,
    ),
}

/// Broker reply to [`Open`], sent as `Result<Opened, Error>`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Opened {
    Tcp {
        peer: SocketAddr,
    },
    Udp,
    Resolved(
        #[serde(deserialize_with = "crate::bounded::vec::<_, _, MAX_NETWORK_ADDRESSES>")]
        Vec<IpAddr>,
    ),
}

/// Broker frames on a TCP stream; the client's upload is raw bytes ending in FIN.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TcpEvent {
    Data(
        #[serde(
            serialize_with = "serde_bytes::serialize",
            deserialize_with = "crate::bounded::bytes::<_, MAX_NETWORK_READ_BYTES>"
        )]
        Vec<u8>,
    ),
    Eof,
    /// Result of shutting down the write side after the client's FIN.
    WriteShutdown(Result<(), Error>),
    Failed(Error),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum UdpRequest {
    Send(
        #[serde(deserialize_with = "crate::bounded::vec::<_, _, MAX_NETWORK_DATAGRAMS>")]
        Vec<Datagram>,
    ),
    Receive,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum UdpReply {
    Sent(
        #[serde(deserialize_with = "crate::bounded::vec::<_, _, MAX_NETWORK_DATAGRAMS>")]
        Vec<SendFailure>,
    ),
    Datagrams(
        #[serde(deserialize_with = "crate::bounded::vec::<_, _, MAX_NETWORK_DATAGRAMS>")]
        Vec<Datagram>,
    ),
    Failed(Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{encode_frame, read_frame_with_limit};

    fn roundtrips<T>(message: &T) -> bool
    where
        T: Serialize + serde::de::DeserializeOwned + PartialEq,
    {
        read_frame_with_limit::<T>(
            &mut encode_frame(message).unwrap().as_slice(),
            MAX_NETWORK_FRAME_BYTES,
        )
        .ok()
        .flatten()
        .is_some_and(|decoded| decoded == *message)
    }

    #[test]
    fn network_frames_bound_collections_and_preserve_empty_datagrams() {
        let datagram = |bytes: usize| Datagram {
            peer: "[::1]:9".parse().unwrap(),
            bytes: vec![0; bytes],
        };
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
            UdpRequest::Send(vec![datagram(0)]),
            UdpRequest::Send(vec![datagram(MAX_NETWORK_DATAGRAM_BYTES)]),
            UdpRequest::Receive,
        ] {
            assert!(roundtrips(&request));
        }
        assert!(!roundtrips(&UdpRequest::Send(vec![datagram(
            MAX_NETWORK_DATAGRAM_BYTES + 1
        )])));
        assert!(!roundtrips(&UdpReply::Datagrams(vec![datagram(
            MAX_NETWORK_DATAGRAM_BYTES + 1
        )])));
        assert!(roundtrips(&TcpEvent::Data(vec![0; MAX_NETWORK_READ_BYTES])));
        assert!(!roundtrips(&TcpEvent::Data(vec![
            0;
            MAX_NETWORK_READ_BYTES + 1
        ])));
        assert!(roundtrips(&Ok::<_, Error>(Opened::Resolved(vec![
            "1.1.1.1".parse().unwrap();
            MAX_NETWORK_ADDRESSES
        ]))));
        assert!(!roundtrips(&Ok::<_, Error>(Opened::Resolved(vec![
            "1.1.1.1".parse().unwrap();
            MAX_NETWORK_ADDRESSES + 1
        ]))));
        let mut malicious = encode_frame(&TcpEvent::Data(vec![])).unwrap();
        malicious.pop();
        malicious.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0x0f]);
        let length = u32::try_from(malicious.len() - 4).unwrap();
        malicious[..4].copy_from_slice(&length.to_le_bytes());
        assert!(
            read_frame_with_limit::<TcpEvent>(&mut malicious.as_slice(), MAX_NETWORK_FRAME_BYTES)
                .is_err()
        );
    }

    /// A batch filled to its byte budget with the largest peer encoding fits one frame, and
    /// batches beyond the element limit are rejected.
    #[test]
    fn full_datagram_batches_fit_one_frame() {
        let peer: SocketAddr = "[ffff::ffff]:65535".parse().unwrap();
        let mut datagrams = Vec::new();
        let mut budget = MAX_NETWORK_DATAGRAM_BATCH_BYTES;
        while datagrams.len() < MAX_NETWORK_DATAGRAMS {
            let datagram = Datagram {
                peer,
                bytes: vec![
                    0xff;
                    (budget - DATAGRAM_FRAME_OVERHEAD_BYTES).min(MAX_NETWORK_DATAGRAM_BYTES)
                ],
            };
            budget -= datagram.batch_bytes();
            datagrams.push(datagram);
            if budget < DATAGRAM_FRAME_OVERHEAD_BYTES {
                break;
            }
        }
        for frame in [
            crate::encode_frame_with_limit(
                &UdpRequest::Send(datagrams.clone()),
                MAX_NETWORK_FRAME_BYTES,
            ),
            crate::encode_frame_with_limit(
                &UdpReply::Datagrams(datagrams),
                MAX_NETWORK_FRAME_BYTES,
            ),
        ] {
            assert!(frame.is_ok());
        }
        let small = vec![
            Datagram {
                peer,
                bytes: vec![],
            };
            MAX_NETWORK_DATAGRAMS
        ];
        assert!(roundtrips(&UdpRequest::Send(small.clone())));
        let mut oversized = small;
        oversized.push(oversized[0].clone());
        assert!(!roundtrips(&UdpRequest::Send(oversized)));
        assert!(!roundtrips(&UdpReply::Sent(vec![
            SendFailure {
                index: 0,
                error: Error::Io,
            };
            MAX_NETWORK_DATAGRAMS + 1
        ])));
    }

    #[test]
    fn read_events_fit_one_frame() {
        let event = TcpEvent::Data(vec![0x42; MAX_NETWORK_READ_BYTES]);
        assert!(encode_frame(&event).unwrap().len() <= MAX_NETWORK_FRAME_BYTES);
        assert!(roundtrips(&event));
    }

    #[test]
    fn bulk_byte_fields_preserve_the_network_wire_format() {
        let peer: SocketAddr = "192.0.2.1:53".parse().unwrap();
        for length in [0, 1, 127, 128, MAX_NETWORK_DATAGRAM_BYTES] {
            let bytes: Vec<u8> = (0..=255).cycle().take(length).collect();
            let event = TcpEvent::Data(bytes.clone());
            assert_eq!(
                encode_frame(&event).unwrap(),
                encode_frame(&(0_u32, &bytes)).unwrap()
            );
            assert!(roundtrips(&event));
            let request = UdpRequest::Send(vec![Datagram {
                peer,
                bytes: bytes.clone(),
            }]);
            assert_eq!(
                encode_frame(&request).unwrap(),
                encode_frame(&(0_u32, 1_u8, peer, &bytes)).unwrap()
            );
            assert!(roundtrips(&request));
            let reply = UdpReply::Datagrams(vec![Datagram { peer, bytes }]);
            assert!(roundtrips(&reply));
        }
        assert_eq!(
            encode_frame(&TcpEvent::WriteShutdown(Ok(()))).unwrap(),
            encode_frame(&(2_u32, 0_u32)).unwrap()
        );
    }
}
