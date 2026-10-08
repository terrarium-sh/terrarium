//! Bounded request/reply messages for the network broker.

use serde::{Deserialize, Deserializer, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

pub const MAX_NETWORK_CHUNK_BYTES: usize = 8 * 1024;
pub const MAX_NETWORK_READ_BYTES: usize = 32704;
pub const MAX_NETWORK_DATAGRAM_BYTES: usize = 4096;
pub const MAX_NETWORK_NAME_BYTES: usize = 256;
pub const MAX_NETWORK_ADDRESSES: usize = 32;
pub const MAX_NETWORK_FRAME_BYTES: usize = MAX_NETWORK_READ_BYTES + 128;
pub const MAX_UDP_PEERS: usize = 16;
pub const MAX_NETWORK_DATAGRAMS: usize = 32;
/// Upper bound on one batched datagram's encoded peer and length prefix.
pub const DATAGRAM_FRAME_OVERHEAD_BYTES: usize = 32;
/// Budget for a datagram batch, counting [`Datagram::batch_bytes`], so the batch fits one frame.
pub const MAX_NETWORK_DATAGRAM_BATCH_BYTES: usize = MAX_NETWORK_READ_BYTES;
pub const UDP_PEER_TTL_SECS: u64 = 60;

/// The `peer` an unconnected UDP resource reports when opened.
pub const UNBOUND_UDP_PEER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);

pub type RequestId = u64;
pub type Handle = u64;
pub type ListenerGrant = u32;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Datagram {
    pub peer: SocketAddr,
    #[serde(
        serialize_with = "serde_bytes::serialize",
        deserialize_with = "decode_datagram"
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub id: RequestId,
    pub operation: Operation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Operation {
    OpenTcp {
        peer: SocketAddr,
        inline_urgent: bool,
    },
    OpenUdp,
    Accept(ListenerGrant),
    Read {
        handle: Handle,
        max_bytes: u32,
    },
    ReceiveDatagram(Handle),
    SendDatagrams {
        handle: Handle,
        #[serde(deserialize_with = "decode_datagrams")]
        datagrams: Vec<Datagram>,
    },
    ShutdownWrite(Handle),
    Resolve(#[serde(deserialize_with = "decode_name")] String),
    Cancel(RequestId),
    Close(Handle),
    WriteAll {
        handle: Handle,
        #[serde(
            serialize_with = "serde_bytes::serialize",
            deserialize_with = "decode_chunk"
        )]
        bytes: Vec<u8>,
    },
    OpenPublishedUdp(ListenerGrant),
    WaitError(Handle),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Error {
    AccessDenied,
    InvalidArgument,
    InvalidState,
    StaleHandle,
    WrongKind,
    Busy,
    LimitExceeded,
    DuplicateRequest,
    Cancelled,
    ConnectionRefused,
    ConnectionReset,
    TimedOut,
    NameUnresolvable,
    ResolverBusy,
    DatagramTooLarge,
    Closed,
    Io,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Response {
    pub id: RequestId,
    pub result: Result<Reply, Error>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reply {
    Opened {
        handle: Handle,
        kind: ResourceKind,
        peer: SocketAddr,
    },
    Data(
        #[serde(
            serialize_with = "serde_bytes::serialize",
            deserialize_with = "decode_read"
        )]
        Vec<u8>,
    ),
    Eof,
    Written(u32),
    Datagrams(#[serde(deserialize_with = "decode_datagrams")] Vec<Datagram>),
    Resolved(#[serde(deserialize_with = "decode_addresses")] Vec<IpAddr>),
    Cancelled(bool),
    Done,
    Sent(#[serde(deserialize_with = "decode_send_failures")] Vec<SendFailure>),
}

fn decode_bounded_vec<'de, D: Deserializer<'de>, T: Deserialize<'de>, const MAX: usize>(
    decoder: D,
) -> Result<Vec<T>, D::Error> {
    struct Bounded<T, const MAX: usize>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>, const MAX: usize> serde::de::Visitor<'de> for Bounded<T, MAX> {
        type Value = Vec<T>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(formatter, "at most {MAX} elements")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut sequence: A,
        ) -> Result<Vec<T>, A::Error> {
            if sequence.size_hint().is_some_and(|size| size > MAX) {
                return Err(serde::de::Error::custom("network collection exceeds limit"));
            }
            let mut values = Vec::new();
            while let Some(value) = sequence.next_element()? {
                if values.len() == MAX {
                    return Err(serde::de::Error::custom("network collection exceeds limit"));
                }
                values.push(value);
            }
            Ok(values)
        }
    }
    decoder.deserialize_seq(Bounded::<T, MAX>(std::marker::PhantomData))
}

fn decode_chunk<'de, D: Deserializer<'de>>(decoder: D) -> Result<Vec<u8>, D::Error> {
    decode_bounded_bytes::<D, MAX_NETWORK_CHUNK_BYTES>(decoder)
}
fn decode_read<'de, D: Deserializer<'de>>(decoder: D) -> Result<Vec<u8>, D::Error> {
    decode_bounded_bytes::<D, MAX_NETWORK_READ_BYTES>(decoder)
}
fn decode_datagram<'de, D: Deserializer<'de>>(decoder: D) -> Result<Vec<u8>, D::Error> {
    decode_bounded_bytes::<D, MAX_NETWORK_DATAGRAM_BYTES>(decoder)
}

fn decode_bounded_bytes<'de, D: Deserializer<'de>, const MAX: usize>(
    decoder: D,
) -> Result<Vec<u8>, D::Error> {
    struct BoundedBytes<const MAX: usize>;

    impl<'de, const MAX: usize> serde::de::Visitor<'de> for BoundedBytes<MAX> {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(formatter, "at most {MAX} bytes")
        }

        fn visit_bytes<E: serde::de::Error>(self, bytes: &[u8]) -> Result<Vec<u8>, E> {
            if bytes.len() > MAX {
                return Err(E::custom("network bytes exceed limit"));
            }
            Ok(bytes.to_vec())
        }

        fn visit_seq<A: serde::de::SeqAccess<'de>>(self, sequence: A) -> Result<Vec<u8>, A::Error> {
            decode_bounded_vec::<_, u8, MAX>(serde::de::value::SeqAccessDeserializer::new(sequence))
        }
    }

    decoder.deserialize_bytes(BoundedBytes::<MAX>)
}
fn decode_datagrams<'de, D: Deserializer<'de>>(decoder: D) -> Result<Vec<Datagram>, D::Error> {
    decode_bounded_vec::<D, Datagram, MAX_NETWORK_DATAGRAMS>(decoder)
}
fn decode_send_failures<'de, D: Deserializer<'de>>(
    decoder: D,
) -> Result<Vec<SendFailure>, D::Error> {
    decode_bounded_vec::<D, SendFailure, MAX_NETWORK_DATAGRAMS>(decoder)
}
fn decode_addresses<'de, D: Deserializer<'de>>(decoder: D) -> Result<Vec<IpAddr>, D::Error> {
    decode_bounded_vec::<D, IpAddr, MAX_NETWORK_ADDRESSES>(decoder)
}
fn decode_name<'de, D: Deserializer<'de>>(decoder: D) -> Result<String, D::Error> {
    struct Name;
    impl serde::de::Visitor<'_> for Name {
        type Value = String;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                formatter,
                "a hostname of at most {MAX_NETWORK_NAME_BYTES} bytes"
            )
        }
        fn visit_str<E: serde::de::Error>(self, name: &str) -> Result<String, E> {
            if name.len() > MAX_NETWORK_NAME_BYTES {
                return Err(E::custom("network hostname exceeds limit"));
            }
            Ok(name.into())
        }
    }
    decoder.deserialize_str(Name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{encode_frame, read_frame_with_limit};

    #[test]
    fn network_frames_bound_collections_and_preserve_empty_datagrams() {
        for operation in [
            Operation::OpenPublishedUdp(1),
            Operation::WaitError(1),
            Operation::SendDatagrams {
                handle: 1,
                datagrams: vec![Datagram {
                    peer: "127.0.0.1:9".parse().unwrap(),
                    bytes: vec![],
                }],
            },
            Operation::SendDatagrams {
                handle: 1,
                datagrams: vec![Datagram {
                    peer: "[::1]:9".parse().unwrap(),
                    bytes: vec![0; MAX_NETWORK_DATAGRAM_BYTES],
                }],
            },
            Operation::WriteAll {
                handle: 1,
                bytes: vec![0; MAX_NETWORK_CHUNK_BYTES],
            },
        ] {
            let request = Request { id: 1, operation };
            assert_eq!(
                read_frame_with_limit::<Request>(
                    &mut encode_frame(&request).unwrap().as_slice(),
                    MAX_NETWORK_FRAME_BYTES
                )
                .unwrap(),
                Some(request)
            );
        }
        for operation in [
            Operation::WriteAll {
                handle: 1,
                bytes: vec![0; MAX_NETWORK_CHUNK_BYTES + 1],
            },
            Operation::SendDatagrams {
                handle: 1,
                datagrams: vec![Datagram {
                    peer: "127.0.0.1:9".parse().unwrap(),
                    bytes: vec![0; MAX_NETWORK_DATAGRAM_BYTES + 1],
                }],
            },
            Operation::Resolve("a".repeat(MAX_NETWORK_NAME_BYTES + 1)),
        ] {
            let request = Request { id: 1, operation };
            assert!(
                read_frame_with_limit::<Request>(
                    &mut encode_frame(&request).unwrap().as_slice(),
                    MAX_NETWORK_FRAME_BYTES
                )
                .is_err()
            );
        }
        for reply in [
            Reply::Data(vec![0; MAX_NETWORK_READ_BYTES + 1]),
            Reply::Datagrams(vec![Datagram {
                peer: "127.0.0.1:9".parse().unwrap(),
                bytes: vec![0; MAX_NETWORK_DATAGRAM_BYTES + 1],
            }]),
            Reply::Resolved(vec!["1.1.1.1".parse().unwrap(); MAX_NETWORK_ADDRESSES + 1]),
        ] {
            let response = Response {
                id: 1,
                result: Ok(reply),
            };
            assert!(
                read_frame_with_limit::<Response>(
                    &mut encode_frame(&response).unwrap().as_slice(),
                    MAX_NETWORK_FRAME_BYTES
                )
                .is_err()
            );
        }
        let mut malicious = encode_frame(&Request {
            id: 1,
            operation: Operation::WriteAll {
                handle: 1,
                bytes: vec![],
            },
        })
        .unwrap();
        malicious.pop();
        malicious.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0x0f]);
        let length = u32::try_from(malicious.len() - 4).unwrap();
        malicious[..4].copy_from_slice(&length.to_le_bytes());
        assert!(
            read_frame_with_limit::<Request>(&mut malicious.as_slice(), MAX_NETWORK_FRAME_BYTES)
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
        let request = Request {
            id: u64::MAX,
            operation: Operation::SendDatagrams {
                handle: u64::MAX,
                datagrams: datagrams.clone(),
            },
        };
        let response = Response {
            id: u64::MAX,
            result: Ok(Reply::Datagrams(datagrams)),
        };
        assert!(crate::encode_frame_with_limit(&request, MAX_NETWORK_FRAME_BYTES).is_ok());
        assert!(crate::encode_frame_with_limit(&response, MAX_NETWORK_FRAME_BYTES).is_ok());
        let small = vec![
            Datagram {
                peer,
                bytes: vec![],
            };
            MAX_NETWORK_DATAGRAMS
        ];
        let request = Request {
            id: u64::MAX,
            operation: Operation::SendDatagrams {
                handle: u64::MAX,
                datagrams: small,
            },
        };
        assert_eq!(
            read_frame_with_limit::<Request>(
                &mut encode_frame(&request).unwrap().as_slice(),
                MAX_NETWORK_FRAME_BYTES
            )
            .unwrap(),
            Some(request)
        );
        let oversized_batch = Request {
            id: 1,
            operation: Operation::SendDatagrams {
                handle: 1,
                datagrams: vec![
                    Datagram {
                        peer,
                        bytes: vec![],
                    };
                    MAX_NETWORK_DATAGRAMS + 1
                ],
            },
        };
        let oversized_failures = Response {
            id: 1,
            result: Ok(Reply::Sent(vec![
                SendFailure {
                    index: 0,
                    error: Error::Io,
                };
                MAX_NETWORK_DATAGRAMS + 1
            ])),
        };
        assert!(
            read_frame_with_limit::<Request>(
                &mut encode_frame(&oversized_batch).unwrap().as_slice(),
                MAX_NETWORK_FRAME_BYTES
            )
            .is_err()
        );
        assert!(
            read_frame_with_limit::<Response>(
                &mut encode_frame(&oversized_failures).unwrap().as_slice(),
                MAX_NETWORK_FRAME_BYTES
            )
            .is_err()
        );
    }

    #[test]
    fn read_replies_grow_without_expanding_native_write_admission() {
        assert_eq!(MAX_NETWORK_READ_BYTES, 32704);
        assert_eq!(MAX_NETWORK_CHUNK_BYTES, 8192);
        let response = Response {
            id: u64::MAX,
            result: Ok(Reply::Data(vec![0x42; MAX_NETWORK_READ_BYTES])),
        };
        let encoded = encode_frame(&response).unwrap();
        assert!(encoded.len() <= MAX_NETWORK_FRAME_BYTES);
        assert_eq!(
            read_frame_with_limit::<Response>(&mut encoded.as_slice(), MAX_NETWORK_FRAME_BYTES)
                .unwrap(),
            Some(response)
        );
        let request = Request {
            id: u64::MAX,
            operation: Operation::WriteAll {
                handle: u64::MAX,
                bytes: vec![0; MAX_NETWORK_READ_BYTES],
            },
        };
        assert!(
            read_frame_with_limit::<Request>(
                &mut encode_frame(&request).unwrap().as_slice(),
                MAX_NETWORK_FRAME_BYTES
            )
            .is_err()
        );
    }

    #[test]
    fn bulk_byte_fields_preserve_the_network_wire_format() {
        let id = 130;
        let handle = u64::MAX - 1;
        let peer: SocketAddr = "192.0.2.1:53".parse().unwrap();
        for length in [
            0,
            1,
            127,
            128,
            MAX_NETWORK_DATAGRAM_BYTES,
            MAX_NETWORK_CHUNK_BYTES,
        ] {
            let bytes: Vec<u8> = (0..=255).cycle().take(length).collect();
            let operations = [
                Some((
                    Operation::WriteAll {
                        handle,
                        bytes: bytes.clone(),
                    },
                    encode_frame(&(id, 10_u32, handle, &bytes)).unwrap(),
                )),
                (length <= MAX_NETWORK_DATAGRAM_BYTES).then(|| {
                    (
                        Operation::SendDatagrams {
                            handle,
                            datagrams: vec![Datagram {
                                peer,
                                bytes: bytes.clone(),
                            }],
                        },
                        encode_frame(&(id, 5_u32, handle, 1_u8, peer, &bytes)).unwrap(),
                    )
                }),
            ];
            for (operation, expected) in operations.into_iter().flatten() {
                let request = Request { id, operation };
                assert_eq!(encode_frame(&request).unwrap(), expected);
                assert_eq!(
                    read_frame_with_limit::<Request>(
                        &mut encode_frame(&request).unwrap().as_slice(),
                        MAX_NETWORK_FRAME_BYTES
                    )
                    .unwrap(),
                    Some(request)
                );
            }
            let replies = [
                Some((
                    Reply::Data(bytes.clone()),
                    encode_frame(&(id, 0_u32, 1_u32, &bytes)).unwrap(),
                )),
                (length <= MAX_NETWORK_DATAGRAM_BYTES).then(|| {
                    (
                        Reply::Datagrams(vec![Datagram {
                            peer,
                            bytes: bytes.clone(),
                        }]),
                        encode_frame(&(id, 0_u32, 4_u32, 1_u8, peer, &bytes)).unwrap(),
                    )
                }),
            ];
            for (reply, expected) in replies.into_iter().flatten() {
                let response = Response {
                    id,
                    result: Ok(reply),
                };
                assert_eq!(encode_frame(&response).unwrap(), expected);
                assert_eq!(
                    read_frame_with_limit::<Response>(
                        &mut encode_frame(&response).unwrap().as_slice(),
                        MAX_NETWORK_FRAME_BYTES
                    )
                    .unwrap(),
                    Some(response)
                );
            }
        }
    }
}
