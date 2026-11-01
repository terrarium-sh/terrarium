//! Messages between the guest agent and the host network frontend: DNS on the control stream,
//! and the header that opens each publication stream.

use std::num::NonZeroU16;

use serde::{Deserialize, Serialize};

use crate::socket::MAX_DNS_BYTES;

/// Concurrent DNS queries the agent may have outstanding on the control stream.
pub const MAX_DNS_QUERIES: usize = 16;

/// The variant tag, query id, transport, and length varint around a DNS message.
const DNS_ENVELOPE_BYTES: usize = 16;

/// The agent's messages on the network control stream.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentControl {
    /// Opens the control stream; the frontend answers [`FrontendControl::Ready`].
    Hello,
    DnsQuery(DnsPayload),
}

impl crate::Message for AgentControl {
    const MAX_PAYLOAD_BYTES: usize = MAX_DNS_BYTES + DNS_ENVELOPE_BYTES;
}

/// The frontend's messages on the network control stream.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FrontendControl {
    Ready,
    DnsResult(DnsPayload),
}

impl crate::Message for FrontendControl {
    const MAX_PAYLOAD_BYTES: usize = MAX_DNS_BYTES + DNS_ENVELOPE_BYTES;
}

/// A DNS message, without a stream's length prefix, and the query `id` that pairs a result with
/// its query.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsPayload {
    pub id: u32,
    pub transport: DnsTransport,
    #[serde(
        serialize_with = "serde_bytes::serialize",
        deserialize_with = "crate::bounded::bytes::<_, MAX_DNS_BYTES>"
    )]
    pub bytes: Vec<u8>,
}

/// How the guest sent a DNS query: as one datagram, or on a TCP stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DnsTransport {
    Datagram,
    Stream,
}

/// The first message on a publication stream: the guest port its host connection or UDP flow
/// reaches.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Publication {
    Tcp { guest_port: NonZeroU16 },
    Udp { guest_port: NonZeroU16 },
}

impl crate::Message for Publication {
    const MAX_PAYLOAD_BYTES: usize = 8;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Message, encode_frame, read_frame};

    fn round_trips<T: Message + PartialEq + std::fmt::Debug>(message: &T) {
        let frame = encode_frame(message).unwrap();
        assert_eq!(
            read_frame::<T>(&mut frame.as_slice()).unwrap().as_ref(),
            Some(message)
        );
    }

    #[test]
    fn control_messages_round_trip_the_largest_dns_message() {
        let largest = DnsPayload {
            id: u32::MAX,
            transport: DnsTransport::Stream,
            bytes: vec![7; MAX_DNS_BYTES],
        };
        round_trips(&AgentControl::Hello);
        round_trips(&AgentControl::DnsQuery(largest.clone()));
        round_trips(&FrontendControl::Ready);
        round_trips(&FrontendControl::DnsResult(largest));
    }

    #[test]
    fn dns_messages_past_the_limit_are_refused() {
        let oversized = AgentControl::DnsQuery(DnsPayload {
            id: 1,
            transport: DnsTransport::Datagram,
            bytes: vec![7; MAX_DNS_BYTES + 1],
        });
        assert!(
            read_frame::<AgentControl>(&mut crate::frames::frame_bytes(&oversized).as_slice())
                .is_err()
        );
    }

    #[test]
    fn publications_round_trip_and_refuse_port_zero() {
        for guest_port in [NonZeroU16::MIN, NonZeroU16::MAX] {
            round_trips(&Publication::Tcp { guest_port });
            round_trips(&Publication::Udp { guest_port });
        }
        let port_zero = crate::frames::frame_bytes(&(0_u32, 0_u16));
        assert!(read_frame::<Publication>(&mut port_zero.as_slice()).is_err());
    }
}
