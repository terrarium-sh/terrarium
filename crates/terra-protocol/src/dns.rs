//! DNS query parsing and response construction.

use std::net::IpAddr;

use crate::network_control::DnsTransport;
use crate::socket::MAX_DNS_BYTES;

/// The question name starts right after the fixed header.
const QUESTION_NAME_OFFSET: u8 = 12;
const HEADER_BYTES: usize = QUESTION_NAME_OFFSET as usize;
const FLAGS_OFFSET: usize = 2;
const QUESTION_COUNT_OFFSET: usize = 4;
const QUESTION_FIXED_BYTES: usize = 4;
const POINTER_TAG: u8 = 0xc0;

const FLAG_RESPONSE: u16 = 0x8000;
const FLAG_TRUNCATED: u16 = 0x0200;
const FLAG_RECURSION_DESIRED: u16 = 0x0100;
const FLAG_RECURSION_AVAILABLE: u16 = 0x0080;

const CLASS_IN: u16 = 1;
const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;

const ANSWER_TTL_SECS: u32 = 60;
const UDP_RESPONSE_BYTES: usize = 512;
const MAX_LABEL_BYTES: u8 = 63;
const MAX_NAME_BYTES: usize = 253;

// An error response echoes at most the largest question, so it never needs truncating for UDP.
const _: () =
    assert!(HEADER_BYTES + MAX_NAME_BYTES + 2 + QUESTION_FIXED_BYTES <= UDP_RESPONSE_BYTES);

/// The response code of an error response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum Rcode {
    ServFail = 2,
    NxDomain = 3,
}

/// The first question of a DNS query.
pub struct Question<'a> {
    /// Lowercased and dotted.
    pub name: String,
    query: &'a [u8],
    /// The wire name, type and class, echoed in responses.
    wire: &'a [u8],
    qtype: u16,
}

impl<'a> Question<'a> {
    /// The first question of `query`; `None` on malformed input.
    #[must_use]
    pub fn parse(query: &'a [u8]) -> Option<Self> {
        if read_u16(query, QUESTION_COUNT_OFFSET)? != 1 {
            return None;
        }
        let mut name = String::new();
        let mut pos = HEADER_BYTES;
        loop {
            let len = *query.get(pos)?;
            pos += 1;
            if len == 0 {
                break;
            }
            // Also rejects compression pointers, which have no earlier name to point to in the
            // first question, and the reserved 0x40 and 0x80 label types.
            if len > MAX_LABEL_BYTES {
                return None;
            }
            let label = query.get(pos..pos + usize::from(len))?;
            if name.len() + label.len() + usize::from(!name.is_empty()) > MAX_NAME_BYTES {
                return None;
            }
            if !name.is_empty() {
                name.push('.');
            }
            name.push_str(std::str::from_utf8(label).ok()?);
            pos += label.len();
        }
        let qtype = read_u16(query, pos)?;
        let wire = query.get(HEADER_BYTES..pos + QUESTION_FIXED_BYTES)?;
        name.make_ascii_lowercase();
        Some(Self {
            name,
            query,
            wire,
            qtype,
        })
    }

    /// Answer with the `ips` matching the question's record type. An answer too large for UDP
    /// becomes a truncated header so the client retries over TCP; one over [`MAX_DNS_BYTES`]
    /// gets SERVFAIL.
    #[must_use]
    pub fn answer(&self, ips: &[IpAddr], transport: DnsTransport) -> Vec<u8> {
        let max_response_bytes = match transport {
            DnsTransport::Datagram => UDP_RESPONSE_BYTES,
            DnsTransport::Stream => MAX_DNS_BYTES,
        };
        let flags = match self.full_answer(ips) {
            Some(response) if response.len() <= max_response_bytes => return response,
            Some(_) if transport == DnsTransport::Datagram => FLAG_TRUNCATED,
            Some(_) | None => Rcode::ServFail as u16,
        };
        header_only_response(self.query, Some(self), flags)
    }

    /// A response carrying just `rcode`.
    #[must_use]
    pub fn error(&self, rcode: Rcode) -> Vec<u8> {
        header_only_response(self.query, Some(self), rcode as u16)
    }

    fn full_answer(&self, ips: &[IpAddr]) -> Option<Vec<u8>> {
        let is_answer = |ip: &&IpAddr| {
            matches!(
                (self.qtype, ip),
                (TYPE_A, IpAddr::V4(_)) | (TYPE_AAAA, IpAddr::V6(_))
            )
        };
        let answer_count = u16::try_from(ips.iter().filter(is_answer).count()).ok()?;
        let mut response = start_response(self.query, 0, 1, answer_count);
        response.extend_from_slice(self.wire);
        for ip in ips.iter().filter(is_answer) {
            let rdata: &[u8] = match ip {
                IpAddr::V4(ip) => &ip.octets(),
                IpAddr::V6(ip) => &ip.octets(),
            };
            response.extend_from_slice(&[POINTER_TAG, QUESTION_NAME_OFFSET]);
            response.extend_from_slice(&self.qtype.to_be_bytes());
            response.extend_from_slice(&CLASS_IN.to_be_bytes());
            response.extend_from_slice(&ANSWER_TTL_SECS.to_be_bytes());
            response.extend_from_slice(&u16::try_from(rdata.len()).ok()?.to_be_bytes());
            response.extend_from_slice(rdata);
        }
        Some(response)
    }
}

/// A response carrying just `rcode`, echoing the query id and, when it parses, its question.
#[must_use]
pub fn error_response(query: &[u8], rcode: Rcode) -> Vec<u8> {
    header_only_response(query, Question::parse(query).as_ref(), rcode as u16)
}

fn header_only_response(query: &[u8], question: Option<&Question>, flags: u16) -> Vec<u8> {
    let mut response = start_response(query, flags, u16::from(question.is_some()), 0);
    if let Some(question) = question {
        response.extend_from_slice(question.wire);
    }
    response
}

/// A response header echoing the query's id and recursion-desired bit, with `flags` added.
fn start_response(query: &[u8], flags: u16, question_count: u16, answer_count: u16) -> Vec<u8> {
    let id = read_u16(query, 0).unwrap_or(0);
    let recursion_desired = read_u16(query, FLAGS_OFFSET).unwrap_or(0) & FLAG_RECURSION_DESIRED;
    let flags = FLAG_RESPONSE | recursion_desired | FLAG_RECURSION_AVAILABLE | flags;
    let mut response = Vec::new();
    for field in [id, flags, question_count, answer_count, 0, 0] {
        response.extend_from_slice(&field.to_be_bytes());
    }
    response
}

fn read_u16(buf: &[u8], offset: usize) -> Option<u16> {
    buf.get(offset..)?
        .first_chunk()
        .map(|bytes| u16::from_be_bytes(*bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const RCODE_MASK: u16 = 0x000f;

    /// A query for `name` with one question (A/IN).
    fn query_for(name: &str) -> Vec<u8> {
        let mut q = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        for label in name.split('.') {
            q.push(u8::try_from(label.len()).unwrap());
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&TYPE_A.to_be_bytes());
        q.extend_from_slice(&CLASS_IN.to_be_bytes());
        q
    }

    fn rcode(response: &[u8]) -> u16 {
        read_u16(response, FLAGS_OFFSET).unwrap() & RCODE_MASK
    }

    fn question_name(packet: &[u8]) -> Option<String> {
        Question::parse(packet).map(|question| question.name)
    }

    fn answer(query: &[u8], ips: &[IpAddr], transport: DnsTransport) -> Vec<u8> {
        Question::parse(query).unwrap().answer(ips, transport)
    }

    #[test]
    fn parses_question_name() {
        assert_eq!(
            question_name(&query_for("WwW.Example.COM")).as_deref(),
            Some("www.example.com")
        );
    }

    #[test]
    fn oversized_udp_answer_requests_tcp_retry_with_the_same_question() {
        let query = query_for("many.example.com");
        let addresses = (1..=32)
            .map(|last| IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)))
            .collect::<Vec<_>>();
        let truncated = answer(&query, &addresses, DnsTransport::Datagram);
        assert!(truncated.len() <= UDP_RESPONSE_BYTES);
        assert_eq!(&truncated[..2], &query[..2]);
        assert_eq!(question_name(&truncated), question_name(&query));
        assert_eq!(read_u16(&truncated, 6), Some(0));
        assert_eq!(read_u16(&truncated, 8), Some(0));
        assert_eq!(read_u16(&truncated, 10), Some(0));
        assert_ne!(
            read_u16(&truncated, FLAGS_OFFSET).unwrap() & FLAG_TRUNCATED,
            0
        );
        assert_eq!(rcode(&truncated), 0);
        let tcp_response = answer(&query, &addresses, DnsTransport::Stream);
        assert!(tcp_response.len() > UDP_RESPONSE_BYTES);
        assert_eq!(read_u16(&tcp_response, 6), Some(32));
        assert_eq!(
            read_u16(&tcp_response, FLAGS_OFFSET).unwrap() & FLAG_TRUNCATED,
            0
        );
    }

    #[test]
    fn udp_answers_within_the_limit_are_the_stream_answer() {
        let query = query_for("example.com");
        let ips = [IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))];
        assert_eq!(
            answer(&query, &ips, DnsTransport::Datagram),
            answer(&query, &ips, DnsTransport::Stream)
        );
    }

    /// The first question of a query has no earlier name a compression pointer could refer to.
    #[test]
    fn rejects_compressed_question_names() {
        let mut query = query_for("www.example.com");
        query.truncate(HEADER_BYTES);
        query.extend_from_slice(&[POINTER_TAG, QUESTION_NAME_OFFSET]);
        query.extend_from_slice(&TYPE_A.to_be_bytes());
        query.extend_from_slice(&CLASS_IN.to_be_bytes());
        assert_eq!(question_name(&query), None);
    }

    #[test]
    fn rejects_names_larger_than_the_hostname_limit() {
        let name = std::iter::repeat_n("a", 128).collect::<Vec<_>>().join(".");
        assert!(name.len() > MAX_NAME_BYTES);
        assert_eq!(question_name(&query_for(&name)), None);
    }

    #[test]
    fn error_response_is_well_formed() {
        let q = query_for("blocked.test");
        let resp = error_response(&q, Rcode::NxDomain);
        let flags = read_u16(&resp, FLAGS_OFFSET).unwrap();
        assert_eq!(flags & FLAG_RESPONSE, FLAG_RESPONSE);
        assert_eq!(rcode(&resp), Rcode::NxDomain as u16);
        assert_eq!(&resp[..2], &q[..2]); // echoed id
        assert_eq!(&resp[HEADER_BYTES..], &q[HEADER_BYTES..]); // echoed question
    }

    #[test]
    fn answer_preserves_the_requested_family() {
        let query = query_for("api.internal");
        let ips = vec![
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            IpAddr::V6("2606:4700::1".parse().unwrap()),
        ];
        assert_eq!(
            answer(&query, &ips, DnsTransport::Stream),
            [
                0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03, b'a',
                b'p', b'i', 0x08, b'i', b'n', b't', b'e', b'r', b'n', b'a', b'l', 0x00, 0x00, 0x01,
                0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04,
                10, 0, 0, 5,
            ]
        );

        let mut aaaa = query_for("api.internal");
        let qtype = aaaa.len() - 4;
        aaaa[qtype..qtype + 2].copy_from_slice(&TYPE_AAAA.to_be_bytes());
        assert_eq!(
            answer(&aaaa, &ips, DnsTransport::Stream),
            [
                0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03, b'a',
                b'p', b'i', 0x08, b'i', b'n', b't', b'e', b'r', b'n', b'a', b'l', 0x00, 0x00, 0x1c,
                0x00, 0x01, 0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x10,
                0x26, 0x06, 0x47, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x01,
            ]
        );
    }

    #[test]
    fn unparseable_queries_get_an_error_without_a_question() {
        let response = error_response(&[0x12, 0x34, 1], Rcode::ServFail);
        assert_eq!(&response[..2], &[0x12, 0x34]);
        assert_eq!(rcode(&response), Rcode::ServFail as u16);
        assert_eq!(read_u16(&response, QUESTION_COUNT_OFFSET), Some(0));
        assert_eq!(response.len(), HEADER_BYTES);
    }

    #[test]
    fn answer_refuses_responses_over_the_size_limit() {
        let query = query_for("many.test");
        let ips = vec![IpAddr::V4(Ipv4Addr::LOCALHOST); MAX_DNS_BYTES / 16];
        let response = answer(&query, &ips, DnsTransport::Stream);
        assert_eq!(rcode(&response), Rcode::ServFail as u16);
    }

    #[test]
    fn malformed_packets_dont_panic() {
        assert_eq!(question_name(&[0, 1, 2]), None);
    }
}
