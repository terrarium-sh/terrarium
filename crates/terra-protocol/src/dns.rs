//! DNS query parsing and response construction.

use std::net::IpAddr;

const DNS_HEADER_LEN: usize = 12;
const DNS_HEADER_POINTER: u8 = 12;
const DNS_FLAGS_OFFSET: usize = 2;
const DNS_QDCOUNT_OFFSET: usize = 4;
const DNS_QUESTION_FIXED_LEN: usize = 4;
const DNS_RR_FIXED_LEN: usize = 10;
const DNS_CLASS_IN: u16 = 1;
const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_AAAA: u16 = 28;
const DNS_AAAA_RDATA_LEN: usize = 16;
pub const DNS_RCODE_SERVFAIL: u16 = 2;
pub const DNS_RCODE_NXDOMAIN: u16 = 3;
const DNS_RCODE_MASK: u16 = 0x000f;
const DNS_FLAG_RESPONSE: u16 = 0x8000;
const DNS_FLAG_TRUNCATED: u16 = 0x0200;
const DNS_UDP_RESPONSE_BYTES: usize = 512;
const DNS_FLAG_RECURSION_DESIRED: u16 = 0x0100;
const DNS_FLAG_RECURSION_AVAILABLE: u16 = 0x0080;
const DNS_POINTER_TAG: u8 = 0xc0;
const DNS_POINTER_OFFSET_MASK: u8 = 0x3f;
const DNS_MAX_COMPRESSION_JUMPS: usize = 16;
const DNS_MAX_LABEL_LEN: usize = 63;
const DNS_MAX_NAME_BYTES: usize = 253;

/// The question name in a DNS query (first question only). `None` on malformed input.
#[must_use]
pub fn question_name(packet: &[u8]) -> Option<String> {
    Some(first_question(packet)?.0)
}

/// Build a DNS response carrying just an error `rcode` (e.g. NXDOMAIN), echoing
/// the query id and question. Mirrors libkrun's `build_error_response`.
#[must_use]
pub fn error_response(query: &[u8], rcode: u16) -> Vec<u8> {
    let id = read_u16(query, 0).unwrap_or(0);
    let req_flags = read_u16(query, DNS_FLAGS_OFFSET).unwrap_or(0);
    let flags = DNS_FLAG_RESPONSE
        | (req_flags & DNS_FLAG_RECURSION_DESIRED)
        | DNS_FLAG_RECURSION_AVAILABLE
        | (rcode & DNS_RCODE_MASK);

    let question = first_question(query).map(|(_, question)| question);
    let question_count = u16::from(question.is_some());

    let mut response = Vec::with_capacity(DNS_HEADER_LEN + question.as_ref().map_or(0, Vec::len));
    response.extend_from_slice(&response_header(id, flags, question_count, 0));
    if let Some(question) = question {
        response.extend_from_slice(&question);
    }
    response
}

fn response_header(
    id: u16,
    flags: u16,
    question_count: u16,
    answer_count: u16,
) -> [u8; DNS_HEADER_LEN] {
    let mut header = [0; DNS_HEADER_LEN];
    header[..2].copy_from_slice(&id.to_be_bytes());
    header[DNS_FLAGS_OFFSET..DNS_FLAGS_OFFSET + 2].copy_from_slice(&flags.to_be_bytes());
    header[DNS_QDCOUNT_OFFSET..DNS_QDCOUNT_OFFSET + 2]
        .copy_from_slice(&question_count.to_be_bytes());
    header[DNS_QDCOUNT_OFFSET + 2..DNS_QDCOUNT_OFFSET + 4]
        .copy_from_slice(&answer_count.to_be_bytes());
    header
}

#[must_use]
pub fn bound_udp_response(query: &[u8], response: Vec<u8>) -> Vec<u8> {
    if response.len() <= DNS_UDP_RESPONSE_BYTES {
        return response;
    }
    let flags = read_u16(&response, DNS_FLAGS_OFFSET).unwrap_or(DNS_RCODE_SERVFAIL);
    let mut truncated = error_response(query, flags & DNS_RCODE_MASK);
    let flags = read_u16(&truncated, DNS_FLAGS_OFFSET).unwrap_or(0) | DNS_FLAG_TRUNCATED;
    truncated[DNS_FLAGS_OFFSET..DNS_FLAGS_OFFSET + 2].copy_from_slice(&flags.to_be_bytes());
    truncated
}

/// Synthesize a DNS response for `query` with the given `ips` (A/AAAA, `ttl` s).
/// SERVFAIL if the question is unparseable; QTYPE filtering — only matching record
/// types are answered.
#[must_use]
pub fn build_ip_response(query: &[u8], ips: &[IpAddr], ttl: u32) -> Vec<u8> {
    let Some((_, question)) = first_question(query) else {
        return error_response(query, DNS_RCODE_SERVFAIL);
    };
    let qtype = read_u16(&question, question.len() - 4).unwrap_or(0);
    let ips: Vec<IpAddr> = ips
        .iter()
        .copied()
        .filter(|ip| {
            matches!(
                (qtype, ip),
                (DNS_TYPE_A, IpAddr::V4(_)) | (DNS_TYPE_AAAA, IpAddr::V6(_))
            )
        })
        .take(usize::from(u16::MAX) + 1)
        .collect();
    let flags = DNS_FLAG_RESPONSE
        | (read_u16(query, DNS_FLAGS_OFFSET).unwrap_or(0) & DNS_FLAG_RECURSION_DESIRED)
        | DNS_FLAG_RECURSION_AVAILABLE;
    let Ok(ancount) = u16::try_from(ips.len()) else {
        return error_response(query, DNS_RCODE_SERVFAIL);
    };

    let mut response = Vec::with_capacity(
        DNS_HEADER_LEN + question.len() + ips.len() * (DNS_RR_FIXED_LEN + DNS_AAAA_RDATA_LEN),
    );
    let id = read_u16(query, 0).unwrap_or(0);
    response.extend_from_slice(&response_header(id, flags, 1, ancount));
    response.extend_from_slice(&question);

    // Name pointer to the question name at the fixed header offset.
    let name_pointer = [DNS_POINTER_TAG, DNS_HEADER_POINTER];
    for ip in &ips {
        response.extend_from_slice(&name_pointer);
        let (rtype, rdata, rdata_len) = match ip {
            IpAddr::V4(v4) => (DNS_TYPE_A, v4.octets().to_vec(), 4u16),
            IpAddr::V6(v6) => (DNS_TYPE_AAAA, v6.octets().to_vec(), 16u16),
        };
        response.extend_from_slice(&rtype.to_be_bytes());
        response.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        response.extend_from_slice(&ttl.to_be_bytes());
        response.extend_from_slice(&rdata_len.to_be_bytes());
        response.extend_from_slice(&rdata);
    }
    response
}

fn first_question(packet: &[u8]) -> Option<(String, Vec<u8>)> {
    if packet.len() < DNS_HEADER_LEN || read_u16(packet, DNS_QDCOUNT_OFFSET)? != 1 {
        return None;
    }
    let mut name = String::new();
    let mut question = Vec::new();
    let after_name = read_name(packet, DNS_HEADER_LEN, &mut name, &mut question)?;
    let end = after_name + DNS_QUESTION_FIXED_LEN;
    question.extend_from_slice(packet.get(after_name..end)?);
    name.make_ascii_lowercase();
    Some((name, question))
}

/// Appends the dotted name to `name` and the uncompressed wire name to
/// `question`. The returned offset follows the encoded name in the original stream.
fn read_name(
    packet: &[u8],
    offset: usize,
    name: &mut String,
    question: &mut Vec<u8>,
) -> Option<usize> {
    let mut pos = offset;
    let mut next_offset = offset;
    let mut jumped = false;
    let mut jumps = 0;

    loop {
        let len = *packet.get(pos)?;
        if len & DNS_POINTER_TAG == DNS_POINTER_TAG {
            let lo = *packet.get(pos + 1)?;
            let pointer = (((len & DNS_POINTER_OFFSET_MASK) as usize) << 8) | lo as usize;
            if pointer >= packet.len() {
                return None;
            }
            if !jumped {
                next_offset = pos + 2;
            }
            pos = pointer;
            jumped = true;
            jumps += 1;
            if jumps > DNS_MAX_COMPRESSION_JUMPS {
                return None;
            }
            continue;
        }
        if len & DNS_POINTER_TAG != 0 {
            return None;
        }

        pos += 1;
        if len == 0 {
            if !jumped {
                next_offset = pos;
            }
            question.push(0);
            return Some(next_offset);
        }

        let len = len as usize;
        if len > DNS_MAX_LABEL_LEN || pos + len > packet.len() {
            return None;
        }
        if name.len() + len + usize::from(!name.is_empty()) > DNS_MAX_NAME_BYTES {
            return None;
        }
        let label = std::str::from_utf8(&packet[pos..pos + len]).ok()?;
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(label);
        question.push(u8::try_from(len).ok()?);
        question.extend_from_slice(label.as_bytes());
        pos += len;
        if !jumped {
            next_offset = pos;
        }
    }
}

fn read_u16(buf: &[u8], offset: usize) -> Option<u16> {
    let bytes = buf.get(offset..offset + 2)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

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
        q.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        q.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        q
    }

    #[test]
    fn parses_question_name() {
        assert_eq!(
            question_name(&query_for("www.example.com")).as_deref(),
            Some("www.example.com")
        );
    }

    #[test]
    fn oversized_udp_answer_requests_tcp_retry_with_the_same_question() {
        let query = query_for("many.example.com");
        let addresses = (1..=32)
            .map(|last| IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)))
            .collect::<Vec<_>>();
        let full = build_ip_response(&query, &addresses, 60);
        assert!(full.len() > DNS_UDP_RESPONSE_BYTES);
        let truncated = bound_udp_response(&query, full);
        assert!(truncated.len() <= DNS_UDP_RESPONSE_BYTES);
        assert_eq!(&truncated[..2], &query[..2]);
        assert_eq!(question_name(&truncated), question_name(&query));
        assert_eq!(read_u16(&truncated, 6), Some(0));
        assert_eq!(read_u16(&truncated, 8), Some(0));
        assert_eq!(read_u16(&truncated, 10), Some(0));
        assert_ne!(
            read_u16(&truncated, DNS_FLAGS_OFFSET).unwrap() & DNS_FLAG_TRUNCATED,
            0
        );
        let tcp_response = build_ip_response(&query, &addresses, 60);
        assert_eq!(read_u16(&tcp_response, 6), Some(32));
        assert_eq!(
            read_u16(&tcp_response, DNS_FLAGS_OFFSET).unwrap() & DNS_FLAG_TRUNCATED,
            0
        );
    }

    #[test]
    fn udp_answers_within_the_limit_are_unchanged() {
        let query = query_for("example.com");
        let response = build_ip_response(&query, &[IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))], 60);
        assert_eq!(bound_udp_response(&query, response.clone()), response);
        let response = error_response(&query, DNS_RCODE_NXDOMAIN);
        assert_eq!(bound_udp_response(&query, response.clone()), response);
    }

    #[test]
    fn parses_compressed_question_name() {
        let mut query = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x12,
            0x00, 0x01, 0x00, 0x01,
        ];
        query.extend([
            3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm',
            0,
        ]);
        assert_eq!(question_name(&query).as_deref(), Some("www.example.com"));
    }

    #[test]
    fn compressed_questions_are_self_contained_in_responses() {
        let ordinary = query_for("WwW.Example.COM");
        let mut compressed = ordinary[..DNS_HEADER_LEN].to_vec();
        compressed.extend_from_slice(&[0xc0, 0x12]);
        compressed.extend_from_slice(&ordinary[ordinary.len() - DNS_QUESTION_FIXED_LEN..]);
        compressed
            .extend_from_slice(&ordinary[DNS_HEADER_LEN..ordinary.len() - DNS_QUESTION_FIXED_LEN]);
        let addresses = [IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))];

        assert_eq!(
            build_ip_response(&compressed, &addresses, 60),
            build_ip_response(&ordinary, &addresses, 60)
        );
        assert_eq!(
            error_response(&compressed, DNS_RCODE_NXDOMAIN),
            error_response(&ordinary, DNS_RCODE_NXDOMAIN)
        );
    }

    #[test]
    fn rejects_names_larger_than_the_hostname_limit() {
        let name = std::iter::repeat_n("a", 128).collect::<Vec<_>>().join(".");
        assert!(name.len() > DNS_MAX_NAME_BYTES);
        assert_eq!(question_name(&query_for(&name)), None);
    }

    #[test]
    fn error_response_is_well_formed() {
        let q = query_for("blocked.test");
        let resp = error_response(&q, DNS_RCODE_NXDOMAIN);
        // QR bit set + rcode NXDOMAIN in low nibble of flags.
        let flags = read_u16(&resp, DNS_FLAGS_OFFSET).unwrap();
        assert_eq!(flags & DNS_FLAG_RESPONSE, DNS_FLAG_RESPONSE);
        assert_eq!(flags & DNS_RCODE_MASK, DNS_RCODE_NXDOMAIN);
        assert_eq!(&resp[..2], &q[..2]); // echoed id
    }

    #[test]
    fn build_ip_response_preserves_the_requested_family_and_ttl() {
        let query = query_for("api.internal");
        let ips = vec![
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            IpAddr::V6("2606:4700::1".parse().unwrap()),
        ];
        assert_eq!(
            build_ip_response(&query, &ips, 17),
            [
                0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03, b'a',
                b'p', b'i', 0x08, b'i', b'n', b't', b'e', b'r', b'n', b'a', b'l', 0x00, 0x00, 0x01,
                0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x11, 0x00, 0x04,
                10, 0, 0, 5,
            ]
        );

        let mut aaaa = query_for("api.internal");
        let qtype = aaaa.len() - 4;
        aaaa[qtype..qtype + 2].copy_from_slice(&DNS_TYPE_AAAA.to_be_bytes());
        assert_eq!(
            build_ip_response(&aaaa, &ips, 17),
            [
                0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03, b'a',
                b'p', b'i', 0x08, b'i', b'n', b't', b'e', b'r', b'n', b'a', b'l', 0x00, 0x00, 0x1c,
                0x00, 0x01, 0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x11, 0x00, 0x10,
                0x26, 0x06, 0x47, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x01,
            ]
        );
    }

    #[test]
    fn build_ip_response_servfails_on_bad_query() {
        let response = build_ip_response(&[0, 1, 2], &[IpAddr::V4(Ipv4Addr::LOCALHOST)], 60);
        let flags = read_u16(&response, DNS_FLAGS_OFFSET).unwrap();
        assert_eq!(flags & DNS_RCODE_MASK, DNS_RCODE_SERVFAIL);
    }

    #[test]
    fn build_ip_response_refuses_too_many_answers() {
        let query = query_for("many.test");
        let ips = vec![IpAddr::V4(Ipv4Addr::LOCALHOST); usize::from(u16::MAX) + 1];
        let response = build_ip_response(&query, &ips, 60);
        assert_eq!(
            read_u16(&response, DNS_FLAGS_OFFSET).unwrap() & DNS_RCODE_MASK,
            DNS_RCODE_SERVFAIL
        );
    }

    #[test]
    fn malformed_packets_dont_panic() {
        assert_eq!(question_name(&[0, 1, 2]), None);
    }
}
