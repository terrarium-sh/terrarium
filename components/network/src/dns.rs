//! DNS query parsing and response construction for the virtio-net gateway.

use std::net::IpAddr;

const DNS_HEADER_LEN: usize = 12;
const DNS_HEADER_POINTER: u8 = 12;
const DNS_ID_LEN: usize = 2;
const DNS_U16_LEN: usize = 2;
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
const DNS_ONE_QUESTION: u16 = 1;
const DNS_FLAG_RESPONSE: u16 = 0x8000;
const DNS_FLAG_RECURSION_DESIRED: u16 = 0x0100;
const DNS_FLAG_RECURSION_AVAILABLE: u16 = 0x0080;
const DNS_POINTER_TAG: u8 = 0xc0;
const DNS_POINTER_MASK: u8 = 0xc0;
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
    let id = query.get(..DNS_ID_LEN).unwrap_or(&[0, 0]);
    let req_flags = read_u16(query, DNS_FLAGS_OFFSET).unwrap_or(0);
    let flags = DNS_FLAG_RESPONSE
        | (req_flags & DNS_FLAG_RECURSION_DESIRED)
        | DNS_FLAG_RECURSION_AVAILABLE
        | (rcode & DNS_RCODE_MASK);

    // Echo the question section (qdcount stays as in the query) when parseable.
    let question_end = question_section_end(query);
    let qdcount = u16::from(question_end.is_some());

    let mut response = Vec::with_capacity(question_end.unwrap_or(DNS_HEADER_LEN));
    response.extend_from_slice(id);
    response.extend_from_slice(&flags.to_be_bytes());
    response.extend_from_slice(&qdcount.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes()); // ancount
    response.extend_from_slice(&0u16.to_be_bytes()); // nscount
    response.extend_from_slice(&0u16.to_be_bytes()); // arcount
    if let Some(end) = question_end {
        response.extend_from_slice(&query[DNS_HEADER_LEN..end]);
    }
    response
}

/// Synthesize a DNS response for `query` with the given `ips` (A/AAAA, `ttl` s).
/// SERVFAIL if the question is unparseable; QTYPE filtering — only matching record
/// types are answered.
#[must_use]
pub fn build_ip_response(query: &[u8], ips: &[IpAddr], ttl: u32) -> Vec<u8> {
    let Some(question_end) = question_section_end(query) else {
        return error_response(query, DNS_RCODE_SERVFAIL);
    };
    let qtype = read_u16(query, question_end - 4).unwrap_or(0);
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

    let mut response =
        Vec::with_capacity(question_end + ips.len() * (DNS_RR_FIXED_LEN + DNS_AAAA_RDATA_LEN));
    response.extend_from_slice(&query[..DNS_ID_LEN]);
    response.extend_from_slice(&flags.to_be_bytes());
    response.extend_from_slice(&DNS_ONE_QUESTION.to_be_bytes()); // qdcount
    response.extend_from_slice(&ancount.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes()); // nscount
    response.extend_from_slice(&0u16.to_be_bytes()); // arcount
    response.extend_from_slice(&query[DNS_HEADER_LEN..question_end]); // echo question

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

fn question_section_end(packet: &[u8]) -> Option<usize> {
    Some(first_question(packet)?.1)
}

fn first_question(packet: &[u8]) -> Option<(String, usize)> {
    if packet.len() < DNS_HEADER_LEN || read_u16(packet, DNS_QDCOUNT_OFFSET)? != DNS_ONE_QUESTION {
        return None;
    }
    let (name, after_name) = read_name(packet, DNS_HEADER_LEN)?;
    let end = after_name + DNS_QUESTION_FIXED_LEN;
    if end > packet.len() {
        return None;
    }
    Some((name, end))
}

/// Parse a DNS name (with compression pointers), returning `(name, next_offset)`.
/// `next_offset` is the byte after the name in the *original* (non-jumped) stream.
fn read_name(packet: &[u8], offset: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut name_bytes = 0;
    let mut pos = offset;
    let mut next_offset = offset;
    let mut jumped = false;
    let mut jumps = 0;

    loop {
        let len = *packet.get(pos)?;
        if len & DNS_POINTER_MASK == DNS_POINTER_TAG {
            let lo = *packet.get(pos + 1)?;
            let pointer = (((len & DNS_POINTER_OFFSET_MASK) as usize) << 8) | lo as usize;
            if pointer >= packet.len() {
                return None;
            }
            if !jumped {
                next_offset = pos + DNS_U16_LEN;
            }
            pos = pointer;
            jumped = true;
            jumps += 1;
            if jumps > DNS_MAX_COMPRESSION_JUMPS {
                return None;
            }
            continue;
        }
        if len & DNS_POINTER_MASK != 0 {
            return None;
        }

        pos += 1;
        if len == 0 {
            if !jumped {
                next_offset = pos;
            }
            break;
        }

        let len = len as usize;
        if len > DNS_MAX_LABEL_LEN || pos + len > packet.len() {
            return None;
        }
        name_bytes += len + usize::from(!labels.is_empty());
        if name_bytes > DNS_MAX_NAME_BYTES {
            return None;
        }
        let label = std::str::from_utf8(&packet[pos..pos + len]).ok()?;
        labels.push(label.to_ascii_lowercase());
        pos += len;
        if !jumped {
            next_offset = pos;
        }
    }

    Some((labels.join("."), next_offset))
}

fn read_u16(buf: &[u8], offset: usize) -> Option<u16> {
    let bytes = buf.get(offset..offset + DNS_U16_LEN)?;
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
            q.push(label.len() as u8);
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
