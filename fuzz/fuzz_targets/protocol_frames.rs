#![no_main]

use libfuzzer_sys::fuzz_target;
use terra_protocol::{AgentOutput, ClientInput, SessionControlReply, SessionControlRequest};

/// Every frame that decodes re-encodes within its limit and decodes back to itself.
fn round_trip<T>(mut bytes: &[u8])
where
    T: terra_protocol::Message + PartialEq,
{
    while let Ok(Some(message)) = terra_protocol::read_frame::<T>(&mut bytes) {
        let encoded = terra_protocol::encode_frame(&message);
        assert!(encoded.is_ok());
        if let Ok(frame) = encoded {
            let mut remaining = frame.as_slice();
            assert!(
                terra_protocol::read_frame::<T>(&mut remaining)
                    .is_ok_and(|decoded| decoded == Some(message))
            );
            assert_eq!(remaining, []);
        }
    }
}

fn decode_agent(bytes: &[u8]) {
    let events = terra_agent_component::read_lifecycle_frames_for_fuzzing(bytes);
    assert!(events.len() * 5 <= bytes.len());
    for event in events {
        if let terra_protocol::LifecycleEvent::Diagnostic { bytes } = event {
            assert!(bytes.len() <= terra_protocol::MAX_DIAGNOSTIC_EVENT_BYTES);
        }
    }
}

fn answer_dns(query: &[u8]) {
    use terra_protocol::dns::{self, DnsTransport};
    let _ = dns::error_response(query, dns::Rcode::NxDomain);
    let Some(question) = dns::Question::parse(query) else {
        return;
    };
    let addresses = [
        std::net::Ipv4Addr::LOCALHOST.into(),
        std::net::Ipv6Addr::LOCALHOST.into(),
    ];
    let response = question.answer(&addresses, DnsTransport::Stream);
    assert!(response.len() <= terra_protocol::dns::MAX_DNS_BYTES);
    let response = question.answer(&addresses, DnsTransport::Datagram);
    assert!(response.len() <= 512);
    let _ = question.error(dns::Rcode::ServFail);
}

fuzz_target!(|bytes: &[u8]| {
    decode_agent(bytes);
    answer_dns(bytes);
    round_trip::<terra_protocol::AgentService>(bytes);
    round_trip::<terra_protocol::AgentCommand>(bytes);
    round_trip::<terra_protocol::Plan>(bytes);
    round_trip::<terra_protocol::SyncRequest>(bytes);
    round_trip::<terra_protocol::SyncReply>(bytes);
    round_trip::<terra_protocol::ExecRequest>(bytes);
    round_trip::<terra_protocol::LifecycleEvent>(bytes);
    round_trip::<ClientInput>(bytes);
    round_trip::<AgentOutput>(bytes);
    round_trip::<SessionControlRequest>(bytes);
    round_trip::<SessionControlReply>(bytes);
    round_trip::<terra_protocol::HostState>(bytes);
    round_trip::<terra_protocol::network::Open>(bytes);
    round_trip::<Result<terra_protocol::network::Resolved, terra_protocol::socket::Error>>(bytes);
    round_trip::<Result<(), terra_protocol::socket::Error>>(bytes);
    round_trip::<terra_protocol::network::TcpEvent>(bytes);
    round_trip::<terra_protocol::network::UdpRequest>(bytes);
    round_trip::<terra_protocol::network::UdpReply>(bytes);
    round_trip::<terra_protocol::network_control::DnsQuery>(bytes);
    round_trip::<terra_protocol::network_control::FrontendControl>(bytes);
    round_trip::<terra_protocol::network_control::Publication>(bytes);
});
