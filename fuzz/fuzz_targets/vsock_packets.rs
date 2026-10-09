#![no_main]

use libfuzzer_sys::fuzz_target;
use terra_vsock_device::{
    AGENT_RX_ALLOC, AGENT_VSOCK_PORT, CONTROL_VSOCK_PORT, GUEST_CID, HOST_CID, MAX_NETWORK_SOCKETS,
    MAX_QUEUED_REPLIES, MAX_QUEUED_REPLY_BYTES, PUBLICATION_HOST_PORTS, TCP_VSOCK_PORT,
    UDP_VSOCK_PORT, VSOCK_HEADER_BYTES, VsockHeader, VsockSwitch,
};

/// Guest request for one endpoint class: agent, control, TCP, or UDP.
fn request(class: u8) -> VsockHeader {
    let (src_port, dst_port) = match class % 4 {
        0 => (AGENT_VSOCK_PORT, AGENT_VSOCK_PORT),
        1 => (CONTROL_VSOCK_PORT, CONTROL_VSOCK_PORT),
        2 => (7000, TCP_VSOCK_PORT),
        _ => (7000, UDP_VSOCK_PORT),
    };
    VsockHeader {
        src_cid: GUEST_CID,
        dst_cid: HOST_CID,
        src_port,
        dst_port,
        len: 0,
        type_: 1,
        op: 1,
        flags: 0,
        buf_alloc: AGENT_RX_ALLOC,
        fwd_cnt: 0,
    }
}

fuzz_target!(|bytes: &[u8]| {
    terra_vsock_device::fuzz_rx_sequence(bytes);
    let selector = bytes.first().copied().unwrap_or(0);
    terra_vsock_frontend_component::fuzz_tx_descriptors(bytes, 0, 16);
    terra_vsock_frontend_component::fuzz_tx_descriptors(bytes, u16::from(selector), 256);
    if let Ok((header, _)) = VsockHeader::parse(bytes) {
        assert_eq!(header.encode().as_slice(), &bytes[..VSOCK_HEADER_BYTES]);
    }
    let mut switch = VsockSwitch::with_network(bytes.last().is_none_or(|byte| byte & 1 == 0));
    for class in 0..4 {
        switch.rx(&request(class), &[]);
    }
    let _ = switch.connect_publication(PUBLICATION_HOST_PORTS.start);
    for chunk in bytes.chunks(128) {
        if let Ok((header, payload)) = VsockHeader::parse(chunk) {
            switch.rx(&header, payload);
        }
        let selector = chunk.first().copied().unwrap_or(0);
        let mut opening = request(selector);
        if selector % 4 >= 2 {
            opening.src_port +=
                u32::from(selector) + (u32::from(chunk.get(1).copied().unwrap_or(0)) << 8);
        }
        if let Some(connection) = switch.connection_for(opening.src_port, opening.dst_port) {
            assert!(switch.available_send_credit(connection) <= switch.output_budget(connection));
            match (selector >> 1) % 8 {
                0 => {
                    let _ = switch.deliver(connection, chunk.to_vec());
                }
                1 => {
                    let _ = switch.consume_upstream(connection, usize::from(selector));
                }
                2 => {
                    let _ = switch.request_credit(connection);
                }
                3 => {
                    let _ = switch.shutdown(connection);
                }
                4 => {
                    let _ = switch.reset_connection(connection);
                    assert!(switch.deliver(connection, chunk.to_vec()).is_err());
                }
                5 => {
                    let mut header = opening;
                    header.op = 6;
                    header.buf_alloc = chunk
                        .get(1..5)
                        .and_then(|value| value.try_into().ok())
                        .map_or(0, u32::from_le_bytes);
                    header.fwd_cnt = chunk
                        .get(5..9)
                        .and_then(|value| value.try_into().ok())
                        .map_or(0, u32::from_le_bytes);
                    switch.rx(&header, &[]);
                }
                6 => {
                    let mut header = opening;
                    header.op = 5;
                    header.len = u32::try_from(chunk.len()).unwrap_or(u32::MAX);
                    switch.rx(&header, chunk);
                }
                _ => switch.reset_connections(),
            }
        }
        let _ = switch.connect_publication(
            PUBLICATION_HOST_PORTS.start + u32::from(chunk.get(2).copied().unwrap_or(0)),
        );
        assert!(switch.network_socket_count() <= MAX_NETWORK_SOCKETS);
        assert!(
            switch.pending_reply_count() <= (2 + MAX_NETWORK_SOCKETS) * MAX_QUEUED_REPLIES + 32
        );
        let replies = switch.take_replies_up_to(3, usize::from(selector));
        assert!(
            replies
                .iter()
                .map(|reply| reply.payload.len())
                .sum::<usize>()
                <= usize::from(selector)
        );
        for connection in switch.retirements().collect::<Vec<_>>() {
            let _ = switch.retire_connection(connection);
        }
        switch.rx(&opening, &[]);
    }
    let replies = switch.take_replies();
    assert!(
        replies
            .iter()
            .map(|reply| reply.payload.len())
            .sum::<usize>()
            <= MAX_QUEUED_REPLY_BYTES
    );
});
