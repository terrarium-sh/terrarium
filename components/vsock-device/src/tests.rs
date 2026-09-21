use super::{
    AGENT_VSOCK_PORT, CONTROL_VSOCK_PORT, GUEST_CID, HOST_CID, MAX_DATA_BYTES, MAX_QUEUED_REPLIES,
    MAX_TX_BYTES, RX_ALLOC, VsockHeader, VsockSwitch,
};

fn guest(op: u16, src_port: u32, dst_port: u32, len: u32, fwd: u32) -> VsockHeader {
    VsockHeader {
        src_cid: GUEST_CID,
        dst_cid: HOST_CID,
        src_port,
        dst_port,
        len,
        type_: 1,
        op,
        flags: 0,
        buf_alloc: RX_ALLOC,
        fwd_cnt: fwd,
    }
}

#[test]
fn ports_come_from_the_shared_contract() {
    assert_eq!(AGENT_VSOCK_PORT, 6000);
    assert_eq!(CONTROL_VSOCK_PORT, 6001);
}

#[test]
fn header_pins_kernel_abi_offsets() {
    let header = guest(5, 100, CONTROL_VSOCK_PORT, 3, 7);
    let bytes = header.encode();
    assert_eq!(
        u64::from_le_bytes(bytes[0..8].try_into().expect("fits")),
        GUEST_CID
    );
    assert_eq!(
        u64::from_le_bytes(bytes[8..16].try_into().expect("fits")),
        HOST_CID
    );
    assert_eq!(
        u32::from_le_bytes(bytes[16..20].try_into().expect("fits")),
        100
    );
    assert_eq!(
        u32::from_le_bytes(bytes[24..28].try_into().expect("fits")),
        3
    );
    assert_eq!(
        u16::from_le_bytes(bytes[28..30].try_into().expect("fits")),
        1
    );
    assert_eq!(
        u16::from_le_bytes(bytes[30..32].try_into().expect("fits")),
        5
    );
    assert_eq!(
        u32::from_le_bytes(bytes[40..44].try_into().expect("fits")),
        7
    );
    let (back, rest) = VsockHeader::parse(&bytes).expect("parses");
    assert_eq!(back, header);
    assert!(rest.is_empty());
    assert!(VsockHeader::parse(&bytes[..43]).is_err());
}

#[test]
fn guest_connect_gets_response() {
    let mut switch = VsockSwitch::new();
    switch.rx(&guest(1, 100, CONTROL_VSOCK_PORT, 0, 0), &[]);
    let replies = switch.take_replies();
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0].header.op, 2);
    assert_eq!(replies[0].header.src_cid, HOST_CID);
    assert_eq!(replies[0].header.dst_cid, GUEST_CID);
    assert_eq!(replies[0].header.src_port, CONTROL_VSOCK_PORT);
    assert_eq!(replies[0].header.dst_port, 100);
    assert_eq!(replies[0].header.buf_alloc, RX_ALLOC);
    assert_eq!(switch.connection_count(), 1);
}

#[test]
fn wrong_port_cid_or_type_gets_rst() {
    let mut switch = VsockSwitch::new();
    switch.rx(&guest(1, 100, AGENT_VSOCK_PORT, 0, 0), &[]);
    switch.rx(&guest(5, 100, CONTROL_VSOCK_PORT, 0, 0), &[]);
    let mut bad_cid = guest(1, 100, CONTROL_VSOCK_PORT, 0, 0);
    bad_cid.src_cid = 9;
    switch.rx(&bad_cid, &[]);
    let mut bad_type = guest(1, 101, CONTROL_VSOCK_PORT, 0, 0);
    bad_type.type_ = 2;
    switch.rx(&bad_type, &[]);
    let replies = switch.take_replies();
    assert_eq!(replies.len(), 4);
    assert!(replies.iter().all(|reply| reply.header.op == 3));
    assert_eq!(switch.connection_count(), 0);
}

#[test]
fn data_flows_upstream_with_credit() {
    let mut switch = VsockSwitch::new();
    switch.rx(&guest(1, 100, CONTROL_VSOCK_PORT, 0, 0), &[]);
    switch.take_replies();
    switch.rx(&guest(5, 100, CONTROL_VSOCK_PORT, 5, 0), b"hello");
    assert!(switch.take_replies().is_empty());
    let upstream = switch.take_upstream();
    assert_eq!(upstream.len(), 1);
    assert_eq!(upstream[0].data, b"hello");
    let replies = switch.take_replies();
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0].header.op, 6);
    assert_eq!(replies[0].header.fwd_cnt, 5);
    switch.rx(&guest(5, 100, CONTROL_VSOCK_PORT, 5, 0), b"world");
    assert_eq!(switch.take_upstream().len(), 1);
}

#[test]
fn over_credit_gets_rst_and_recycled() {
    let mut switch = VsockSwitch::new();
    switch.rx(&guest(1, 100, CONTROL_VSOCK_PORT, 0, 0), &[]);
    switch.take_replies();
    let flood = vec![0u8; MAX_DATA_BYTES as usize];
    switch.rx(
        &guest(5, 100, CONTROL_VSOCK_PORT, MAX_DATA_BYTES, 0),
        &flood,
    );
    assert!(switch.take_replies().is_empty());
    switch.rx(&guest(5, 100, CONTROL_VSOCK_PORT, 1, 0), b"x");
    let replies = switch.take_replies();
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0].header.op, 3);
    assert_eq!(switch.connection_count(), 0);
}

#[test]
fn stalled_consumer_withholds_credit_until_drained() {
    let mut switch = VsockSwitch::new();
    switch.rx(&guest(1, 100, CONTROL_VSOCK_PORT, 0, 0), &[]);
    switch.take_replies();
    switch.rx(&guest(5, 100, CONTROL_VSOCK_PORT, 5, 0), b"hello");
    assert!(switch.take_replies().is_empty());
    switch.rx(&guest(5, 100, CONTROL_VSOCK_PORT, 5, 0), b"world");
    assert!(switch.take_replies().is_empty());
    assert_eq!(switch.take_upstream().len(), 2);
    let replies = switch.take_replies();
    assert_eq!(replies.len(), 2);
    assert!(replies.iter().all(|reply| reply.header.op == 6));
    assert_eq!(replies[1].header.fwd_cnt, 10);
}

#[test]
fn repeated_reset_traffic_stays_bounded() {
    let mut switch = VsockSwitch::new();
    for port in 0..200 {
        switch.rx(&guest(5, 9000 + port, CONTROL_VSOCK_PORT, 5, 0), b"hello");
    }
    assert!(switch.take_replies().len() <= MAX_QUEUED_REPLIES);
    assert_eq!(switch.connection_count(), 0);
    switch.rx(&guest(1, 100, CONTROL_VSOCK_PORT, 0, 0), &[]);
    switch.take_replies();
    for _ in 0..200 {
        switch.rx(&guest(99, 100, CONTROL_VSOCK_PORT, 0, 0), &[]);
    }
    assert!(switch.take_replies().len() <= MAX_QUEUED_REPLIES);
    assert_eq!(switch.connection_count(), 1);
}

#[test]
fn forged_credit_ahead_resets_without_freeing() {
    let mut switch = VsockSwitch::new();
    switch.rx(&guest(1, 100, CONTROL_VSOCK_PORT, 0, 0), &[]);
    switch.take_replies();
    switch
        .deliver(100, CONTROL_VSOCK_PORT, b"hello")
        .expect("fits in window");
    switch.take_replies();
    switch.rx(&guest(6, 100, CONTROL_VSOCK_PORT, 0, 5000), &[]);
    let replies = switch.take_replies();
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0].header.op, 3);
    assert_eq!(switch.connection_count(), 0);
}

#[test]
fn credit_wrap_compares_by_distance() {
    let mut switch = VsockSwitch::new();
    switch.rx(&guest(1, 100, CONTROL_VSOCK_PORT, 0, 0), &[]);
    switch.take_replies();
    switch
        .deliver(100, CONTROL_VSOCK_PORT, &[9u8; 1024])
        .expect("fits");
    switch.take_replies();
    switch.rx(&guest(6, 100, CONTROL_VSOCK_PORT, 0, 1024), &[]);
    assert!(switch.take_replies().is_empty());
    let big = vec![7u8; MAX_TX_BYTES];
    assert!(switch.deliver(100, CONTROL_VSOCK_PORT, &big).is_err());
}

#[test]
fn len_mismatch_and_bad_op_get_rst() {
    let mut switch = VsockSwitch::new();
    switch.rx(&guest(1, 100, CONTROL_VSOCK_PORT, 0, 0), &[]);
    switch.take_replies();
    switch.rx(&guest(5, 100, CONTROL_VSOCK_PORT, 5, 0), b"abc");
    switch.rx(&guest(99, 100, CONTROL_VSOCK_PORT, 0, 0), &[]);
    let replies = switch.take_replies();
    assert_eq!(replies.len(), 2);
    assert!(replies.iter().all(|reply| reply.header.op == 3));
    assert_eq!(switch.connection_count(), 1);
}

#[test]
fn duplicate_request_gets_rst() {
    let mut switch = VsockSwitch::new();
    switch.rx(&guest(1, 100, CONTROL_VSOCK_PORT, 0, 0), &[]);
    switch.take_replies();
    switch.rx(&guest(1, 100, CONTROL_VSOCK_PORT, 0, 0), &[]);
    let replies = switch.take_replies();
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0].header.op, 3);
    assert_eq!(switch.connection_count(), 1);
}

#[test]
fn rw_on_unknown_gets_rst() {
    let mut switch = VsockSwitch::new();
    switch.rx(&guest(5, 100, CONTROL_VSOCK_PORT, 5, 0), b"hello");
    let replies = switch.take_replies();
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0].header.op, 3);
}

#[test]
fn shutdown_both_directions_recycles() {
    let mut switch = VsockSwitch::new();
    switch.rx(&guest(1, 100, CONTROL_VSOCK_PORT, 0, 0), &[]);
    switch.take_replies();
    let mut send = guest(4, 100, CONTROL_VSOCK_PORT, 0, 0);
    send.flags = 2;
    switch.rx(&send, &[]);
    assert_eq!(switch.connection_count(), 1);
    let echo = switch.take_replies();
    assert_eq!(echo.len(), 1);
    assert_eq!(echo[0].header.op, 4);
    let mut rcv = guest(4, 100, CONTROL_VSOCK_PORT, 0, 0);
    rcv.flags = 1;
    switch.rx(&rcv, &[]);
    assert_eq!(switch.connection_count(), 0);
    assert!(switch.take_replies().is_empty());
}

#[test]
fn rst_recycles() {
    let mut switch = VsockSwitch::new();
    switch.rx(&guest(1, 100, CONTROL_VSOCK_PORT, 0, 0), &[]);
    switch.take_replies();
    switch.rx(&guest(3, 100, CONTROL_VSOCK_PORT, 0, 0), &[]);
    assert_eq!(switch.connection_count(), 0);
    assert!(switch.take_replies().is_empty());
}

#[test]
fn guest_connection_cap_preserves_host_capacity() {
    let mut switch = VsockSwitch::new();
    switch.rx(&guest(1, 1000, CONTROL_VSOCK_PORT, 0, 0), &[]);
    switch.rx(&guest(1, 1001, CONTROL_VSOCK_PORT, 0, 0), &[]);
    let replies = switch.take_replies();
    assert_eq!(replies.len(), 2);
    assert_eq!(replies[0].header.op, 2);
    assert_eq!(replies[1].header.op, 3);
    assert_eq!(switch.connection_count(), 1);
    assert!(switch.connect(AGENT_VSOCK_PORT).is_ok());
    assert_eq!(switch.connection_count(), 2);
}

#[test]
fn host_initiated_connect_completes_on_response() {
    let mut switch = VsockSwitch::new();
    let ephemeral = switch.connect(AGENT_VSOCK_PORT).expect("connects");
    let request = switch.take_replies();
    assert_eq!(request.len(), 1);
    assert_eq!(request[0].header.op, 1);
    assert_eq!(request[0].header.src_port, ephemeral);
    assert_eq!(request[0].header.dst_port, AGENT_VSOCK_PORT);
    assert!(
        switch
            .deliver(AGENT_VSOCK_PORT, ephemeral, b"early")
            .is_err()
    );
    switch.rx(&guest(2, AGENT_VSOCK_PORT, ephemeral, 0, 0), &[]);
    assert_eq!(switch.connection_count(), 1);
    switch
        .deliver(AGENT_VSOCK_PORT, ephemeral, b"hello")
        .expect("delivers");
    let replies = switch.take_replies();
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0].header.op, 5);
    assert_eq!(replies[0].payload, b"hello");
    switch.rx(&guest(6, AGENT_VSOCK_PORT, ephemeral, 0, 5), &[]);
    assert!(switch.take_replies().is_empty());
    assert!(switch.connect(6002).is_err());
}

#[test]
fn deliver_honors_peer_window_and_cap() {
    let mut switch = VsockSwitch::new();
    switch.rx(&guest(1, 100, CONTROL_VSOCK_PORT, 0, 0), &[]);
    switch.take_replies();
    let big = vec![0u8; RX_ALLOC as usize + 1];
    assert!(switch.deliver(100, CONTROL_VSOCK_PORT, &big).is_err());
    let mut wide = guest(1, 101, CONTROL_VSOCK_PORT, 0, 0);
    wide.buf_alloc = u32::MAX;
    switch.rx(&wide, &[]);
    switch.take_replies();
    let huge = vec![0u8; 257 * 1024];
    assert!(switch.deliver(101, CONTROL_VSOCK_PORT, &huge).is_err());
    assert!(switch.deliver(999, CONTROL_VSOCK_PORT, b"x").is_err());
}

#[cfg(unix)]
#[test]
#[allow(unsafe_code)]
fn vsock_header_matches_upstream_packet_layout() {
    use super::VsockHeader;
    use virtio_vsock::packet::{PKT_HEADER_SIZE, VsockPacket};

    let ours = VsockHeader {
        src_cid: 3,
        dst_cid: 2,
        src_port: 100,
        dst_port: 6001,
        len: 5,
        type_: 1,
        op: 5,
        flags: 0,
        buf_alloc: 65536,
        fwd_cnt: 7,
    };
    let mut raw = [0u8; PKT_HEADER_SIZE];
    // SAFETY: `raw` outlives `packet`, the test is single-threaded, and
    // nothing else touches the buffer while the packet borrows it.
    let mut packet = unsafe { VsockPacket::new(&mut raw, None) }.expect("packet wraps");
    packet
        .set_src_cid(ours.src_cid)
        .set_dst_cid(ours.dst_cid)
        .set_src_port(ours.src_port)
        .set_dst_port(ours.dst_port)
        .set_len(ours.len)
        .set_type(ours.type_)
        .set_op(ours.op)
        .set_flags(ours.flags)
        .set_buf_alloc(ours.buf_alloc)
        .set_fwd_cnt(ours.fwd_cnt);
    let mut upstream = [0u8; PKT_HEADER_SIZE];
    packet.header_slice().copy_to(&mut upstream[..]);
    assert_eq!(upstream, ours.encode());
    let (parsed, rest) = VsockHeader::parse(&upstream).expect("parses");
    assert_eq!(parsed, ours);
    assert!(rest.is_empty());
}
