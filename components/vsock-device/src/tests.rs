use super::{
    GUEST_CID, HOST_CID, MAX_DATA_BYTES, MAX_TX_BYTES, MUX_VSOCK_PORT, RX_ALLOC, VsockError,
    VsockHeader, VsockSwitch,
};

fn guest(op: u16, source: u32, destination: u32, len: u32, fwd_cnt: u32) -> VsockHeader {
    VsockHeader {
        src_cid: GUEST_CID,
        dst_cid: HOST_CID,
        src_port: source,
        dst_port: destination,
        len,
        type_: 1,
        op,
        flags: 0,
        buf_alloc: RX_ALLOC,
        fwd_cnt,
    }
}

fn connect(switch: &mut VsockSwitch, source: u32) {
    connect_with_window(switch, source, RX_ALLOC);
}

fn connect_with_window(switch: &mut VsockSwitch, source: u32, window: u32) {
    let mut request = guest(1, source, MUX_VSOCK_PORT, 0, 0);
    request.buf_alloc = window;
    switch.rx(&request, &[]);
    assert_eq!(switch.take_replies()[0].header.op, 2);
}

#[test]
fn carrier_uses_the_one_shared_port() {
    let mut switch = VsockSwitch::new();
    connect(&mut switch, 100);
    assert_eq!(switch.connections_up_to(1), vec![(100, MUX_VSOCK_PORT)]);
    switch.rx(&guest(1, 101, MUX_VSOCK_PORT, 0, 0), &[]);
    switch.rx(&guest(1, 101, 6001, 0, 0), &[]);
    assert!(
        switch
            .take_replies()
            .iter()
            .all(|reply| reply.header.op == 3)
    );
}

#[test]
fn data_flows_through_carrier_and_advances_credit() {
    let mut switch = VsockSwitch::new();
    connect(&mut switch, 100);
    switch.rx(&guest(5, 100, MUX_VSOCK_PORT, 5, 0), b"hello");
    assert_eq!(switch.take_upstream()[0].data, b"hello");
    assert_eq!(switch.take_replies()[0].header.op, 6);
}

#[test]
fn guest_half_close_preserves_buffered_data() {
    let mut switch = VsockSwitch::new();
    connect(&mut switch, 100);
    switch.rx(&guest(5, 100, MUX_VSOCK_PORT, 5, 0), b"guest");
    let mut close = guest(4, 100, MUX_VSOCK_PORT, 0, 5);
    close.flags = 2;
    switch.rx(&close, &[]);
    assert!(switch.guest_send_closed(100, MUX_VSOCK_PORT));
    assert_eq!(switch.take_upstream()[0].data, b"guest");
    switch.shutdown(100, MUX_VSOCK_PORT).expect("closes");
    assert_eq!(switch.connection_count(), 0);
}

#[test]
fn forged_credit_resets_the_carrier() {
    let mut switch = VsockSwitch::new();
    connect(&mut switch, 100);
    switch.deliver(100, MUX_VSOCK_PORT, b"hello").expect("fits");
    switch.take_replies();
    switch.rx(&guest(6, 100, MUX_VSOCK_PORT, 0, 6), &[]);
    assert_eq!(switch.connection_count(), 0);
    assert!(
        switch
            .take_replies()
            .iter()
            .any(|reply| reply.header.op == 3)
    );
}

#[test]
fn backwards_credit_does_not_reclaim_the_send_bound() {
    let mut switch = VsockSwitch::new();
    connect_with_window(&mut switch, 100, u32::MAX);
    switch.deliver(100, MUX_VSOCK_PORT, b"four").expect("fits");
    switch.take_replies();
    let mut credit = guest(6, 100, MUX_VSOCK_PORT, 0, 2);
    credit.buf_alloc = u32::MAX;
    switch.rx(&credit, &[]);
    credit.fwd_cnt = 1;
    switch.rx(&credit, &[]);
    let data = vec![0; MAX_TX_BYTES - 2];
    assert!(switch.deliver(100, MUX_VSOCK_PORT, &data).is_ok());
}

#[test]
fn carrier_send_and_receive_bounds_apply_before_growth() {
    let mut switch = VsockSwitch::new();
    connect_with_window(&mut switch, 100, u32::MAX);
    let send = vec![0; MAX_TX_BYTES];
    switch.deliver(100, MUX_VSOCK_PORT, &send).expect("fits");
    assert_eq!(
        switch.deliver(100, MUX_VSOCK_PORT, b"x"),
        Err(VsockError::Backpressure)
    );

    let mut switch = VsockSwitch::new();
    connect(&mut switch, 100);
    let receive = vec![0; MAX_DATA_BYTES as usize];
    switch.rx(&guest(5, 100, MUX_VSOCK_PORT, MAX_DATA_BYTES, 0), &receive);
    switch.rx(&guest(5, 100, MUX_VSOCK_PORT, 1, MAX_DATA_BYTES), b"x");
    assert_eq!(switch.connection_count(), 0);
}

#[test]
fn malformed_or_wrong_tuple_gets_a_reset_for_its_socket() {
    let mut switch = VsockSwitch::new();
    switch.rx(&guest(1, 100, 6001, 0, 0), &[]);
    let mut bad_cid = guest(1, 101, 6002, 0, 0);
    bad_cid.src_cid = 9;
    switch.rx(&bad_cid, &[]);
    switch.rx(&guest(5, 102, MUX_VSOCK_PORT, 5, 0), b"bad");
    let replies = switch.take_replies();
    assert_eq!(replies.len(), 3);
    assert_eq!(replies[0].header.src_port, 6001);
    assert_eq!(replies[1].header.src_port, 6002);
    assert_eq!(replies[2].header.src_port, MUX_VSOCK_PORT);
    assert!(replies.iter().all(|reply| reply.header.op == 3));
}

#[test]
fn reset_discards_old_carrier_traffic_and_advances_generation() {
    let mut switch = VsockSwitch::new();
    connect(&mut switch, 100);
    switch.rx(&guest(5, 100, MUX_VSOCK_PORT, 3, 0), b"old");
    let generation = switch.generation();
    switch.reset_connections();
    assert_eq!(switch.generation(), generation + 1);
    assert_eq!(switch.take_upstream(), []);
    switch.rx(&guest(5, 100, MUX_VSOCK_PORT, 3, 0), b"old");
    assert_eq!(switch.take_upstream(), []);
}

#[test]
fn reset_does_not_allow_a_second_guest_to_hijack_the_carrier() {
    let mut switch = VsockSwitch::new();
    connect(&mut switch, 100);
    switch.reset_connections();
    switch.rx(&guest(1, 101, MUX_VSOCK_PORT, 0, 0), &[]);
    assert_eq!(switch.take_replies()[0].header.op, 3);
    assert_eq!(switch.connection_count(), 0);
}

#[test]
fn restart_accepts_a_new_carrier_without_reusing_its_generation() {
    let mut switch = VsockSwitch::new();
    connect(&mut switch, 100);
    let first_generation = switch.generation();
    switch.reset_connections();
    let reset_generation = switch.generation();
    switch.restart();
    assert_ne!(switch.generation(), first_generation);
    assert_ne!(switch.generation(), reset_generation);
    connect(&mut switch, 100);
    assert!(switch.connection_exists(100, MUX_VSOCK_PORT));
}

#[test]
fn oversized_packet_is_rejected() {
    let mut switch = VsockSwitch::new();
    connect(&mut switch, 100);
    let payload = vec![0; MAX_DATA_BYTES as usize + 1];
    switch.rx(
        &guest(5, 100, MUX_VSOCK_PORT, MAX_DATA_BYTES + 1, 0),
        &payload,
    );
    assert_eq!(switch.take_replies()[0].header.op, 3);
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
        dst_port: MUX_VSOCK_PORT,
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
