use super::{
    AGENT_RX_ALLOC, AGENT_VSOCK_PORT, CONTROL_RX_ALLOC, CONTROL_VSOCK_PORT, ConnectionId,
    GUEST_CID, HOST_CID, MAX_AGENT_TX_BYTES, MAX_DATA_BYTES, Role, VsockError, VsockHeader,
    VsockSwitch,
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
        buf_alloc: AGENT_RX_ALLOC,
        fwd_cnt,
    }
}

fn connect(switch: &mut VsockSwitch, source: u32) {
    connect_with_window(switch, source, AGENT_RX_ALLOC);
}

fn connect_with_window(switch: &mut VsockSwitch, source: u32, window: u32) {
    let mut request = guest(1, source, AGENT_VSOCK_PORT, 0, 0);
    request.buf_alloc = window;
    switch.rx(&request, &[]);
    assert_eq!(switch.take_replies()[0].header.op, 2);
}

fn agent(switch: &VsockSwitch) -> ConnectionId {
    switch.connection(Role::Agent).unwrap()
}

#[test]
fn fixed_endpoints_reject_unknown_and_duplicate_connections() {
    let mut switch = VsockSwitch::new();
    connect(&mut switch, AGENT_VSOCK_PORT);
    switch.rx(&guest(1, 101, AGENT_VSOCK_PORT, 0, 0), &[]);
    switch.rx(&guest(1, AGENT_VSOCK_PORT, AGENT_VSOCK_PORT, 0, 0), &[]);
    assert!(
        switch
            .take_replies()
            .iter()
            .all(|reply| reply.header.op == 3)
    );
    switch.rx(&guest(1, CONTROL_VSOCK_PORT, CONTROL_VSOCK_PORT, 0, 0), &[]);
    assert_eq!(switch.take_replies()[0].header.op, 2);
    assert!(switch.connection(Role::Agent).is_none());
    assert_eq!(switch.retirements().count(), 1);
    assert!(switch.connection(Role::Control).is_some());
}

#[test]
fn data_flows_through_carrier_and_advances_credit() {
    let mut switch = VsockSwitch::new();
    connect(&mut switch, AGENT_VSOCK_PORT);
    switch.rx(
        &guest(5, AGENT_VSOCK_PORT, AGENT_VSOCK_PORT, 5, 0),
        b"hello",
    );
    assert_eq!(switch.peek_upstream(agent(&switch), usize::MAX), b"hello");
    switch.consume_upstream(agent(&switch), usize::MAX).unwrap();
    assert_eq!(switch.take_replies()[0].header.op, 6);
}

#[test]
fn partial_carrier_drains_advance_credit_by_consumed_bytes() {
    let mut switch = VsockSwitch::new();
    connect(&mut switch, AGENT_VSOCK_PORT);
    switch.rx(
        &guest(5, AGENT_VSOCK_PORT, AGENT_VSOCK_PORT, 5, 0),
        b"hello",
    );
    assert_eq!(switch.peek_upstream(agent(&switch), 4), b"hell");
    switch.consume_upstream(agent(&switch), 4).unwrap();
    assert_eq!(switch.take_replies()[0].header.fwd_cnt, 4);
    assert_eq!(switch.peek_upstream(agent(&switch), 1), b"o");
    switch.consume_upstream(agent(&switch), 1).unwrap();
    assert_eq!(switch.take_replies()[0].header.fwd_cnt, 5);
}

#[test]
fn credit_after_backpressure_keeps_the_carrier_usable() {
    let mut switch = VsockSwitch::new();
    connect(&mut switch, AGENT_VSOCK_PORT);
    switch
        .deliver(agent(&switch), vec![0; AGENT_RX_ALLOC as usize])
        .expect("initial delivery");
    assert_eq!(
        switch.deliver(agent(&switch), b"blocked".to_vec()),
        Err(VsockError::Backpressure)
    );
    switch.rx(
        &guest(6, AGENT_VSOCK_PORT, AGENT_VSOCK_PORT, 0, AGENT_RX_ALLOC),
        &[],
    );
    switch
        .deliver(agent(&switch), b"ok".to_vec())
        .expect("credit restores delivery");
    assert!(switch.connection(Role::Agent).is_some());
}

#[test]
fn guest_half_close_preserves_buffered_data() {
    let mut switch = VsockSwitch::new();
    connect(&mut switch, AGENT_VSOCK_PORT);
    switch.rx(
        &guest(5, AGENT_VSOCK_PORT, AGENT_VSOCK_PORT, 5, 0),
        b"guest",
    );
    let mut close = guest(4, AGENT_VSOCK_PORT, AGENT_VSOCK_PORT, 0, 0);
    close.flags = 2;
    switch.rx(&close, &[]);
    assert!(switch.guest_send_closed(agent(&switch)));
    assert_eq!(switch.peek_upstream(agent(&switch), usize::MAX), b"guest");
    switch.consume_upstream(agent(&switch), usize::MAX).unwrap();
    let connection = agent(&switch);
    switch.shutdown(connection).expect("closes");
    assert!(
        switch
            .take_replies()
            .iter()
            .any(|reply| reply.header.op == 4)
    );
    switch.reset_connection(connection).unwrap();
    assert!(switch.connection(Role::Agent).is_none());
}

#[test]
fn guest_half_close_keeps_the_opposite_direction_open() {
    for flags in [1, 2] {
        let mut switch = VsockSwitch::new();
        connect(&mut switch, AGENT_VSOCK_PORT);
        let mut close = guest(4, AGENT_VSOCK_PORT, AGENT_VSOCK_PORT, 0, 0);
        close.flags = flags;
        switch.rx(&close, &[]);
        assert_eq!(switch.take_replies(), []);
        if flags == 2 {
            switch.deliver(agent(&switch), b"reply".to_vec()).unwrap();
            let reply = switch.take_replies().pop().unwrap();
            assert_eq!(reply.header.op, 5);
            assert_eq!(reply.payload, b"reply");
        } else {
            switch.rx(
                &guest(5, AGENT_VSOCK_PORT, AGENT_VSOCK_PORT, 5, 0),
                b"input",
            );
            assert_eq!(switch.peek_upstream(agent(&switch), usize::MAX), b"input");
            switch.consume_upstream(agent(&switch), usize::MAX).unwrap();
        }
    }
}

/// FIN carries the guest's last consumed-byte count while leaving replies open.
#[test]
fn guest_fin_applies_piggybacked_send_credit() {
    let mut switch = VsockSwitch::new();
    connect_with_window(&mut switch, AGENT_VSOCK_PORT, 4);
    let connection = agent(&switch);
    switch.deliver(connection, b"data".to_vec()).unwrap();
    switch.take_replies();
    assert_eq!(switch.send_capacity(connection), 0);
    assert!(switch.request_credit(connection).unwrap());
    switch.take_replies();
    let mut fin = guest(4, AGENT_VSOCK_PORT, AGENT_VSOCK_PORT, 0, 4);
    fin.buf_alloc = 4;
    fin.flags = 2;
    switch.rx(&fin, &[]);
    assert!(switch.guest_send_closed(connection));
    assert_eq!(switch.send_capacity(connection), 4);
    switch.deliver(connection, b"last".to_vec()).unwrap();
    assert_eq!(switch.take_replies().pop().unwrap().payload, b"last");
}

#[test]
fn forged_credit_resets_the_carrier() {
    let mut switch = VsockSwitch::new();
    connect(&mut switch, AGENT_VSOCK_PORT);
    switch
        .deliver(agent(&switch), b"hello".to_vec())
        .expect("fits");
    switch.take_replies();
    switch.rx(&guest(6, AGENT_VSOCK_PORT, AGENT_VSOCK_PORT, 0, 6), &[]);
    assert!(switch.connection(Role::Agent).is_none());
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
    connect_with_window(&mut switch, AGENT_VSOCK_PORT, u32::MAX);
    let connection = agent(&switch);
    switch.deliver(connection, b"four".to_vec()).unwrap();
    switch.take_replies();
    let mut credit = guest(6, AGENT_VSOCK_PORT, AGENT_VSOCK_PORT, 0, 2);
    credit.buf_alloc = u32::MAX;
    switch.rx(&credit, &[]);
    credit.fwd_cnt = 1;
    switch.rx(&credit, &[]);
    for _ in 0..3 {
        switch
            .deliver(connection, vec![0; MAX_DATA_BYTES as usize])
            .unwrap();
        switch.take_replies();
    }
    switch
        .deliver(connection, vec![0; MAX_DATA_BYTES as usize - 2])
        .unwrap();
    assert_eq!(
        switch.deliver(connection, b"x".to_vec()),
        Err(VsockError::Backpressure)
    );
}

#[test]
fn carrier_send_and_receive_bounds_apply_before_growth() {
    let mut switch = VsockSwitch::new();
    connect_with_window(&mut switch, AGENT_VSOCK_PORT, u32::MAX);
    let connection = agent(&switch);
    for _ in 0..MAX_AGENT_TX_BYTES / MAX_DATA_BYTES as usize {
        switch
            .deliver(connection, vec![0; MAX_DATA_BYTES as usize])
            .unwrap();
        switch.take_replies();
    }
    assert_eq!(
        switch.deliver(connection, b"x".to_vec()),
        Err(VsockError::Backpressure)
    );
    let mut switch = VsockSwitch::new();
    connect(&mut switch, AGENT_VSOCK_PORT);
    let receive = vec![0; MAX_DATA_BYTES as usize];
    switch.rx(
        &guest(5, AGENT_VSOCK_PORT, AGENT_VSOCK_PORT, MAX_DATA_BYTES, 0),
        &receive,
    );
    switch.rx(&guest(5, AGENT_VSOCK_PORT, AGENT_VSOCK_PORT, 1, 0), b"x");
    assert!(switch.connection(Role::Agent).is_none());
}

#[test]
fn malformed_or_wrong_tuple_gets_a_reset_for_its_socket() {
    let mut switch = VsockSwitch::new();
    switch.rx(&guest(1, AGENT_VSOCK_PORT, 6001, 0, 0), &[]);
    let mut bad_cid = guest(1, 101, 6002, 0, 0);
    bad_cid.src_cid = 9;
    switch.rx(&bad_cid, &[]);
    switch.rx(&guest(5, 102, AGENT_VSOCK_PORT, 5, 0), b"bad");
    let replies = switch.take_replies();
    assert_eq!(replies.len(), 3);
    assert_eq!(replies[0].header.src_port, 6001);
    assert_eq!(replies[1].header.src_port, 6002);
    assert_eq!(replies[2].header.src_port, AGENT_VSOCK_PORT);
    assert!(replies.iter().all(|reply| reply.header.op == 3));
}

#[test]
fn shared_reset_retires_both_roles_and_rejects_stale_operations() {
    let mut switch = VsockSwitch::new();
    connect(&mut switch, AGENT_VSOCK_PORT);
    switch.rx(&guest(1, CONTROL_VSOCK_PORT, CONTROL_VSOCK_PORT, 0, 0), &[]);
    switch.take_replies();
    let old_agent = agent(&switch);
    let old_network = switch.connection(Role::Control).unwrap();
    switch.rx(&guest(5, AGENT_VSOCK_PORT, AGENT_VSOCK_PORT, 3, 0), b"old");
    switch.reset_connections();
    assert!(switch.connection(Role::Agent).is_none());
    assert!(switch.connection(Role::Control).is_none());
    assert_eq!(
        switch.deliver(old_agent, b"stale".to_vec()),
        Err(VsockError::UnknownConnection)
    );
    assert_eq!(
        switch.consume_upstream(old_network, 10),
        Err(VsockError::UnknownConnection)
    );
    switch.rx(&guest(1, AGENT_VSOCK_PORT, AGENT_VSOCK_PORT, 0, 0), &[]);
    assert_eq!(switch.take_replies()[0].header.op, 3);
    assert!(switch.retire_connection(old_agent));
    assert!(switch.retire_connection(old_network));
    connect(&mut switch, AGENT_VSOCK_PORT);
    assert_ne!(agent(&switch), old_agent);
    assert!(!switch.retire_connection(old_agent));
    assert_eq!(
        switch.shutdown(old_agent),
        Err(VsockError::UnknownConnection)
    );
}

#[test]
fn network_reset_preserves_agent_and_replacement_requires_retirement() {
    let mut switch = VsockSwitch::new();
    connect(&mut switch, AGENT_VSOCK_PORT);
    switch.rx(&guest(1, CONTROL_VSOCK_PORT, CONTROL_VSOCK_PORT, 0, 0), &[]);
    switch.take_replies();
    let network = switch.connection(Role::Control).unwrap();
    switch.reset_connection(network).unwrap();
    switch.take_replies();
    switch.rx(&guest(1, CONTROL_VSOCK_PORT, CONTROL_VSOCK_PORT, 0, 0), &[]);
    assert_eq!(switch.take_replies()[0].header.op, 3);
    assert!(switch.retire_connection(network));
    switch.rx(&guest(1, CONTROL_VSOCK_PORT, CONTROL_VSOCK_PORT, 0, 0), &[]);
    assert_eq!(switch.take_replies()[0].header.op, 2);
    switch.deliver(agent(&switch), b"agent".to_vec()).unwrap();
}

#[test]
fn oversized_packet_is_rejected() {
    let mut switch = VsockSwitch::new();
    connect(&mut switch, AGENT_VSOCK_PORT);
    let payload = vec![0; MAX_DATA_BYTES as usize + 1];
    switch.rx(
        &guest(5, AGENT_VSOCK_PORT, AGENT_VSOCK_PORT, MAX_DATA_BYTES + 1, 0),
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
        src_port: AGENT_VSOCK_PORT,
        dst_port: AGENT_VSOCK_PORT,
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
    assert_eq!(rest, []);
}

#[test]
fn local_only_rejects_network_without_consuming_agent_capacity() {
    let mut switch = VsockSwitch::with_network(false);
    for _ in 0..200 {
        switch.rx(&guest(1, CONTROL_VSOCK_PORT, CONTROL_VSOCK_PORT, 0, 0), &[]);
    }
    assert_eq!(switch.pending_reply_count(), 32);
    switch.rx(&guest(1, AGENT_VSOCK_PORT, AGENT_VSOCK_PORT, 0, 0), &[]);
    let replies = switch.take_replies_up_to(1, 0);
    assert_eq!(replies[0].header.op, 2);
    assert!(switch.connection(Role::Agent).is_some());
    assert!(switch.connection(Role::Control).is_none());
}

#[test]
fn network_queue_pressure_preserves_agent_admission_and_round_robin_output() {
    let mut switch = VsockSwitch::new();
    let mut request = guest(1, CONTROL_VSOCK_PORT, CONTROL_VSOCK_PORT, 0, 0);
    request.buf_alloc = u32::MAX;
    switch.rx(&request, &[]);
    switch.take_replies();
    let network = switch.connection(Role::Control).unwrap();
    for _ in 0..120 {
        switch.deliver(network, b"n".to_vec()).unwrap();
    }
    assert_eq!(
        switch.deliver(network, b"blocked".to_vec()),
        Err(VsockError::Backpressure)
    );
    switch.rx(&guest(7, CONTROL_VSOCK_PORT, CONTROL_VSOCK_PORT, 0, 0), &[]);
    switch.rx(&guest(1, AGENT_VSOCK_PORT, AGENT_VSOCK_PORT, 0, 0), &[]);
    let agent = agent(&switch);
    switch.deliver(agent, b"a".to_vec()).unwrap();
    let replies = switch.take_replies_up_to(4, 10);
    assert_eq!(
        replies
            .iter()
            .map(|reply| reply.header.src_port)
            .collect::<Vec<_>>(),
        [
            AGENT_VSOCK_PORT,
            CONTROL_VSOCK_PORT,
            AGENT_VSOCK_PORT,
            CONTROL_VSOCK_PORT
        ]
    );
    assert_eq!(replies[2].payload, b"a");
    assert!(switch.connection(Role::Control).is_some());
}

#[test]
fn blocked_network_credit_and_input_leave_agent_progress_available() {
    let mut switch = VsockSwitch::new();
    connect(&mut switch, AGENT_VSOCK_PORT);
    let mut request = guest(1, CONTROL_VSOCK_PORT, CONTROL_VSOCK_PORT, 0, 0);
    request.buf_alloc = 0;
    switch.rx(&request, &[]);
    switch.take_replies();
    let network = switch.connection(Role::Control).unwrap();
    let mut data = guest(
        5,
        CONTROL_VSOCK_PORT,
        CONTROL_VSOCK_PORT,
        CONTROL_RX_ALLOC,
        0,
    );
    data.buf_alloc = 0;
    switch.rx(&data, &vec![0; CONTROL_RX_ALLOC as usize]);
    assert_eq!(
        switch.deliver(network, b"blocked".to_vec()),
        Err(VsockError::Backpressure)
    );
    switch.rx(
        &guest(5, AGENT_VSOCK_PORT, AGENT_VSOCK_PORT, 7, 0),
        b"control",
    );
    assert_eq!(switch.peek_upstream(agent(&switch), 7), b"control");
    switch.consume_upstream(agent(&switch), 7).unwrap();
    switch.deliver(agent(&switch), b"reply".to_vec()).unwrap();
    assert_eq!(
        switch
            .peek_upstream(network, CONTROL_RX_ALLOC as usize)
            .len(),
        CONTROL_RX_ALLOC as usize
    );
}

#[test]
fn reset_reply_must_leave_the_queue_before_replacement_is_admitted() {
    let mut switch = VsockSwitch::new();
    connect(&mut switch, AGENT_VSOCK_PORT);
    let old = agent(&switch);
    switch.reset_connection(old).unwrap();
    assert!(!switch.retire_connection(old));
    let reply = switch.take_replies().pop().unwrap();
    assert_eq!(reply.header.op, 3);
    assert!(switch.is_reply_current(&reply));
    assert!(switch.retire_connection(old));
    assert!(!switch.is_reply_current(&reply));
    connect(&mut switch, AGENT_VSOCK_PORT);
    assert_eq!(
        switch.deliver(old, b"old".to_vec()),
        Err(VsockError::UnknownConnection)
    );
}

#[test]
fn guest_full_shutdown_preserves_accepted_input_until_forwarded() {
    let mut switch = VsockSwitch::new();
    connect(&mut switch, AGENT_VSOCK_PORT);
    let connection = agent(&switch);
    switch.rx(
        &guest(5, AGENT_VSOCK_PORT, AGENT_VSOCK_PORT, 5, 0),
        b"input",
    );
    let mut shutdown = guest(4, AGENT_VSOCK_PORT, AGENT_VSOCK_PORT, 0, 0);
    shutdown.flags = 3;
    switch.rx(&shutdown, &[]);
    assert!(switch.guest_send_closed(connection));
    assert!(switch.guest_receive_closed(connection));
    assert_eq!(switch.peek_upstream(connection, 5), b"input");
    switch.consume_upstream(connection, 5).unwrap();
    assert_eq!(
        switch.deliver(connection, b"rejected".to_vec()),
        Err(VsockError::UnknownConnection)
    );
}

#[test]
fn receive_credit_updates_coalesce_without_losing_consumed_bytes() {
    let mut switch = VsockSwitch::new();
    connect(&mut switch, AGENT_VSOCK_PORT);
    let connection = agent(&switch);
    switch.rx(
        &guest(5, AGENT_VSOCK_PORT, AGENT_VSOCK_PORT, 1024, 0),
        &vec![0; 1024],
    );
    for _ in 0..1024 {
        switch.consume_upstream(connection, 1).unwrap();
    }
    assert_eq!(switch.pending_reply_count(), 1);
    assert_eq!(switch.take_replies()[0].header.fwd_cnt, 1024);
    assert_eq!(switch.connection(Role::Agent), Some(connection));
}

/// Coalescing a credit update ahead of older data headers would move the guest's
/// acknowledged-byte count backwards and block otherwise available send capacity.
#[test]
fn receive_credit_updates_preserve_packet_counter_order() {
    let mut switch = VsockSwitch::new();
    connect(&mut switch, AGENT_VSOCK_PORT);
    let connection = agent(&switch);
    switch.rx(&guest(5, AGENT_VSOCK_PORT, AGENT_VSOCK_PORT, 4, 0), b"data");
    switch.consume_upstream(connection, 1).unwrap();
    switch.deliver(connection, b"reply".to_vec()).unwrap();
    switch.consume_upstream(connection, 1).unwrap();
    let replies = switch.take_replies();
    assert_eq!(
        replies
            .iter()
            .map(|reply| reply.header.op)
            .collect::<Vec<_>>(),
        [6, 5, 6]
    );
    assert_eq!(
        replies
            .iter()
            .map(|reply| reply.header.fwd_cnt)
            .collect::<Vec<_>>(),
        [1, 1, 2]
    );
}

#[test]
fn host_fin_follows_accepted_bytes_without_invalidating_a_pending_reply() {
    let mut switch = VsockSwitch::new();
    connect(&mut switch, AGENT_VSOCK_PORT);
    let connection = agent(&switch);
    switch.deliver(connection, b"accepted".to_vec()).unwrap();
    let pending = switch.take_replies_up_to(1, 100).pop().unwrap();
    switch.shutdown(connection).unwrap();
    assert!(switch.is_reply_current(&pending));
    let fin = switch.take_replies().pop().unwrap();
    assert_eq!(fin.header.op, 4);
    assert_eq!(fin.header.flags, 2);
    assert_eq!(switch.connection(Role::Agent), Some(connection));
}

#[test]
fn guest_receive_shutdown_discards_output_and_keeps_input_open() {
    let mut switch = VsockSwitch::new();
    connect(&mut switch, AGENT_VSOCK_PORT);
    let connection = agent(&switch);
    switch.deliver(connection, b"pending".to_vec()).unwrap();
    let pending = switch.take_replies_up_to(1, 100).pop().unwrap();
    switch.deliver(connection, b"queued".to_vec()).unwrap();
    let mut shutdown = guest(4, AGENT_VSOCK_PORT, AGENT_VSOCK_PORT, 0, 0);
    shutdown.flags = 1;
    switch.rx(&shutdown, &[]);
    assert!(!switch.is_reply_current(&pending));
    assert_eq!(switch.take_replies(), []);
    switch.rx(
        &guest(5, AGENT_VSOCK_PORT, AGENT_VSOCK_PORT, 5, 0),
        b"input",
    );
    assert_eq!(switch.peek_upstream(connection, 5), b"input");
    switch.consume_upstream(connection, 5).unwrap();
}

fn connect_tcp(switch: &mut VsockSwitch, guest_port: u32) -> ConnectionId {
    let mut request = guest(1, guest_port, super::TCP_VSOCK_PORT, 0, 0);
    request.buf_alloc = u32::MAX;
    switch.rx(&request, &[]);
    switch
        .connection_for(guest_port, super::TCP_VSOCK_PORT)
        .unwrap()
}

#[test]
fn tcp_endpoints_are_bounded_and_do_not_select_fixed_services() {
    use super::{MAX_NETWORK_SOCKETS, TCP_VSOCK_PORT};
    let mut switch = VsockSwitch::new();
    for source in [0, AGENT_VSOCK_PORT, CONTROL_VSOCK_PORT] {
        switch.rx(&guest(1, source, TCP_VSOCK_PORT, 0, 0), &[]);
    }
    assert_eq!(switch.flow_connections(), [] as [ConnectionId; 0]);
    assert!(
        switch
            .take_replies()
            .iter()
            .all(|reply| reply.header.op == 3)
    );
    let same_source_as_destination = connect_tcp(&mut switch, TCP_VSOCK_PORT);
    assert_eq!(same_source_as_destination.role, Role::Tcp);
    for offset in 1..MAX_NETWORK_SOCKETS {
        connect_udp(&mut switch, 20000 + u32::try_from(offset).unwrap());
    }
    switch.rx(&guest(1, 12345, TCP_VSOCK_PORT, 0, 0), &[]);
    assert!(switch.connection_for(12345, TCP_VSOCK_PORT).is_none());
    assert_eq!(switch.network_socket_count(), MAX_NETWORK_SOCKETS);
    assert_eq!(
        switch.connect_publication(super::PUBLICATION_HOST_PORTS.start),
        Err(VsockError::Backpressure)
    );
    connect(&mut switch, AGENT_VSOCK_PORT);
    switch.rx(&guest(1, CONTROL_VSOCK_PORT, CONTROL_VSOCK_PORT, 0, 0), &[]);
    assert!(switch.connection(Role::Agent).is_some());
    assert!(switch.connection(Role::Control).is_some());
    assert_eq!(switch.network_socket_count(), MAX_NETWORK_SOCKETS);
}

#[test]
fn invalid_tcp_requests_and_unknown_data_do_not_consume_admission() {
    use super::TCP_VSOCK_PORT;
    let mut switch = VsockSwitch::new();
    let request = guest(1, 12345, TCP_VSOCK_PORT, 0, 0);
    let mut wrong_cid = request;
    wrong_cid.src_cid = 7;
    let mut wrong_type = request;
    wrong_type.type_ = 2;
    let mut wrong_flags = request;
    wrong_flags.flags = 1;
    let mut wrong_credit = request;
    wrong_credit.fwd_cnt = 1;
    for header in [wrong_cid, wrong_type, wrong_flags, wrong_credit] {
        switch.rx(&header, &[]);
    }
    switch.rx(&request, b"unexpected");
    switch.rx(&guest(5, 12345, TCP_VSOCK_PORT, 1, 0), b"x");
    assert_eq!(switch.network_socket_count(), 0);
    assert!(
        switch
            .take_replies()
            .iter()
            .all(|reply| reply.header.op == 3)
    );
    let connection = connect_tcp(&mut switch, 12345);
    assert_eq!(
        switch.connection_for(12345, TCP_VSOCK_PORT),
        Some(connection)
    );
}

#[test]
fn tcp_port_reuse_requires_retirement_and_invalidates_stale_work() {
    use super::TCP_VSOCK_PORT;
    let mut switch = VsockSwitch::new();
    let old = connect_tcp(&mut switch, 12345);
    switch.take_replies();
    switch.deliver(old, b"old output".to_vec()).unwrap();
    let output = switch.take_replies().pop().unwrap();
    switch.rx(&guest(5, 12345, TCP_VSOCK_PORT, 9, 0), b"old input");
    switch.reset_connection(old).unwrap();
    assert!(!switch.is_reply_current(&output));
    assert_eq!(
        switch.consume_upstream(old, 10),
        Err(VsockError::UnknownConnection)
    );
    assert_eq!(switch.network_socket_count(), 1);
    assert!(!switch.retire_connection(old));
    switch.rx(&guest(1, 12345, TCP_VSOCK_PORT, 0, 0), &[]);
    assert!(switch.connection_for(12345, TCP_VSOCK_PORT).is_none());
    let resets = switch.take_replies();
    assert!(resets.iter().all(|reply| reply.header.op == 3));
    assert!(switch.retire_connection(old));
    assert_eq!(switch.network_socket_count(), 0);
    let fresh = connect_tcp(&mut switch, 12345);
    assert_ne!(old, fresh);
    assert!(resets.iter().all(|reply| !switch.is_reply_current(reply)));
    assert_eq!(
        switch.deliver(old, b"stale".to_vec()),
        Err(VsockError::UnknownConnection)
    );
    assert_eq!(switch.peek_upstream(fresh, 10), []);
    assert!(!switch.retire_connection(old));
}

#[test]
fn tcp_flow_buffers_fit_the_pinned_aggregate_and_preserve_fixed_reserves() {
    use super::{FLOW_RX_ALLOC, MAX_FLOW_TX_BYTES, MAX_NETWORK_SOCKETS, TCP_VSOCK_PORT};
    let mut switch = VsockSwitch::new();
    let mut upstream_bytes = 0;
    let mut reply_bytes = 0;
    for offset in 0..MAX_NETWORK_SOCKETS {
        let source = 10000 + u32::try_from(offset).unwrap();
        let connection = connect_tcp(&mut switch, source);
        assert_eq!(switch.input_budget(connection), FLOW_RX_ALLOC as usize);
        assert_eq!(switch.output_budget(connection), MAX_FLOW_TX_BYTES);
        switch.rx(
            &VsockHeader {
                buf_alloc: u32::try_from(MAX_FLOW_TX_BYTES).unwrap(),
                ..guest(5, source, TCP_VSOCK_PORT, FLOW_RX_ALLOC, 0)
            },
            &vec![0; FLOW_RX_ALLOC as usize],
        );
        upstream_bytes += switch.peek_upstream(connection, usize::MAX).len();
        for chunk in vec![0; MAX_FLOW_TX_BYTES].chunks(MAX_DATA_BYTES as usize) {
            switch.deliver(connection, chunk.to_vec()).unwrap();
            reply_bytes += chunk.len();
        }
        assert_eq!(switch.send_capacity(connection), 0);
        assert_eq!(
            switch.deliver(connection, b"overflow".to_vec()),
            Err(VsockError::Backpressure)
        );
    }
    assert_eq!(
        upstream_bytes,
        terra_protocol::vsock::MAX_FLOW_UPSTREAM_BYTES
    );
    assert_eq!(reply_bytes, terra_protocol::vsock::MAX_FLOW_REPLY_BYTES);
    switch.rx(&guest(1, 20000, TCP_VSOCK_PORT, 0, 0), &[]);
    assert!(switch.connection_for(20000, TCP_VSOCK_PORT).is_none());
    connect(&mut switch, AGENT_VSOCK_PORT);
    switch.deliver(agent(&switch), b"control".to_vec()).unwrap();
    let replies = switch.take_replies_up_to(4, 64 * 1024);
    assert!(
        replies
            .iter()
            .any(|reply| reply.header.src_port == AGENT_VSOCK_PORT)
    );
}

#[test]
fn tcp_credit_and_receive_exhaustion_retire_only_the_affected_flow() {
    use super::{FLOW_RX_ALLOC, TCP_VSOCK_PORT};
    let mut switch = VsockSwitch::new();
    let first = connect_tcp(&mut switch, 12345);
    let second = connect_tcp(&mut switch, 12346);
    switch.take_replies();
    switch.rx(&guest(6, first.guest_port, TCP_VSOCK_PORT, 0, 1), &[]);
    assert!(
        switch
            .connection_for(first.guest_port, TCP_VSOCK_PORT)
            .is_none()
    );
    assert_eq!(
        switch.connection_for(second.guest_port, TCP_VSOCK_PORT),
        Some(second)
    );
    switch.rx(
        &guest(5, second.guest_port, TCP_VSOCK_PORT, FLOW_RX_ALLOC, 0),
        &vec![0; FLOW_RX_ALLOC as usize],
    );
    switch.rx(&guest(5, second.guest_port, TCP_VSOCK_PORT, 1, 0), b"x");
    assert!(
        switch
            .connection_for(second.guest_port, TCP_VSOCK_PORT)
            .is_none()
    );
    assert_eq!(switch.retirements().count(), 2);
}

#[test]
fn tcp_half_close_drains_raw_bytes_before_fin() {
    use super::TCP_VSOCK_PORT;
    let mut switch = VsockSwitch::new();
    let connection = connect_tcp(&mut switch, 12345);
    switch.take_replies();
    switch.rx(&guest(5, 12345, TCP_VSOCK_PORT, 8, 0), b"accepted");
    let mut fin = guest(4, 12345, TCP_VSOCK_PORT, 0, 0);
    fin.flags = 2;
    switch.rx(&fin, &[]);
    assert!(switch.guest_send_closed(connection));
    assert_eq!(switch.peek_upstream(connection, 8), b"accepted");
    assert_eq!(switch.peek_upstream(connection, 3), b"acc");
    switch.consume_upstream(connection, 3).unwrap();
    assert_eq!(switch.peek_upstream(connection, 5), b"epted");
    switch.consume_upstream(connection, 5).unwrap();
    switch.deliver(connection, b"response".to_vec()).unwrap();
    switch.shutdown(connection).unwrap();
    let replies = switch.take_replies();
    let payload = replies
        .iter()
        .position(|reply| reply.header.op == 5)
        .unwrap();
    let fin = replies
        .iter()
        .position(|reply| reply.header.op == 4)
        .unwrap();
    assert!(payload < fin);
    assert_eq!(replies[payload].payload, b"response");
    assert_eq!(
        switch.connection_for(12345, TCP_VSOCK_PORT),
        Some(connection)
    );
}

#[test]
fn output_rotates_tcp_flows_and_reserves_agent_and_control_service() {
    use super::TCP_VSOCK_PORT;
    let mut switch = VsockSwitch::new();
    connect(&mut switch, AGENT_VSOCK_PORT);
    switch.rx(&guest(1, CONTROL_VSOCK_PORT, CONTROL_VSOCK_PORT, 0, 0), &[]);
    let tcp = [
        connect_tcp(&mut switch, 12345),
        connect_tcp(&mut switch, 12346),
        connect_tcp(&mut switch, 12347),
    ];
    switch.take_replies();
    for connection in switch.connections() {
        for _ in 0..4 {
            switch.deliver(connection, b"x".to_vec()).unwrap();
        }
    }
    let first = switch.take_replies_up_to(9, 9);
    assert_eq!(first.len(), 9);
    assert_eq!(
        first
            .iter()
            .filter(|reply| reply.header.src_port == AGENT_VSOCK_PORT)
            .count(),
        3
    );
    assert_eq!(
        first
            .iter()
            .filter(|reply| reply.header.src_port == CONTROL_VSOCK_PORT)
            .count(),
        3
    );
    let tcp_ports = first
        .iter()
        .filter(|reply| reply.header.src_port == TCP_VSOCK_PORT)
        .map(|reply| reply.header.dst_port)
        .collect::<Vec<_>>();
    assert_eq!(tcp_ports.len(), 3);
    for connection in tcp {
        assert!(tcp_ports.contains(&connection.guest_port));
    }
}

#[test]
fn network_failure_and_physical_reset_have_distinct_scopes() {
    let mut switch = VsockSwitch::new();
    connect(&mut switch, AGENT_VSOCK_PORT);
    switch.rx(&guest(1, CONTROL_VSOCK_PORT, CONTROL_VSOCK_PORT, 0, 0), &[]);
    connect_tcp(&mut switch, 12345);
    connect_udp(&mut switch, 12346);
    switch.take_replies();
    let old_agent = agent(&switch);
    switch.reset_network_connections();
    assert_eq!(switch.connection(Role::Agent), Some(old_agent));
    assert!(switch.connection(Role::Control).is_none());
    assert_eq!(switch.flow_connections(), [] as [ConnectionId; 0]);
    assert_eq!(switch.retirements().count(), 3);
    assert_eq!(switch.network_socket_count(), 2);
    switch.reset_connections();
    assert_eq!(switch.connections(), [] as [ConnectionId; 0]);
    assert_eq!(switch.retirements().count(), 4);
    assert_eq!(switch.pending_reply_count(), 0);
}

#[test]
fn malformed_active_tcp_packets_retire_the_connection_number_and_discard_stale_bytes() {
    use super::TCP_VSOCK_PORT;
    for malformed in 0..5 {
        let mut switch = VsockSwitch::new();
        let connection = connect_tcp(&mut switch, 12345);
        let unaffected = connect_tcp(&mut switch, 12346);
        switch.take_replies();
        switch
            .deliver(connection, b"stale output".to_vec())
            .unwrap();
        let pending = switch.take_replies().pop().unwrap();
        switch.rx(&guest(5, 12345, TCP_VSOCK_PORT, 3, 0), b"old");
        let mut header = guest(5, 12345, TCP_VSOCK_PORT, 1, 0);
        match malformed {
            0 => header.type_ = 2,
            1 => header.flags = 4,
            2 => header.len = 2,
            3 => {
                header.op = 2;
                header.len = 0;
            }
            4 => {
                header.op = 1;
                header.len = 0;
            }
            _ => unreachable!(),
        }
        let payload: &[u8] = if header.len == 0 { &[] } else { b"x" };
        switch.rx(&header, payload);
        assert!(switch.connection_for(12345, TCP_VSOCK_PORT).is_none());
        assert!(!switch.is_reply_current(&pending));
        assert_eq!(
            switch.consume_upstream(connection, 10),
            Err(VsockError::UnknownConnection)
        );
        assert_eq!(
            switch.connection_for(12346, TCP_VSOCK_PORT),
            Some(unaffected)
        );
        assert!(
            switch
                .take_replies()
                .iter()
                .all(|reply| reply.header.op == 3)
        );
    }
}

#[test]
fn aggregate_transport_payload_limits_match_the_pinned_budget() {
    assert_eq!(super::MAX_QUEUED_UPSTREAM_BYTES, 49248 * 1024);
    assert_eq!(super::MAX_QUEUED_REPLY_BYTES, 82304 * 1024);
    assert_eq!(
        terra_protocol::vsock::MAX_FLOW_UPSTREAM_BYTES
            + terra_protocol::vsock::MAX_FLOW_REPLY_BYTES,
        128 * 1024 * 1024
    );
}

#[test]
fn only_a_new_credit_request_reports_work_to_schedule() {
    let mut switch = VsockSwitch::new();
    let mut opening = guest(1, 12345, super::TCP_VSOCK_PORT, 0, 0);
    opening.buf_alloc = 0;
    switch.rx(&opening, &[]);
    let connection = switch.connection_for(12345, super::TCP_VSOCK_PORT).unwrap();
    switch.take_replies();
    assert!(switch.request_credit(connection).unwrap());
    assert!(!switch.request_credit(connection).unwrap());
    assert_eq!(switch.take_replies().len(), 1);
    assert!(!switch.request_credit(connection).unwrap());
    let mut unchanged = guest(6, 12345, super::TCP_VSOCK_PORT, 0, 0);
    unchanged.buf_alloc = 0;
    for _ in 0..128 {
        switch.rx(&unchanged, &[]);
        assert!(!switch.request_credit(connection).unwrap());
    }
    assert_eq!(switch.pending_reply_count(), 0);
    unchanged.buf_alloc = super::FLOW_RX_ALLOC;
    switch.rx(&unchanged, &[]);
    assert!(switch.request_credit(connection).unwrap());
}

#[test]
fn broker_loss_disables_network_admission_and_keeps_agent_live() {
    let mut switch = VsockSwitch::new();
    connect(&mut switch, AGENT_VSOCK_PORT);
    let agent = agent(&switch);
    connect_tcp(&mut switch, 12345);
    switch.take_replies();
    switch.disable_network();
    switch.rx(&guest(1, 12346, super::TCP_VSOCK_PORT, 0, 0), &[]);
    switch.rx(&guest(1, CONTROL_VSOCK_PORT, CONTROL_VSOCK_PORT, 0, 0), &[]);
    assert_eq!(switch.flow_connections(), [] as [ConnectionId; 0]);
    assert!(switch.connection(Role::Control).is_none());
    assert_eq!(switch.connection(Role::Agent), Some(agent));
    switch.deliver(agent, b"stop".to_vec()).unwrap();
    assert!(
        switch
            .take_replies()
            .iter()
            .any(|reply| reply.payload == b"stop")
    );
    switch.rx(&guest(1, 12347, super::UDP_VSOCK_PORT, 0, 0), &[]);
    assert_eq!(switch.flow_connections(), [] as [ConnectionId; 0]);
    assert_eq!(
        switch.connect_publication(super::PUBLICATION_HOST_PORTS.start),
        Err(VsockError::Backpressure)
    );
}

fn connect_udp(switch: &mut VsockSwitch, guest_port: u32) -> ConnectionId {
    let mut request = guest(1, guest_port, super::UDP_VSOCK_PORT, 0, 0);
    request.buf_alloc = u32::MAX;
    switch.rx(&request, &[]);
    switch
        .connection_for(guest_port, super::UDP_VSOCK_PORT)
        .unwrap()
}

/// UDP sockets are ordinary flows: each owns its own stream and credit, and retires alone.
#[test]
fn udp_flows_have_independent_streams_and_share_admission_with_tcp() {
    let mut switch = VsockSwitch::new();
    let first = connect_udp(&mut switch, 12345);
    let second = connect_udp(&mut switch, 12346);
    let tcp = connect_tcp(&mut switch, 12345);
    assert_eq!((first.role, tcp.role), (Role::Udp, Role::Tcp));
    assert_eq!(switch.network_socket_count(), 3);
    switch.take_replies();
    switch.rx(&guest(5, 12345, super::UDP_VSOCK_PORT, 4, 0), b"udp1");
    assert_eq!(switch.peek_upstream(first, 8), b"udp1");
    assert_eq!(switch.peek_upstream(second, 8), b"");
    assert_eq!(switch.peek_upstream(tcp, 8), b"");
    switch.rx(&guest(3, 12345, super::UDP_VSOCK_PORT, 0, 0), &[]);
    assert!(!switch.is_current(first));
    assert!(switch.is_current(second));
    assert!(switch.is_current(tcp));
    for reserved in [
        AGENT_VSOCK_PORT,
        CONTROL_VSOCK_PORT,
        super::PUBLICATION_VSOCK_PORT,
        0,
    ] {
        switch.rx(&guest(1, reserved, super::UDP_VSOCK_PORT, 0, 0), &[]);
        assert!(
            switch
                .connection_for(reserved, super::UDP_VSOCK_PORT)
                .is_none()
        );
    }
}

/// A lower configured admission limit covers TCP, UDP, publication, and retiring flows,
/// while agent and control remain separately available.
#[test]
fn configured_capacity_applies_to_every_network_socket_class() {
    let mut switch = VsockSwitch::with_network_socket_capacity(true, 2);
    let tcp = connect_tcp(&mut switch, 12345);
    let udp = connect_udp(&mut switch, 12346);
    switch.take_replies();
    switch.reset_connection(tcp).unwrap();
    switch.rx(&guest(1, 12347, super::UDP_VSOCK_PORT, 0, 0), &[]);
    assert!(
        switch
            .connection_for(12347, super::UDP_VSOCK_PORT)
            .is_none()
    );
    assert_eq!(
        switch.connect_publication(super::PUBLICATION_HOST_PORTS.start),
        Err(VsockError::Backpressure)
    );
    switch.take_replies();
    assert!(switch.retire_connection(tcp));
    let publication = switch
        .connect_publication(super::PUBLICATION_HOST_PORTS.start)
        .unwrap();
    switch.rx(&guest(1, 12348, super::TCP_VSOCK_PORT, 0, 0), &[]);
    assert!(
        switch
            .connection_for(12348, super::TCP_VSOCK_PORT)
            .is_none()
    );
    assert!(switch.is_current(udp));
    assert!(switch.is_connecting(publication));
    connect(&mut switch, AGENT_VSOCK_PORT);
    switch.rx(&guest(1, CONTROL_VSOCK_PORT, CONTROL_VSOCK_PORT, 0, 0), &[]);
    assert!(switch.connection(Role::Agent).is_some());
    assert!(switch.connection(Role::Control).is_some());
    assert_eq!(switch.network_socket_count(), 2);
}

fn guest_response(host_port: u32) -> VsockHeader {
    VsockHeader {
        dst_port: host_port,
        ..guest(2, super::PUBLICATION_VSOCK_PORT, host_port, 0, 0)
    }
}

/// Only the frontend opens publication streams; the guest can accept or refuse but never initiate one.
#[test]
fn publication_streams_are_host_initiated_and_refuse_guest_requests() {
    use super::{PUBLICATION_HOST_PORTS, PUBLICATION_VSOCK_PORT};
    let mut switch = VsockSwitch::new();
    let host_port = PUBLICATION_HOST_PORTS.start;
    switch.rx(&guest(1, PUBLICATION_VSOCK_PORT, host_port, 0, 0), &[]);
    assert!(
        switch
            .take_replies()
            .iter()
            .all(|reply| reply.header.op == 3)
    );
    assert_eq!(switch.network_socket_count(), 0);
    let pending = switch.connect_publication(host_port).unwrap();
    assert_eq!(switch.connect_publication(host_port), Err(VsockError::Busy));
    assert!(switch.is_connecting(pending));
    assert!(!switch.is_current(pending));
    let request = switch.take_replies().pop().unwrap();
    assert_eq!(
        (
            request.header.op,
            request.header.src_port,
            request.header.dst_port
        ),
        (1, host_port, PUBLICATION_VSOCK_PORT)
    );
    assert!(switch.is_reply_current(&request));
    switch.rx(&guest_response(host_port), &[]);
    assert!(switch.is_current(pending));
    assert_eq!(switch.flow_connections(), [pending]);
    switch.rx(&guest(5, PUBLICATION_VSOCK_PORT, host_port, 3, 0), b"get");
    assert_eq!(switch.peek_upstream(pending, 3), b"get");
    switch.deliver(pending, b"ok".to_vec()).unwrap();
    assert_eq!(switch.take_replies().pop().unwrap().payload, b"ok");

    let refused = switch.connect_publication(host_port + 1).unwrap();
    switch.take_replies();
    switch.rx(&guest(3, PUBLICATION_VSOCK_PORT, host_port + 1, 0, 0), &[]);
    assert!(!switch.is_connecting(refused));
    assert_eq!(
        switch.retirements().collect::<Vec<_>>(),
        [ConnectionId {
            number: refused.number,
            ..refused
        }]
    );
    assert!(switch.retire_connection(refused));
    assert_eq!(switch.network_socket_count(), 1);
    assert!(
        switch
            .connect_publication(PUBLICATION_HOST_PORTS.end)
            .is_err()
    );
}

#[test]
fn rejected_publication_handshakes_retire_before_a_late_response() {
    for operation in [1, 4, 5, 6, 7, 8] {
        let mut switch = VsockSwitch::new();
        let host_port = super::PUBLICATION_HOST_PORTS.start;
        let pending = switch.connect_publication(host_port).unwrap();
        let request = switch.take_replies().pop().unwrap();
        let mut packet = guest(operation, super::PUBLICATION_VSOCK_PORT, host_port, 0, 0);
        packet.flags = u32::from(operation == 4);
        packet.len = u32::from(operation == 5);
        let payload: &[u8] = if operation == 5 { b"x" } else { &[] };
        switch.rx(&packet, payload);
        assert!(!switch.is_connecting(pending));
        assert!(!switch.is_reply_current(&request));
        assert_eq!(switch.retirements().collect::<Vec<_>>(), [pending]);
        switch.rx(&guest_response(host_port), &[]);
        assert!(!switch.is_current(pending));
        assert!(
            switch
                .take_replies()
                .iter()
                .all(|reply| reply.header.op == 3)
        );
        assert!(switch.retire_connection(pending));
    }

    let mut switch = VsockSwitch::new();
    let host_port = super::PUBLICATION_HOST_PORTS.start;
    let pending = switch.connect_publication(host_port).unwrap();
    switch.take_replies();
    let mut malformed = guest_response(host_port);
    malformed.flags = 1;
    switch.rx(&malformed, &[]);
    assert!(!switch.is_connecting(pending));
    assert_eq!(switch.retirements().collect::<Vec<_>>(), [pending]);
}
