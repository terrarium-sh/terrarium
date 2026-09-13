//! Bounded virtio-vsock packet validation and stream state.

use crate::VsockHeader;

use std::collections::VecDeque;

pub use terra_protocol::control::{AGENT_VSOCK_PORT, CONTROL_VSOCK_PORT, DIAGNOSTIC_VSOCK_PORT};

/// Well-known CIDs: host is 2, our one guest is 3. Single-box workers
/// never allocate guest CIDs; Phase 3 keeps the same guest contract.
pub const HOST_CID: u64 = 2;
pub const GUEST_CID: u64 = 3;
/// Largest connection table: resets, not growth, handle pressure.
pub const MAX_CONNECTIONS: usize = 64;
/// Largest single data payload accepted.
pub const MAX_DATA_BYTES: u32 = 64 * 1024;
/// Bytes of receive window advertised per connection.
pub const RX_ALLOC: u32 = 64 * 1024;
/// Bytes of host-to-guest data buffered per connection.
pub const MAX_TX_BYTES: usize = 256 * 1024;
/// Largest queued replies: resets, not growth, handle pressure.
pub const MAX_QUEUED_REPLIES: usize = 128;
/// Largest queued host-to-guest payload bytes across all replies.
pub const MAX_QUEUED_REPLY_BYTES: usize = 1 << 20;
/// Largest queued guest-to-host payloads before backpressure.
pub const MAX_QUEUED_UPSTREAM_ITEMS: usize = 128;
/// Largest queued guest-to-host bytes before backpressure.
pub const MAX_QUEUED_UPSTREAM_BYTES: usize = 1 << 20;

const TYPE_STREAM: u16 = 1;
const OP_REQUEST: u16 = 1;
const OP_RESPONSE: u16 = 2;
const OP_RST: u16 = 3;
const OP_SHUTDOWN: u16 = 4;
const OP_RW: u16 = 5;
const OP_CREDIT_UPDATE: u16 = 6;
const OP_CREDIT_REQUEST: u16 = 7;
const FLAG_SHUTDOWN_RCV: u32 = 1;
const FLAG_SHUTDOWN_SEND: u32 = 2;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Connecting { retry_pending: bool },
    Connected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CreditRequest {
    Idle,
    Pending,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Connection {
    guest_port: u32,
    host_port: u32,
    host_initiated: bool,
    state: State,
    peer_buf_alloc: u32,
    peer_fwd_cnt: u32,
    rx_received: u32,
    rx_fwd_cnt: u32,
    tx_fwd_cnt: u32,
    tx_pending: usize,
    credit_request: CreditRequest,
    tx_shutdown: bool,
    rx_shutdown: bool,
}

fn queued_bytes(conn: &Connection) -> u32 {
    conn.rx_received.wrapping_sub(conn.rx_fwd_cnt)
}

fn unacked_bytes(sent: u32, acked: u32) -> u32 {
    sent.wrapping_sub(acked)
}

fn ack_ahead(acked: u32, sent: u32) -> bool {
    acked != sent && acked.wrapping_sub(sent) < (1 << 31)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub header: VsockHeader,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upstream {
    pub guest_port: u32,
    pub host_port: u32,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VsockError {
    TableFull,
    Backpressure,
    UnknownConnection,
}

/// One vsock device's connection table. `&mut` is the single-owner
/// rule, matching the block device: queue parsing and state stay on
/// one task, and the worker drains `Upstream` / feeds `deliver`.
pub struct VsockSwitch {
    connections: Vec<Connection>,
    lifecycle_bound: [bool; 2],
    diagnostics_enabled: bool,
    upstream: VecDeque<Upstream>,
    upstream_bytes: usize,
    replies: VecDeque<Reply>,
    reply_bytes: usize,
    next_ephemeral: u32,
}

impl VsockSwitch {
    #[must_use]
    pub fn new() -> Self {
        Self {
            connections: Vec::new(),
            lifecycle_bound: [false; 2],
            diagnostics_enabled: false,
            upstream: VecDeque::new(),
            upstream_bytes: 0,
            replies: VecDeque::new(),
            reply_bytes: 0,
            next_ephemeral: 0x8000_0000,
        }
    }

    pub fn set_diagnostics_enabled(&mut self, enabled: bool) {
        self.diagnostics_enabled = enabled;
    }

    pub fn reset_connections(&mut self) {
        self.connections.clear();
        self.upstream.clear();
        self.upstream_bytes = 0;
        self.replies.clear();
        self.reply_bytes = 0;
        self.next_ephemeral = 0x8000_0000;
    }

    fn lifecycle_port_is_bound(&self, port: u32) -> bool {
        match port {
            CONTROL_VSOCK_PORT => self.lifecycle_bound[0],
            DIAGNOSTIC_VSOCK_PORT => self.lifecycle_bound[1],
            _ => false,
        }
    }

    fn bind_lifecycle_port(&mut self, port: u32) {
        match port {
            CONTROL_VSOCK_PORT => self.lifecycle_bound[0] = true,
            DIAGNOSTIC_VSOCK_PORT => self.lifecycle_bound[1] = true,
            _ => {}
        }
    }

    fn find(&self, guest_port: u32, host_port: u32) -> Option<usize> {
        self.connections
            .iter()
            .position(|conn| conn.guest_port == guest_port && conn.host_port == host_port)
    }

    fn has_guest_connection(&self, host_port: u32) -> bool {
        self.connections
            .iter()
            .any(|conn| !conn.host_initiated && conn.host_port == host_port)
    }

    fn can_queue_reply(&self, payload_len: usize) -> bool {
        if self.replies.len() >= MAX_QUEUED_REPLIES
            || self.reply_bytes + payload_len > MAX_QUEUED_REPLY_BYTES
        {
            return false;
        }
        true
    }

    fn queue_reply(&mut self, reply: Reply) -> bool {
        if !self.can_queue_reply(reply.payload.len()) {
            return false;
        }
        self.reply_bytes += reply.payload.len();
        self.replies.push_back(reply);
        true
    }

    fn host_header(host_port: u32, guest_port: u32) -> VsockHeader {
        VsockHeader {
            src_cid: HOST_CID,
            dst_cid: GUEST_CID,
            src_port: host_port,
            dst_port: guest_port,
            len: 0,
            type_: TYPE_STREAM,
            op: 0,
            flags: 0,
            buf_alloc: 0,
            fwd_cnt: 0,
        }
    }

    fn rst(&mut self, guest_port: u32, host_port: u32) -> bool {
        self.queue_reply(Reply {
            header: VsockHeader {
                op: OP_RST,
                ..Self::host_header(host_port, guest_port)
            },
            payload: Vec::new(),
        })
    }

    fn respond(&mut self, conn: &Connection, op: u16, flags: u32) -> bool {
        self.queue_reply(Reply {
            header: VsockHeader {
                op,
                flags,
                buf_alloc: RX_ALLOC,
                fwd_cnt: conn.rx_fwd_cnt,
                ..Self::host_header(conn.host_port, conn.guest_port)
            },
            payload: Vec::new(),
        })
    }

    /// Host-initiated connect to an agent port. Returns the host source port;
    /// the entry completes on the guest's RESPONSE.
    pub fn connect(&mut self, guest_port: u32) -> Result<u32, VsockError> {
        if guest_port != AGENT_VSOCK_PORT {
            return Err(VsockError::UnknownConnection);
        }
        if self.connections.len() >= MAX_CONNECTIONS {
            return Err(VsockError::TableFull);
        }
        let mut host_port = self.next_ephemeral;
        while self.find(guest_port, host_port).is_some() {
            host_port = host_port.wrapping_add(1);
        }
        self.next_ephemeral = host_port.wrapping_add(1);
        let conn = Connection {
            guest_port,
            host_port,
            host_initiated: true,
            state: State::Connecting {
                retry_pending: false,
            },
            peer_buf_alloc: 0,
            peer_fwd_cnt: 0,
            rx_received: 0,
            rx_fwd_cnt: 0,
            tx_fwd_cnt: 0,
            tx_pending: 0,
            credit_request: CreditRequest::Idle,
            tx_shutdown: false,
            rx_shutdown: false,
        };
        self.connections.push(conn);
        if self.respond(&conn, OP_REQUEST, 0) {
            Ok(host_port)
        } else {
            self.connections.pop();
            Err(VsockError::Backpressure)
        }
    }

    fn note_peer_credit(&mut self, index: usize, header: &VsockHeader) -> bool {
        let sent = self.connections[index].tx_fwd_cnt;
        let acked = header.fwd_cnt;
        if ack_ahead(acked, sent) {
            let (guest_port, host_port) = (
                self.connections[index].guest_port,
                self.connections[index].host_port,
            );
            self.rst(guest_port, host_port);
            self.drop_connection(index);
            return false;
        }
        let previous = self.connections[index].peer_fwd_cnt;
        if acked != previous && !ack_ahead(acked, previous) {
            return true;
        }
        let unacked = unacked_bytes(sent, acked);
        if unacked > u32::try_from(MAX_TX_BYTES).unwrap_or(u32::MAX) {
            return true;
        }
        self.connections[index].peer_buf_alloc = header.buf_alloc;
        self.connections[index].peer_fwd_cnt = acked;
        self.connections[index].tx_pending = usize::try_from(unacked).unwrap_or(usize::MAX);
        self.connections[index].credit_request = CreditRequest::Idle;
        true
    }

    /// One guest packet plus its data bytes. Returns nothing directly;
    /// drain `take_replies` / `take_upstream` after each call. A packet
    /// that cannot be attributed to this switch (wrong type or CIDs)
    /// is answered with RST unless it already is one; an RST with
    /// valid CIDs still tears its connection down.
    pub fn rx(&mut self, header: &VsockHeader, data: &[u8]) {
        if header.type_ != TYPE_STREAM || header.src_cid != GUEST_CID || header.dst_cid != HOST_CID
        {
            if header.op != OP_RST {
                self.rst(header.src_port, header.dst_port);
            }
            return;
        }
        let data_len = u64::try_from(data.len()).unwrap_or(u64::MAX);
        if (header.op == OP_RW) != (header.len > 0)
            || header.len > MAX_DATA_BYTES
            || data_len != u64::from(header.len)
        {
            if header.op == OP_RST {
                self.on_rst(header);
            } else {
                self.rst(header.src_port, header.dst_port);
            }
            return;
        }
        match header.op {
            OP_REQUEST => self.on_request(header),
            OP_RESPONSE => self.on_response(header),
            OP_RST => self.on_rst(header),
            OP_SHUTDOWN => self.on_shutdown(header),
            OP_RW => self.on_data(header, data),
            OP_CREDIT_UPDATE => self.on_credit(header),
            OP_CREDIT_REQUEST => self.on_credit_request(header),
            _ => {
                self.rst(header.src_port, header.dst_port);
            }
        }
    }

    fn on_request(&mut self, header: &VsockHeader) {
        if !matches!(header.dst_port, CONTROL_VSOCK_PORT | DIAGNOSTIC_VSOCK_PORT)
            || (header.dst_port == DIAGNOSTIC_VSOCK_PORT && !self.diagnostics_enabled)
            || header.fwd_cnt != 0
            || self.find(header.src_port, header.dst_port).is_some()
            || self.has_guest_connection(header.dst_port)
            || self.lifecycle_port_is_bound(header.dst_port)
        {
            self.rst(header.src_port, header.dst_port);
            return;
        }
        if self.connections.len() >= MAX_CONNECTIONS {
            self.rst(header.src_port, header.dst_port);
            return;
        }
        let conn = Connection {
            guest_port: header.src_port,
            host_port: header.dst_port,
            host_initiated: false,
            state: State::Connected,
            peer_buf_alloc: header.buf_alloc,
            peer_fwd_cnt: header.fwd_cnt,
            rx_received: 0,
            rx_fwd_cnt: 0,
            tx_fwd_cnt: 0,
            tx_pending: 0,
            credit_request: CreditRequest::Idle,
            tx_shutdown: false,
            rx_shutdown: false,
        };
        self.connections.push(conn);
        if self.respond(&conn, OP_RESPONSE, 0) {
            self.bind_lifecycle_port(header.dst_port);
        } else {
            self.connections.pop();
        }
    }

    fn on_response(&mut self, header: &VsockHeader) {
        let Some(index) = self.find(header.src_port, header.dst_port) else {
            self.rst(header.src_port, header.dst_port);
            return;
        };
        let conn = self.connections[index];
        if !matches!(conn.state, State::Connecting { .. }) || !conn.host_initiated {
            self.rst(header.src_port, header.dst_port);
            return;
        }
        self.connections[index].state = State::Connected;
        self.note_peer_credit(index, header);
    }

    fn on_rst(&mut self, header: &VsockHeader) {
        if let Some(index) = self.find(header.src_port, header.dst_port) {
            let connection = &mut self.connections[index];
            if connection.host_initiated {
                if let State::Connecting { retry_pending } = &mut connection.state {
                    *retry_pending = true;
                } else {
                    self.drop_connection(index);
                }
            } else {
                self.drop_connection(index);
            }
        }
    }

    pub fn retry_connecting(&mut self) -> bool {
        let retries = self
            .connections
            .iter()
            .enumerate()
            .filter_map(|(index, connection)| {
                (connection.host_initiated
                    && matches!(
                        connection.state,
                        State::Connecting {
                            retry_pending: true
                        }
                    ))
                .then_some((index, *connection))
            })
            .collect::<Vec<_>>();
        let mut queued = false;
        for (index, connection) in retries {
            if self.queue_reply(Reply {
                header: VsockHeader {
                    op: OP_REQUEST,
                    buf_alloc: RX_ALLOC,
                    fwd_cnt: connection.rx_fwd_cnt,
                    ..Self::host_header(connection.host_port, connection.guest_port)
                },
                payload: Vec::new(),
            }) {
                self.connections[index].state = State::Connecting {
                    retry_pending: false,
                };
                queued = true;
            }
        }
        queued
    }

    #[must_use]
    pub fn has_pending_connect_retry(&self) -> bool {
        self.connections.iter().any(|connection| {
            connection.host_initiated
                && matches!(
                    connection.state,
                    State::Connecting {
                        retry_pending: true
                    }
                )
        })
    }

    fn on_shutdown(&mut self, header: &VsockHeader) {
        let Some(index) = self.find(header.src_port, header.dst_port) else {
            self.rst(header.src_port, header.dst_port);
            return;
        };
        let conn = &mut self.connections[index];
        if conn.state != State::Connected {
            self.rst(header.src_port, header.dst_port);
            return;
        }
        if header.flags & FLAG_SHUTDOWN_RCV != 0 {
            conn.tx_shutdown = true;
        }
        if header.flags & FLAG_SHUTDOWN_SEND != 0 {
            conn.rx_shutdown = true;
        }
        if conn.tx_shutdown && conn.rx_shutdown {
            self.drop_connection(index);
        } else {
            let snapshot = self.connections[index];
            if !self.respond(&snapshot, OP_SHUTDOWN, header.flags) {
                self.drop_connection(index);
            }
        }
    }

    fn on_data(&mut self, header: &VsockHeader, data: &[u8]) {
        let Some(index) = self.find(header.src_port, header.dst_port) else {
            self.rst(header.src_port, header.dst_port);
            return;
        };
        let conn = self.connections[index];
        if conn.state != State::Connected || conn.rx_shutdown {
            self.rst(header.src_port, header.dst_port);
            return;
        }
        if !self.note_peer_credit(index, header) {
            return;
        }
        let queued = u64::from(queued_bytes(&self.connections[index]));
        if queued + u64::from(header.len) > u64::from(RX_ALLOC) {
            self.rst(header.src_port, header.dst_port);
            self.drop_connection(index);
            return;
        }
        if self.upstream.len() >= MAX_QUEUED_UPSTREAM_ITEMS
            || self.upstream_bytes + data.len() > MAX_QUEUED_UPSTREAM_BYTES
        {
            self.rst(header.src_port, header.dst_port);
            self.drop_connection(index);
            return;
        }
        self.connections[index].rx_received =
            self.connections[index].rx_received.wrapping_add(header.len);
        self.upstream_bytes += data.len();
        self.upstream.push_back(Upstream {
            guest_port: conn.guest_port,
            host_port: conn.host_port,
            data: data.to_vec(),
        });
    }

    fn on_credit(&mut self, header: &VsockHeader) {
        let Some(index) = self.find(header.src_port, header.dst_port) else {
            self.rst(header.src_port, header.dst_port);
            return;
        };
        if self.connections[index].state != State::Connected {
            self.rst(header.src_port, header.dst_port);
            return;
        }
        self.note_peer_credit(index, header);
    }

    fn on_credit_request(&mut self, header: &VsockHeader) {
        let Some(index) = self.find(header.src_port, header.dst_port) else {
            self.rst(header.src_port, header.dst_port);
            return;
        };
        if self.connections[index].state != State::Connected
            || !self.note_peer_credit(index, header)
        {
            self.rst(header.src_port, header.dst_port);
            return;
        }
        let snapshot = self.connections[index];
        if !self.respond(&snapshot, OP_CREDIT_UPDATE, 0) {
            self.drop_connection(index);
        }
    }

    fn request_credit(&mut self, index: usize) {
        if self.connections[index].credit_request == CreditRequest::Pending {
            return;
        }
        let snapshot = self.connections[index];
        if self.queue_reply(Reply {
            header: VsockHeader {
                op: OP_CREDIT_REQUEST,
                buf_alloc: RX_ALLOC,
                fwd_cnt: snapshot.rx_fwd_cnt,
                ..Self::host_header(snapshot.host_port, snapshot.guest_port)
            },
            payload: Vec::new(),
        }) {
            self.connections[index].credit_request = CreditRequest::Pending;
        }
    }

    /// Queue host-to-guest bytes. Bounded by the peer's advertised
    /// window and the per-connection buffer cap; excess is backpressure
    /// to the worker, never silent growth.
    pub fn deliver(
        &mut self,
        guest_port: u32,
        host_port: u32,
        data: &[u8],
    ) -> Result<(), VsockError> {
        let Some(index) = self.find(guest_port, host_port) else {
            return Err(VsockError::UnknownConnection);
        };
        let conn = self.connections[index];
        if conn.state != State::Connected || conn.tx_shutdown {
            return Err(VsockError::UnknownConnection);
        }
        let len = u32::try_from(data.len()).map_err(|_| VsockError::Backpressure)?;
        let unacked = unacked_bytes(conn.tx_fwd_cnt, conn.peer_fwd_cnt);
        let available = conn.peer_buf_alloc.saturating_sub(unacked);
        let exceeds_pending_cap =
            data.len() > MAX_TX_BYTES || conn.tx_pending > MAX_TX_BYTES - data.len();
        if len > available || exceeds_pending_cap || !self.can_queue_reply(data.len()) {
            if data.len() <= MAX_TX_BYTES && (len > available || exceeds_pending_cap) {
                self.request_credit(index);
            }
            return Err(VsockError::Backpressure);
        }
        let end = conn.tx_fwd_cnt.wrapping_add(len);
        self.connections[index].tx_fwd_cnt = end;
        self.connections[index].tx_pending += data.len();
        let queued = self.queue_reply(Reply {
            header: VsockHeader {
                len,
                op: OP_RW,
                buf_alloc: RX_ALLOC,
                fwd_cnt: conn.rx_fwd_cnt,
                ..Self::host_header(host_port, guest_port)
            },
            payload: data.to_vec(),
        });
        if !queued {
            self.connections[index].tx_fwd_cnt = conn.tx_fwd_cnt;
            self.connections[index].tx_pending = conn.tx_pending;
            return Err(VsockError::Backpressure);
        }
        Ok(())
    }

    /// Close the host-to-guest half after a host client reaches EOF. The guest
    /// may still send buffered output until it closes its send half or resets.
    pub fn shutdown(&mut self, guest_port: u32, host_port: u32) -> Result<(), VsockError> {
        let Some(index) = self.find(guest_port, host_port) else {
            return Err(VsockError::UnknownConnection);
        };
        let conn = self.connections[index];
        if conn.state != State::Connected {
            return Err(VsockError::UnknownConnection);
        }
        if conn.tx_shutdown {
            return Ok(());
        }
        if !self.can_queue_reply(0) {
            return Err(VsockError::Backpressure);
        }
        self.connections[index].tx_shutdown = true;
        let snapshot = self.connections[index];
        if !self.respond(&snapshot, OP_SHUTDOWN, FLAG_SHUTDOWN_SEND) {
            self.drop_connection(index);
            return Err(VsockError::Backpressure);
        }
        if snapshot.rx_shutdown {
            self.drop_connection(index);
        }
        Ok(())
    }

    /// Abort a host client flow and reclaim its bounded switch state.
    pub fn reset_connection(&mut self, guest_port: u32, host_port: u32) -> Result<(), VsockError> {
        let Some(index) = self.find(guest_port, host_port) else {
            return Err(VsockError::UnknownConnection);
        };
        self.rst(guest_port, host_port);
        self.drop_connection(index);
        Ok(())
    }

    #[must_use]
    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    fn drop_connection(&mut self, index: usize) {
        let connection = self.connections.swap_remove(index);
        self.upstream.retain(|item| {
            item.guest_port != connection.guest_port || item.host_port != connection.host_port
        });
        self.upstream_bytes = self.upstream.iter().map(|item| item.data.len()).sum();
    }

    #[must_use]
    pub fn connection_exists(&self, guest_port: u32, host_port: u32) -> bool {
        self.find(guest_port, host_port).is_some()
    }

    #[must_use]
    pub fn connection_connected(&self, guest_port: u32, host_port: u32) -> bool {
        self.find(guest_port, host_port)
            .is_some_and(|index| self.connections[index].state == State::Connected)
    }

    #[must_use]
    pub fn guest_send_closed(&self, guest_port: u32, host_port: u32) -> bool {
        self.find(guest_port, host_port)
            .is_some_and(|index| self.connections[index].rx_shutdown)
    }

    /// Return at most `max_items` guest and host port pairs that are currently connected.
    #[must_use]
    pub fn connections_up_to(&self, max_items: usize) -> Vec<(u32, u32)> {
        self.connections
            .iter()
            .filter(|connection| connection.state == State::Connected)
            .take(max_items)
            .map(|connection| (connection.guest_port, connection.host_port))
            .collect()
    }

    fn advance_receive_credit(&mut self, item: &Upstream) {
        let Some(index) = self.find(item.guest_port, item.host_port) else {
            return;
        };
        let snapshot = {
            let connection = &mut self.connections[index];
            connection.rx_fwd_cnt = connection
                .rx_fwd_cnt
                .wrapping_add(u32::try_from(item.data.len()).unwrap_or(u32::MAX));
            *connection
        };
        if !self.respond(&snapshot, OP_CREDIT_UPDATE, 0) {
            self.drop_connection(index);
        }
    }

    pub fn take_replies(&mut self) -> Vec<Reply> {
        self.take_replies_up_to(usize::MAX, usize::MAX)
    }

    /// Move whole replies that fit in the device's bounded outbox.
    pub fn take_replies_up_to(&mut self, max_items: usize, max_bytes: usize) -> Vec<Reply> {
        let mut drained = Vec::new();
        let mut bytes = 0;
        while drained.len() < max_items
            && self
                .replies
                .front()
                .is_some_and(|reply| reply.payload.len() <= max_bytes.saturating_sub(bytes))
        {
            let Some(reply) = self.replies.pop_front() else {
                break;
            };
            bytes += reply.payload.len();
            self.reply_bytes -= reply.payload.len();
            drained.push(reply);
        }
        drained
    }

    /// Consume whole upstream records that fit in `max_bytes`. Credits
    /// advance only for the returned records, after their host consumer
    /// has made room.
    pub fn take_upstream_up_to(&mut self, max_bytes: usize) -> Vec<Upstream> {
        let mut drained = Vec::new();
        let mut remaining = max_bytes;
        while self
            .upstream
            .front()
            .is_some_and(|item| item.data.len() <= remaining)
        {
            let Some(item) = self.upstream.pop_front() else {
                break;
            };
            remaining -= item.data.len();
            self.upstream_bytes -= item.data.len();
            self.advance_receive_credit(&item);
            drained.push(item);
        }
        drained
    }

    /// Consume up to `max_bytes` for one connection in stream order. Other
    /// connections retain their queued records and receive no credit.
    pub fn take_upstream_for_up_to(
        &mut self,
        guest_port: u32,
        host_port: u32,
        max_bytes: usize,
    ) -> Vec<Upstream> {
        let mut drained = Vec::new();
        let mut remaining = max_bytes;
        let mut index = 0;
        while remaining != 0 && index < self.upstream.len() {
            let matches_connection = self
                .upstream
                .get(index)
                .is_some_and(|item| item.guest_port == guest_port && item.host_port == host_port);
            if !matches_connection {
                index += 1;
                continue;
            }
            let take = self.upstream[index].data.len().min(remaining);
            let item = if take == self.upstream[index].data.len() {
                let Some(item) = self.upstream.remove(index) else {
                    break;
                };
                item
            } else {
                let Some(item) = self.upstream.get_mut(index) else {
                    break;
                };
                let data = item.data.drain(..take).collect();
                Upstream {
                    guest_port: item.guest_port,
                    host_port: item.host_port,
                    data,
                }
            };
            remaining -= item.data.len();
            self.upstream_bytes -= item.data.len();
            self.advance_receive_credit(&item);
            drained.push(item);
            if remaining == 0 {
                break;
            }
        }
        drained
    }

    pub fn take_upstream(&mut self) -> Vec<Upstream> {
        self.take_upstream_up_to(usize::MAX)
    }
}

impl Default for VsockSwitch {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credit_wrap_compares_by_distance() {
        assert!(!ack_ahead(0, 0));
        assert!(ack_ahead(5, 0));
        assert!(!ack_ahead(0, 5));
        assert_eq!(unacked_bytes(5, 5), 0);
        assert_eq!(unacked_bytes(10, 5), 5);
        assert_eq!(unacked_bytes(0, u32::MAX), 1);
        assert!(ack_ahead(0, u32::MAX));
        assert!(!ack_ahead(u32::MAX, 0));
        assert_eq!(unacked_bytes(0, u32::MAX - 10), 11);
    }

    fn guest(op: u16, len: u32, fwd_cnt: u32) -> VsockHeader {
        VsockHeader {
            src_cid: GUEST_CID,
            dst_cid: HOST_CID,
            src_port: 100,
            dst_port: CONTROL_VSOCK_PORT,
            len,
            type_: TYPE_STREAM,
            op,
            flags: 0,
            buf_alloc: RX_ALLOC,
            fwd_cnt,
        }
    }

    #[test]
    fn reset_drops_buffered_input_before_the_same_ports_reconnect() {
        let mut switch = VsockSwitch::new();
        switch.rx(&guest(OP_REQUEST, 0, 0), &[]);
        switch.rx(&guest(OP_RW, 3, 0), b"old");
        switch.reset_connection(100, CONTROL_VSOCK_PORT).unwrap();
        assert_eq!(switch.upstream_bytes, 0);
        switch.rx(&guest(OP_REQUEST, 0, 0), &[]);
        assert!(
            switch
                .take_upstream_for_up_to(100, CONTROL_VSOCK_PORT, usize::MAX)
                .is_empty()
        );
    }

    #[test]
    fn upstream_credit_waits_for_bounded_consumer() {
        let mut switch = VsockSwitch::new();
        switch.rx(&guest(OP_REQUEST, 0, 0), &[]);
        switch.take_replies();
        switch.rx(&guest(OP_RW, 5, 0), b"hello");
        assert!(switch.take_upstream_up_to(4).is_empty());
        assert!(switch.take_replies().is_empty());
        assert_eq!(switch.take_upstream_up_to(5)[0].data, b"hello");
        assert_eq!(switch.take_replies()[0].header.fwd_cnt, 5);
    }

    #[test]
    fn stale_ack_cannot_reclaim_sent_window() {
        let mut switch = VsockSwitch::new();
        switch.rx(&guest(OP_REQUEST, 0, 0), &[]);
        switch.take_replies();
        switch
            .deliver(100, CONTROL_VSOCK_PORT, b"hello")
            .expect("fits");
        switch.take_replies();
        switch.rx(&guest(OP_CREDIT_UPDATE, 0, 5), &[]);
        switch.rx(&guest(OP_CREDIT_UPDATE, 0, 0), &[]);
        let full = vec![0; MAX_TX_BYTES];
        assert_eq!(
            switch.deliver(100, CONTROL_VSOCK_PORT, &full),
            Err(VsockError::Backpressure)
        );
    }

    #[test]
    fn blocked_host_delivery_requests_credit_once_then_resumes() {
        let mut switch = VsockSwitch::new();
        let host_port = switch.connect(AGENT_VSOCK_PORT).unwrap();
        switch.take_replies();
        let mut response = guest(OP_RESPONSE, 0, 0);
        response.src_port = AGENT_VSOCK_PORT;
        response.dst_port = host_port;
        response.buf_alloc = 4;
        switch.rx(&response, &[]);

        switch
            .deliver(AGENT_VSOCK_PORT, host_port, b"four")
            .unwrap();
        switch.take_replies();
        assert_eq!(
            switch.deliver(AGENT_VSOCK_PORT, host_port, b"x"),
            Err(VsockError::Backpressure)
        );
        assert_eq!(switch.take_replies()[0].header.op, OP_CREDIT_REQUEST);
        assert_eq!(
            switch.deliver(AGENT_VSOCK_PORT, host_port, b"x"),
            Err(VsockError::Backpressure)
        );
        assert!(switch.take_replies().is_empty());

        let mut update = guest(OP_CREDIT_UPDATE, 0, 4);
        update.src_port = AGENT_VSOCK_PORT;
        update.dst_port = host_port;
        update.buf_alloc = 4;
        switch.rx(&update, &[]);
        switch
            .deliver(AGENT_VSOCK_PORT, host_port, b"x")
            .expect("peer credit reopens the host window");
    }

    #[test]
    fn incoming_credit_request_gets_current_update() {
        let mut switch = VsockSwitch::new();
        switch.rx(&guest(OP_REQUEST, 0, 0), &[]);
        switch.take_replies();
        switch.rx(&guest(OP_CREDIT_REQUEST, 0, 0), &[]);
        let reply = switch.take_replies().pop().expect("credit update");
        assert_eq!(reply.header.op, OP_CREDIT_UPDATE);
        assert_eq!(reply.header.buf_alloc, RX_ALLOC);
        assert_eq!(reply.header.fwd_cnt, 0);
    }

    #[test]
    fn diagnostic_port_requires_events() {
        let mut switch = VsockSwitch::new();
        let mut request = guest(OP_REQUEST, 0, 0);
        request.dst_port = DIAGNOSTIC_VSOCK_PORT;
        switch.rx(&request, &[]);
        assert!(!switch.connection_exists(100, DIAGNOSTIC_VSOCK_PORT));
        switch.take_replies();
        switch.set_diagnostics_enabled(true);
        switch.rx(&request, &[]);
        assert_eq!(
            switch.take_replies()[0].header.src_port,
            DIAGNOSTIC_VSOCK_PORT
        );
    }

    #[test]
    fn lifecycle_port_stays_bound_after_reset() {
        let mut switch = VsockSwitch::new();
        switch.rx(&guest(OP_REQUEST, 0, 0), &[]);
        switch.take_replies();
        switch.reset_connection(100, CONTROL_VSOCK_PORT).unwrap();
        switch.take_replies();
        switch.rx(&guest(OP_REQUEST, 0, 0), &[]);
        assert!(!switch.connection_exists(100, CONTROL_VSOCK_PORT));
        assert_eq!(switch.take_replies()[0].header.op, OP_RST);
    }

    #[test]
    fn transport_reset_keeps_events_diagnostics_enabled() {
        let mut switch = VsockSwitch::new();
        switch.set_diagnostics_enabled(true);
        switch.reset_connections();
        let mut diagnostic = guest(OP_REQUEST, 0, 0);
        diagnostic.dst_port = DIAGNOSTIC_VSOCK_PORT;
        switch.rx(&diagnostic, &[]);
        let reply = switch.take_replies().pop().unwrap();
        assert_eq!(reply.header.op, OP_RESPONSE);
        assert_eq!(reply.header.src_port, DIAGNOSTIC_VSOCK_PORT);
    }

    #[test]
    fn transport_reset_keeps_events_and_lifecycle_bindings() {
        let mut switch = VsockSwitch::new();
        switch.set_diagnostics_enabled(true);
        switch.rx(&guest(OP_REQUEST, 0, 0), &[]);
        let mut diagnostic = guest(OP_REQUEST, 0, 0);
        diagnostic.dst_port = DIAGNOSTIC_VSOCK_PORT;
        switch.rx(&diagnostic, &[]);
        switch.take_replies();

        switch.reset_connections();

        let mut repeated_control = guest(OP_REQUEST, 0, 0);
        repeated_control.src_port = 101;
        switch.rx(&repeated_control, &[]);
        let mut repeated_diagnostic = diagnostic;
        repeated_diagnostic.src_port = 101;
        switch.rx(&repeated_diagnostic, &[]);
        assert_eq!(
            switch
                .take_replies()
                .into_iter()
                .map(|reply| reply.header.op)
                .collect::<Vec<_>>(),
            vec![OP_RST, OP_RST]
        );
    }

    #[test]
    fn transport_reset_keeps_legacy_diagnostics_denied() {
        let mut switch = VsockSwitch::new();
        switch.reset_connections();
        let mut diagnostic = guest(OP_REQUEST, 0, 0);
        diagnostic.dst_port = DIAGNOSTIC_VSOCK_PORT;
        switch.rx(&diagnostic, &[]);
        assert_eq!(switch.take_replies()[0].header.op, OP_RST);
    }

    #[test]
    fn a_full_reply_queue_does_not_create_a_connection() {
        let mut switch = VsockSwitch::new();
        let invalid = VsockHeader {
            src_cid: 0,
            ..guest(OP_REQUEST, 0, 0)
        };
        for _ in 0..MAX_QUEUED_REPLIES {
            switch.rx(&invalid, &[]);
        }
        switch.rx(&guest(OP_REQUEST, 0, 0), &[]);
        assert!(!switch.connection_exists(100, CONTROL_VSOCK_PORT));
        assert_eq!(switch.take_replies().len(), MAX_QUEUED_REPLIES);
    }

    #[test]
    fn upstream_overflow_discards_the_reset_connection_data() {
        let mut switch = VsockSwitch::new();
        let data = vec![0; MAX_DATA_BYTES as usize];
        let mut overflow_port = 0;
        for _ in 0..=MAX_QUEUED_UPSTREAM_BYTES / data.len() {
            let host_port = switch.connect(AGENT_VSOCK_PORT).unwrap();
            switch.take_replies();
            let mut response = guest(OP_RESPONSE, 0, 0);
            response.src_port = AGENT_VSOCK_PORT;
            response.dst_port = host_port;
            switch.rx(&response, &[]);
            let mut upstream = guest(OP_RW, MAX_DATA_BYTES, 0);
            upstream.src_port = AGENT_VSOCK_PORT;
            upstream.dst_port = host_port;
            switch.rx(&upstream, &data);
            overflow_port = host_port;
        }
        assert!(!switch.connection_exists(AGENT_VSOCK_PORT, overflow_port));
        assert!(
            switch
                .take_upstream()
                .iter()
                .all(|item| item.host_port != overflow_port)
        );
    }

    #[test]
    fn guest_connections_cannot_fill_host_connection_table() {
        let mut switch = VsockSwitch::new();
        let last_source_port = 100 + u32::try_from(MAX_CONNECTIONS).unwrap_or(u32::MAX);
        for source_port in 100..last_source_port {
            let mut request = guest(OP_REQUEST, 0, 0);
            request.src_port = source_port;
            switch.rx(&request, &[]);
            switch.take_replies();
        }
        assert_eq!(switch.connection_count(), 1);
        assert!(switch.connect(AGENT_VSOCK_PORT).is_ok());
    }

    #[test]
    fn host_connect_requests_agent_then_relays_data_and_tears_down() {
        let mut switch = VsockSwitch::new();
        let host_port = switch.connect(AGENT_VSOCK_PORT).unwrap();
        assert!(host_port >= 0x8000_0000);

        let request = switch.take_replies().pop().unwrap();
        assert_eq!(request.header.src_cid, HOST_CID);
        assert_eq!(request.header.dst_cid, GUEST_CID);
        assert_eq!(request.header.src_port, host_port);
        assert_eq!(request.header.dst_port, AGENT_VSOCK_PORT);
        assert_eq!(request.header.op, OP_REQUEST);

        let mut response = guest(OP_RESPONSE, 0, 0);
        response.src_port = AGENT_VSOCK_PORT;
        response.dst_port = host_port;
        switch.rx(&response, &[]);
        assert_eq!(
            switch.connections_up_to(1),
            vec![(AGENT_VSOCK_PORT, host_port)]
        );

        switch
            .deliver(AGENT_VSOCK_PORT, host_port, b"host")
            .unwrap();
        let host_data = switch.take_replies().pop().unwrap();
        assert_eq!(host_data.header.op, OP_RW);
        assert_eq!(host_data.header.src_port, host_port);
        assert_eq!(host_data.header.dst_port, AGENT_VSOCK_PORT);
        assert_eq!(host_data.payload, b"host");

        let mut guest_data = guest(OP_RW, 5, 4);
        guest_data.src_port = AGENT_VSOCK_PORT;
        guest_data.dst_port = host_port;
        switch.rx(&guest_data, b"guest");
        assert_eq!(switch.take_upstream()[0].data, b"guest");
        switch.take_replies();

        switch.shutdown(AGENT_VSOCK_PORT, host_port).unwrap();
        let shutdown = switch.take_replies().pop().unwrap();
        assert_eq!(shutdown.header.op, OP_SHUTDOWN);
        assert_eq!(shutdown.header.flags, FLAG_SHUTDOWN_SEND);
        assert_eq!(shutdown.header.src_port, host_port);
        assert_eq!(shutdown.header.dst_port, AGENT_VSOCK_PORT);
        assert_eq!(
            switch.deliver(AGENT_VSOCK_PORT, host_port, b"closed"),
            Err(VsockError::UnknownConnection)
        );

        let mut guest_shutdown = guest(OP_SHUTDOWN, 0, 5);
        guest_shutdown.src_port = AGENT_VSOCK_PORT;
        guest_shutdown.dst_port = host_port;
        guest_shutdown.flags = FLAG_SHUTDOWN_SEND;
        switch.rx(&guest_shutdown, &[]);
        assert_eq!(switch.connection_count(), 0);

        let reset_port = switch.connect(AGENT_VSOCK_PORT).unwrap();
        switch.take_replies();
        let mut reset = guest(OP_RST, 0, 0);
        reset.src_port = AGENT_VSOCK_PORT;
        reset.dst_port = reset_port;
        switch
            .reset_connection(AGENT_VSOCK_PORT, reset_port)
            .unwrap();
        let reset_reply = switch.take_replies().pop().unwrap();
        assert_eq!(reset_reply.header.op, OP_RST);
        assert_eq!(reset_reply.header.src_port, reset_port);
        assert_eq!(reset_reply.header.dst_port, AGENT_VSOCK_PORT);
        switch.rx(&reset, &[]);
        assert_eq!(switch.connection_count(), 0);
    }

    #[test]
    fn host_connect_retries_an_agent_startup_reset() {
        let mut switch = VsockSwitch::new();
        let host_port = switch.connect(AGENT_VSOCK_PORT).expect("host connect");
        let request = switch.take_replies().pop().expect("initial request");

        let mut reset = guest(OP_RST, 0, 0);
        reset.src_port = AGENT_VSOCK_PORT;
        reset.dst_port = host_port;
        switch.rx(&reset, &[]);

        assert_eq!(switch.connection_count(), 1);
        assert!(switch.retry_connecting());
        let retry = switch.take_replies().pop().expect("retry request");
        assert_eq!(retry.header, request.header);

        let mut response = guest(OP_RESPONSE, 0, 0);
        response.src_port = AGENT_VSOCK_PORT;
        response.dst_port = host_port;
        switch.rx(&response, &[]);
        assert_eq!(
            switch.connections_up_to(1),
            vec![(AGENT_VSOCK_PORT, host_port)]
        );
    }

    #[test]
    fn selected_drain_bypasses_a_stalled_connection() {
        let mut switch = VsockSwitch::new();
        switch.set_diagnostics_enabled(true);
        switch.rx(&guest(OP_REQUEST, 0, 0), &[]);
        let mut diagnostic_request = guest(OP_REQUEST, 0, 0);
        diagnostic_request.dst_port = DIAGNOSTIC_VSOCK_PORT;
        switch.rx(&diagnostic_request, &[]);
        switch.take_replies();
        assert_eq!(
            switch.connections_up_to(2),
            vec![(100, CONTROL_VSOCK_PORT), (100, DIAGNOSTIC_VSOCK_PORT)]
        );

        switch.rx(&guest(OP_RW, 5, 0), b"first");
        let mut diagnostic_data = guest(OP_RW, 6, 0);
        diagnostic_data.dst_port = DIAGNOSTIC_VSOCK_PORT;
        switch.rx(&diagnostic_data, b"second");

        let drained = switch.take_upstream_for_up_to(100, DIAGNOSTIC_VSOCK_PORT, 6);
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].data, b"second");
        assert_eq!(
            switch.take_upstream_for_up_to(100, CONTROL_VSOCK_PORT, 5)[0].data,
            b"first"
        );
    }

    #[test]
    fn guest_send_close_preserves_buffered_upstream_before_eof() {
        let mut switch = VsockSwitch::new();
        let host_port = switch.connect(AGENT_VSOCK_PORT).unwrap();
        switch.take_replies();

        let mut response = guest(OP_RESPONSE, 0, 0);
        response.src_port = AGENT_VSOCK_PORT;
        response.dst_port = host_port;
        switch.rx(&response, &[]);

        let mut data = guest(OP_RW, 5, 0);
        data.src_port = AGENT_VSOCK_PORT;
        data.dst_port = host_port;
        switch.rx(&data, b"guest");

        let mut shutdown = guest(OP_SHUTDOWN, 0, 5);
        shutdown.src_port = AGENT_VSOCK_PORT;
        shutdown.dst_port = host_port;
        shutdown.flags = FLAG_SHUTDOWN_SEND;
        switch.rx(&shutdown, &[]);

        assert!(switch.connection_exists(AGENT_VSOCK_PORT, host_port));
        assert!(switch.guest_send_closed(AGENT_VSOCK_PORT, host_port));
        assert_eq!(
            switch.take_upstream_for_up_to(AGENT_VSOCK_PORT, host_port, 5)[0].data,
            b"guest"
        );
        switch.take_replies();
        switch.shutdown(AGENT_VSOCK_PORT, host_port).unwrap();
        assert_eq!(switch.connection_count(), 0);
    }

    #[test]
    fn selected_drain_splits_an_oversized_record_before_later_data() {
        let mut switch = VsockSwitch::new();
        switch.rx(&guest(OP_REQUEST, 0, 0), &[]);
        switch.take_replies();
        switch.rx(&guest(OP_RW, 6, 0), b"first!");
        switch.rx(&guest(OP_RW, 3, 0), b"two");

        assert_eq!(
            switch.take_upstream_for_up_to(100, CONTROL_VSOCK_PORT, 4)[0].data,
            b"firs"
        );
        assert_eq!(
            switch
                .take_upstream_for_up_to(100, CONTROL_VSOCK_PORT, 5)
                .into_iter()
                .map(|item| item.data)
                .collect::<Vec<_>>(),
            vec![b"t!".to_vec(), b"two".to_vec()]
        );
    }
}
