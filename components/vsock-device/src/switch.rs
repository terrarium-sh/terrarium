//! Bounded virtio-vsock carrier validation and stream state.

use crate::VsockHeader;
use std::collections::VecDeque;

pub use terra_protocol::mux::MUX_VSOCK_PORT;

pub const HOST_CID: u64 = 2;
pub const GUEST_CID: u64 = 3;
pub const MAX_CONNECTIONS: usize = 1;
pub const MAX_DATA_BYTES: u32 = 64 * 1024;
pub const RX_ALLOC: u32 = 64 * 1024;
pub const MAX_TX_BYTES: usize = 256 * 1024;
pub const MAX_QUEUED_REPLIES: usize = 128;
pub const MAX_QUEUED_REPLY_BYTES: usize = 1 << 20;
pub const MAX_QUEUED_UPSTREAM_ITEMS: usize = 128;
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
enum CreditRequest {
    Idle,
    Pending,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Connection {
    guest_port: u32,
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

fn queued_bytes(connection: &Connection) -> u32 {
    connection.rx_received.wrapping_sub(connection.rx_fwd_cnt)
}
fn unacked_bytes(sent: u32, acknowledged: u32) -> u32 {
    sent.wrapping_sub(acknowledged)
}
fn ack_ahead(acknowledged: u32, sent: u32) -> bool {
    acknowledged != sent && acknowledged.wrapping_sub(sent) < (1 << 31)
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

/// The one guest-initiated carrier to the host multiplexer.
pub struct VsockSwitch {
    connection: Option<Connection>,
    carrier_bound: bool,
    generation: u64,
    upstream: VecDeque<Upstream>,
    upstream_bytes: usize,
    replies: VecDeque<Reply>,
    reply_bytes: usize,
}

impl VsockSwitch {
    #[must_use]
    pub fn new() -> Self {
        Self {
            connection: None,
            carrier_bound: false,
            generation: 0,
            upstream: VecDeque::new(),
            upstream_bytes: 0,
            replies: VecDeque::new(),
            reply_bytes: 0,
        }
    }

    /// Forget the carrier and queued traffic. A task that captured the prior
    /// generation must not operate on a later carrier.
    pub fn reset_connections(&mut self) {
        self.connection = None;
        self.upstream.clear();
        self.upstream_bytes = 0;
        self.replies.clear();
        self.reply_bytes = 0;
        self.generation = self
            .generation
            .checked_add(1)
            .unwrap_or_else(|| std::process::abort());
    }

    /// Start a replacement device lifetime without reusing its generation.
    pub fn restart(&mut self) {
        self.reset_connections();
        self.carrier_bound = false;
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    fn connected(&self, guest_port: u32, host_port: u32) -> bool {
        host_port == MUX_VSOCK_PORT
            && self
                .connection
                .is_some_and(|connection| connection.guest_port == guest_port)
    }

    fn can_queue_reply(&self, payload_len: usize) -> bool {
        self.replies.len() < MAX_QUEUED_REPLIES
            && self.reply_bytes + payload_len <= MAX_QUEUED_REPLY_BYTES
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

    fn respond(&mut self, connection: &Connection, op: u16, flags: u32) -> bool {
        self.queue_reply(Reply {
            header: VsockHeader {
                op,
                flags,
                buf_alloc: RX_ALLOC,
                fwd_cnt: connection.rx_fwd_cnt,
                ..Self::host_header(MUX_VSOCK_PORT, connection.guest_port)
            },
            payload: Vec::new(),
        })
    }

    fn drop_connection(&mut self) {
        self.connection = None;
        self.upstream.clear();
        self.upstream_bytes = 0;
    }

    fn note_peer_credit(&mut self, header: &VsockHeader) -> bool {
        let Some(connection) = self.connection else {
            return false;
        };
        let acknowledged = header.fwd_cnt;
        if ack_ahead(acknowledged, connection.tx_fwd_cnt) {
            self.rst(connection.guest_port, MUX_VSOCK_PORT);
            self.drop_connection();
            return false;
        }
        if acknowledged != connection.peer_fwd_cnt
            && !ack_ahead(acknowledged, connection.peer_fwd_cnt)
        {
            return true;
        }
        let unacked = unacked_bytes(connection.tx_fwd_cnt, acknowledged);
        if unacked > u32::try_from(MAX_TX_BYTES).unwrap_or(u32::MAX) {
            return true;
        }
        let Some(connection) = self.connection.as_mut() else {
            return false;
        };
        connection.peer_buf_alloc = header.buf_alloc;
        connection.peer_fwd_cnt = acknowledged;
        connection.tx_pending = usize::try_from(unacked).unwrap_or(usize::MAX);
        connection.credit_request = CreditRequest::Idle;
        true
    }

    /// Process one guest packet. The only accepted REQUEST targets the carrier port.
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
        if header.dst_port != MUX_VSOCK_PORT
            || header.fwd_cnt != 0
            || self.carrier_bound
            || self.connection.is_some()
        {
            self.rst(header.src_port, header.dst_port);
            return;
        }
        let connection = Connection {
            guest_port: header.src_port,
            peer_buf_alloc: header.buf_alloc,
            peer_fwd_cnt: 0,
            rx_received: 0,
            rx_fwd_cnt: 0,
            tx_fwd_cnt: 0,
            tx_pending: 0,
            credit_request: CreditRequest::Idle,
            tx_shutdown: false,
            rx_shutdown: false,
        };
        if self.respond(&connection, OP_RESPONSE, 0) {
            self.connection = Some(connection);
            self.carrier_bound = true;
        }
    }

    fn on_rst(&mut self, header: &VsockHeader) {
        if self.connected(header.src_port, header.dst_port) {
            self.drop_connection();
        }
    }

    fn on_shutdown(&mut self, header: &VsockHeader) {
        if !self.connected(header.src_port, header.dst_port) {
            self.rst(header.src_port, header.dst_port);
            return;
        }
        let Some(mut connection) = self.connection else {
            self.rst(header.src_port, header.dst_port);
            return;
        };
        if header.flags & FLAG_SHUTDOWN_RCV != 0 {
            connection.tx_shutdown = true;
        }
        if header.flags & FLAG_SHUTDOWN_SEND != 0 {
            connection.rx_shutdown = true;
        }
        if connection.tx_shutdown && connection.rx_shutdown {
            self.drop_connection();
            return;
        }
        self.connection = Some(connection);
        if !self.respond(&connection, OP_SHUTDOWN, header.flags) {
            self.drop_connection();
        }
    }

    fn on_data(&mut self, header: &VsockHeader, data: &[u8]) {
        if !self.connected(header.src_port, header.dst_port) {
            self.rst(header.src_port, header.dst_port);
            return;
        }
        if self
            .connection
            .is_none_or(|connection| connection.rx_shutdown)
            || !self.note_peer_credit(header)
        {
            return;
        }
        let Some(connection) = self.connection else {
            return;
        };
        if u64::from(queued_bytes(&connection)) + u64::from(header.len) > u64::from(RX_ALLOC)
            || self.upstream.len() >= MAX_QUEUED_UPSTREAM_ITEMS
            || self.upstream_bytes + data.len() > MAX_QUEUED_UPSTREAM_BYTES
        {
            self.rst(header.src_port, header.dst_port);
            self.drop_connection();
            return;
        }
        let Some(connection) = self.connection.as_mut() else {
            return;
        };
        connection.rx_received = connection.rx_received.wrapping_add(header.len);
        self.upstream_bytes += data.len();
        self.upstream.push_back(Upstream {
            guest_port: header.src_port,
            host_port: MUX_VSOCK_PORT,
            data: data.to_vec(),
        });
    }

    fn on_credit(&mut self, header: &VsockHeader) {
        if !self.connected(header.src_port, header.dst_port) {
            self.rst(header.src_port, header.dst_port);
            return;
        }
        self.note_peer_credit(header);
    }

    fn on_credit_request(&mut self, header: &VsockHeader) {
        if !self.connected(header.src_port, header.dst_port) {
            self.rst(header.src_port, header.dst_port);
            return;
        }
        if !self.note_peer_credit(header) {
            return;
        }
        let Some(connection) = self.connection else {
            return;
        };
        if !self.respond(&connection, OP_CREDIT_UPDATE, 0) {
            self.drop_connection();
        }
    }

    fn request_credit(&mut self) {
        let Some(connection) = self.connection else {
            return;
        };
        if connection.credit_request == CreditRequest::Pending {
            return;
        }
        if self.queue_reply(Reply {
            header: VsockHeader {
                op: OP_CREDIT_REQUEST,
                buf_alloc: RX_ALLOC,
                fwd_cnt: connection.rx_fwd_cnt,
                ..Self::host_header(MUX_VSOCK_PORT, connection.guest_port)
            },
            payload: Vec::new(),
        }) && let Some(connection) = self.connection.as_mut()
        {
            connection.credit_request = CreditRequest::Pending;
        }
    }

    #[must_use]
    pub fn available_send_credit(&self) -> usize {
        self.connection.map_or(0, |connection| {
            connection.peer_buf_alloc.saturating_sub(unacked_bytes(
                connection.tx_fwd_cnt,
                connection.peer_fwd_cnt,
            )) as usize
        })
    }

    pub fn deliver(
        &mut self,
        guest_port: u32,
        host_port: u32,
        data: &[u8],
    ) -> Result<(), VsockError> {
        if !self.connected(guest_port, host_port) {
            return Err(VsockError::UnknownConnection);
        }
        let Some(connection) = self.connection else {
            return Err(VsockError::UnknownConnection);
        };
        if connection.tx_shutdown {
            return Err(VsockError::UnknownConnection);
        }
        let len = u32::try_from(data.len()).map_err(|_| VsockError::Backpressure)?;
        let available = self.available_send_credit();
        let exceeds_pending_cap =
            data.len() > MAX_TX_BYTES || connection.tx_pending > MAX_TX_BYTES - data.len();
        if data.len() > available || exceeds_pending_cap || !self.can_queue_reply(data.len()) {
            if data.len() <= MAX_TX_BYTES && (data.len() > available || exceeds_pending_cap) {
                self.request_credit();
            }
            return Err(VsockError::Backpressure);
        }
        self.connection = Some(Connection {
            tx_fwd_cnt: connection.tx_fwd_cnt.wrapping_add(len),
            tx_pending: connection.tx_pending + data.len(),
            ..connection
        });
        if !self.queue_reply(Reply {
            header: VsockHeader {
                len,
                op: OP_RW,
                buf_alloc: RX_ALLOC,
                fwd_cnt: connection.rx_fwd_cnt,
                ..Self::host_header(host_port, guest_port)
            },
            payload: data.to_vec(),
        }) {
            self.connection = Some(connection);
            return Err(VsockError::Backpressure);
        }
        Ok(())
    }

    pub fn shutdown(&mut self, guest_port: u32, host_port: u32) -> Result<(), VsockError> {
        if !self.connected(guest_port, host_port) {
            return Err(VsockError::UnknownConnection);
        }
        let Some(connection) = self.connection else {
            return Err(VsockError::UnknownConnection);
        };
        if connection.tx_shutdown {
            return Ok(());
        }
        if !self.can_queue_reply(0) {
            return Err(VsockError::Backpressure);
        }
        let snapshot = Connection {
            tx_shutdown: true,
            ..connection
        };
        self.connection = Some(snapshot);
        if !self.respond(&snapshot, OP_SHUTDOWN, FLAG_SHUTDOWN_SEND) {
            self.drop_connection();
            return Err(VsockError::Backpressure);
        }
        if snapshot.rx_shutdown {
            self.drop_connection();
        }
        Ok(())
    }

    pub fn reset_connection(&mut self, guest_port: u32, host_port: u32) -> Result<(), VsockError> {
        if !self.connected(guest_port, host_port) {
            return Err(VsockError::UnknownConnection);
        }
        self.rst(guest_port, host_port);
        self.drop_connection();
        Ok(())
    }

    #[must_use]
    pub fn connection_count(&self) -> usize {
        self.connection.is_some().into()
    }
    #[must_use]
    pub fn connection_exists(&self, guest_port: u32, host_port: u32) -> bool {
        self.connected(guest_port, host_port)
    }
    #[must_use]
    pub fn connection_connected(&self, guest_port: u32, host_port: u32) -> bool {
        self.connected(guest_port, host_port)
    }
    #[must_use]
    pub fn guest_send_closed(&self, guest_port: u32, host_port: u32) -> bool {
        self.connected(guest_port, host_port)
            && self
                .connection
                .is_some_and(|connection| connection.rx_shutdown)
    }
    #[must_use]
    pub fn connections_up_to(&self, max_items: usize) -> Vec<(u32, u32)> {
        self.connection
            .filter(|_| max_items != 0)
            .map(|connection| vec![(connection.guest_port, MUX_VSOCK_PORT)])
            .unwrap_or_default()
    }

    fn advance_receive_credit(&mut self, item: &Upstream) {
        if !self.connected(item.guest_port, item.host_port) {
            return;
        }
        let Some(connection) = self.connection.as_mut() else {
            return;
        };
        connection.rx_fwd_cnt = connection
            .rx_fwd_cnt
            .wrapping_add(u32::try_from(item.data.len()).unwrap_or(u32::MAX));
        let snapshot = *connection;
        if !self.respond(&snapshot, OP_CREDIT_UPDATE, 0) {
            self.drop_connection();
        }
    }

    pub fn take_replies(&mut self) -> Vec<Reply> {
        self.take_replies_up_to(usize::MAX, usize::MAX)
    }

    #[must_use]
    pub fn pending_reply_count(&self) -> usize {
        self.replies.len()
    }
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
    pub fn take_upstream_up_to(&mut self, max_bytes: usize) -> Vec<Upstream> {
        let Some(connection) = self.connection else {
            return Vec::new();
        };
        self.take_upstream_for_up_to(connection.guest_port, MUX_VSOCK_PORT, max_bytes)
    }
    pub fn take_upstream_for_up_to(
        &mut self,
        guest_port: u32,
        host_port: u32,
        max_bytes: usize,
    ) -> Vec<Upstream> {
        if !self.connected(guest_port, host_port) {
            return Vec::new();
        }
        let mut drained = Vec::new();
        let mut remaining = max_bytes;
        while remaining != 0 {
            let Some(front) = self.upstream.front() else {
                break;
            };
            let take = front.data.len().min(remaining);
            let item = if take == front.data.len() {
                let Some(item) = self.upstream.pop_front() else {
                    break;
                };
                item
            } else {
                let Some(item) = self.upstream.front_mut() else {
                    break;
                };
                Upstream {
                    guest_port: item.guest_port,
                    host_port: item.host_port,
                    data: item.data.drain(..take).collect(),
                }
            };
            remaining -= item.data.len();
            self.upstream_bytes -= item.data.len();
            self.advance_receive_credit(&item);
            drained.push(item);
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
    use super::{ack_ahead, unacked_bytes};

    #[test]
    fn credit_wrap_uses_modular_distance() {
        assert!(!ack_ahead(0, 0));
        assert!(ack_ahead(0, u32::MAX));
        assert!(!ack_ahead(u32::MAX, 0));
        assert_eq!(unacked_bytes(0, u32::MAX), 1);
    }
}
