//! Bounded virtio-vsock carrier validation and stream state.

use crate::VsockHeader;
use std::collections::VecDeque;

use terra_protocol::vsock;

pub use vsock::{MAX_NETWORK_SOCKETS, PUBLICATION_HOST_PORTS};
pub const AGENT_VSOCK_PORT: u32 = vsock::AGENT_PORT;
pub const CONTROL_VSOCK_PORT: u32 = vsock::CONTROL_PORT;
pub const TCP_VSOCK_PORT: u32 = vsock::TCP_PORT;
pub const UDP_VSOCK_PORT: u32 = vsock::UDP_PORT;
pub const PUBLICATION_VSOCK_PORT: u32 = vsock::PUBLICATION_PORT;
#[allow(clippy::cast_possible_truncation)]
pub const FLOW_RX_ALLOC: u32 = vsock::FLOW_UPSTREAM_BYTES as u32;
pub(crate) const MAX_FLOW_TX_BYTES: usize = vsock::FLOW_REPLY_BYTES;
#[allow(clippy::cast_possible_truncation)]
pub(crate) const CONTROL_RX_ALLOC: u32 = vsock::CONTROL_UPSTREAM_BYTES as u32;
pub(crate) const MAX_CONTROL_TX_BYTES: usize = vsock::CONTROL_REPLY_BYTES;

pub const HOST_CID: u64 = vsock::HOST_CID as u64;
pub const GUEST_CID: u64 = vsock::GUEST_CID as u64;
pub const MAX_DATA_BYTES: u32 = 64 * 1024;
#[allow(clippy::cast_possible_truncation)]
pub const AGENT_RX_ALLOC: u32 = vsock::AGENT_UPSTREAM_BYTES as u32;
pub(crate) const MAX_AGENT_TX_BYTES: usize = vsock::AGENT_REPLY_BYTES;
pub const MAX_QUEUED_REPLIES: usize = 128;
pub const MAX_QUEUED_REPLY_BYTES: usize = vsock::MAX_QUEUED_REPLY_BYTES;
pub const MAX_QUEUED_UPSTREAM_BYTES: usize = vsock::MAX_QUEUED_UPSTREAM_BYTES;

const RESERVED_CONTROL_REPLY_SLOTS: usize = 8;

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
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent vsock credit and half-close flags"
)]
struct Connection {
    peer_buf_alloc: u32,
    peer_fwd_cnt: u32,
    rx_received: u32,
    rx_fwd_cnt: u32,
    rx_credit_update_fwd_cnt: u32,
    is_receive_credit_requested: bool,
    tx_fwd_cnt: u32,
    is_credit_requested: bool,
    tx_shutdown: bool,
    peer_receive_closed: bool,
    rx_shutdown: bool,
}

impl Connection {
    const fn new(peer_buf_alloc: u32) -> Self {
        Self {
            peer_buf_alloc,
            peer_fwd_cnt: 0,
            rx_received: 0,
            rx_fwd_cnt: 0,
            rx_credit_update_fwd_cnt: 0,
            is_receive_credit_requested: false,
            tx_fwd_cnt: 0,
            is_credit_requested: false,
            tx_shutdown: false,
            peer_receive_closed: false,
            rx_shutdown: false,
        }
    }
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
    pub generation: u64,
    pub header: VsockHeader,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VsockError {
    Backpressure,
    Busy,
    UnknownConnection,
}

pub(crate) struct StreamConnection {
    connection: Option<Connection>,
    is_connecting: bool,
    guest_port: u32,
    host_port: u32,
    rx_alloc: u32,
    max_tx_bytes: usize,
    upstream: VecDeque<u8>,
    replies: VecDeque<Reply>,
    reply_bytes: usize,
}

impl StreamConnection {
    #[must_use]
    pub fn new(guest_port: u32, host_port: u32, rx_alloc: u32, max_tx_bytes: usize) -> Self {
        Self {
            connection: None,
            is_connecting: false,
            guest_port,
            host_port,
            rx_alloc,
            max_tx_bytes,
            upstream: VecDeque::with_capacity(rx_alloc as usize),
            replies: VecDeque::new(),
            reply_bytes: 0,
        }
    }

    fn can_queue_reply(&self, payload_len: usize) -> bool {
        self.replies.len() < MAX_QUEUED_REPLIES
            && self.reply_bytes + payload_len <= self.max_tx_bytes
    }

    fn queue_reply(&mut self, reply: Reply) -> bool {
        if !self.can_queue_reply(reply.payload.len()) {
            return false;
        }
        let credit_update = (reply.header.op == OP_CREDIT_UPDATE).then_some(reply.header.fwd_cnt);
        self.reply_bytes += reply.payload.len();
        self.replies.push_back(reply);
        if let Some(fwd_cnt) = credit_update
            && let Some(connection) = self.connection.as_mut()
        {
            connection.rx_credit_update_fwd_cnt = fwd_cnt;
        }
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
            generation: 0,
            header: VsockHeader {
                op: OP_RST,
                ..Self::host_header(host_port, guest_port)
            },
            payload: Vec::new(),
        })
    }

    fn respond(&mut self, connection: &Connection, op: u16, flags: u32) -> bool {
        if op == OP_CREDIT_UPDATE
            && let Some(reply) = self
                .replies
                .back_mut()
                .filter(|reply| reply.header.op == OP_CREDIT_UPDATE)
        {
            reply.header.fwd_cnt = connection.rx_fwd_cnt;
            if let Some(active_connection) = self.connection.as_mut() {
                active_connection.rx_credit_update_fwd_cnt = connection.rx_fwd_cnt;
            }
            return true;
        }
        self.queue_reply(Reply {
            generation: 0,
            header: VsockHeader {
                op,
                flags,
                buf_alloc: self.rx_alloc,
                fwd_cnt: connection.rx_fwd_cnt,
                ..Self::host_header(self.host_port, self.guest_port)
            },
            payload: Vec::new(),
        })
    }

    fn drop_connection(&mut self) {
        self.connection = None;
        self.is_connecting = false;
        self.upstream.clear();
    }

    fn note_peer_credit(&mut self, header: &VsockHeader) -> bool {
        let Some(connection) = self.connection else {
            return false;
        };
        let acknowledged = header.fwd_cnt;
        if ack_ahead(acknowledged, connection.tx_fwd_cnt) {
            self.rst(self.guest_port, self.host_port);
            self.drop_connection();
            return false;
        }
        if acknowledged != connection.peer_fwd_cnt
            && !ack_ahead(acknowledged, connection.peer_fwd_cnt)
        {
            return true;
        }
        let unacked = unacked_bytes(connection.tx_fwd_cnt, acknowledged);
        if unacked > u32::try_from(self.max_tx_bytes).unwrap_or(u32::MAX) {
            return true;
        }
        let prior_available = connection.peer_buf_alloc.saturating_sub(unacked_bytes(
            connection.tx_fwd_cnt,
            connection.peer_fwd_cnt,
        ));
        let available = header.buf_alloc.saturating_sub(unacked);
        let flush_receive_credit = header.buf_alloc < connection.peer_buf_alloc
            && connection.rx_fwd_cnt != connection.rx_credit_update_fwd_cnt;
        let Some(connection) = self.connection.as_mut() else {
            return false;
        };
        connection.peer_buf_alloc = header.buf_alloc;
        connection.peer_fwd_cnt = acknowledged;
        if available > prior_available {
            connection.is_credit_requested = false;
        }
        if flush_receive_credit {
            let snapshot = *connection;
            if !self.respond(&snapshot, OP_CREDIT_UPDATE, 0) {
                self.drop_connection();
                return false;
            }
        }
        true
    }

    fn reject_packet(&mut self, header: &VsockHeader) {
        if header.op != OP_RST {
            self.rst(header.src_port, header.dst_port);
        }
        if self.connection.is_some() || self.is_connecting {
            self.drop_connection();
        }
    }

    pub fn rx(&mut self, header: &VsockHeader, data: &[u8]) {
        let data_len = u64::try_from(data.len()).unwrap_or(u64::MAX);
        if header.type_ != TYPE_STREAM
            || header.src_cid != GUEST_CID
            || header.dst_cid != HOST_CID
            || (header.op == OP_RW) != (header.len > 0)
            || header.len > MAX_DATA_BYTES
            || data_len != u64::from(header.len)
            || (header.op == OP_SHUTDOWN
                && (header.flags == 0
                    || header.flags & !(FLAG_SHUTDOWN_RCV | FLAG_SHUTDOWN_SEND) != 0))
            || (header.op != OP_SHUTDOWN && header.flags != 0)
        {
            self.reject_packet(header);
            return;
        }
        if self.is_connecting && !matches!(header.op, OP_RESPONSE | OP_RST) {
            self.reject_packet(header);
            return;
        }
        match header.op {
            OP_REQUEST => self.on_request(header),
            OP_RESPONSE => self.on_response(header),
            OP_RST => self.on_rst(),
            OP_SHUTDOWN => self.on_shutdown(header),
            OP_RW => self.on_data(header, data),
            OP_CREDIT_UPDATE => self.on_credit(header),
            OP_CREDIT_REQUEST => self.on_credit_request(header),
            _ => self.reject_packet(header),
        }
    }

    fn on_request(&mut self, header: &VsockHeader) {
        if header.fwd_cnt != 0 || self.connection.is_some() || self.is_connecting {
            self.reject_packet(header);
            return;
        }
        let connection = Connection::new(header.buf_alloc);
        if self.respond(&connection, OP_RESPONSE, 0) {
            self.connection = Some(connection);
        }
    }

    fn on_response(&mut self, header: &VsockHeader) {
        if !self.is_connecting || header.fwd_cnt != 0 {
            self.reject_packet(header);
            self.is_connecting = false;
            return;
        }
        self.is_connecting = false;
        self.connection = Some(Connection::new(header.buf_alloc));
    }

    fn request(&mut self) -> bool {
        if self.connection.is_some() || self.is_connecting {
            return false;
        }
        let queued = self.queue_reply(Reply {
            generation: 0,
            header: VsockHeader {
                op: OP_REQUEST,
                buf_alloc: self.rx_alloc,
                ..Self::host_header(self.host_port, self.guest_port)
            },
            payload: Vec::new(),
        });
        if queued {
            self.is_connecting = true;
        }
        queued
    }

    fn on_rst(&mut self) {
        if self.connection.is_some() || self.is_connecting {
            self.drop_connection();
        }
    }

    fn on_shutdown(&mut self, header: &VsockHeader) {
        if self.connection.is_none() {
            self.rst(header.src_port, header.dst_port);
            return;
        }
        if !self.note_peer_credit(header) {
            return;
        }
        let Some(mut connection) = self.connection else {
            self.rst(header.src_port, header.dst_port);
            return;
        };
        if header.flags & FLAG_SHUTDOWN_RCV != 0 {
            connection.tx_shutdown = true;
            connection.peer_receive_closed = true;
            self.replies.retain(|reply| reply.header.op != OP_RW);
            self.reply_bytes = 0;
        }
        if header.flags & FLAG_SHUTDOWN_SEND != 0 {
            connection.rx_shutdown = true;
        }
        self.connection = Some(connection);
    }

    fn on_data(&mut self, header: &VsockHeader, data: &[u8]) {
        if self.connection.is_none() {
            self.rst(header.src_port, header.dst_port);
            return;
        }
        if self
            .connection
            .is_none_or(|connection| connection.rx_shutdown)
        {
            self.reject_packet(header);
            return;
        }
        if !self.note_peer_credit(header) {
            return;
        }
        let Some(connection) = self.connection else {
            return;
        };
        if u64::from(queued_bytes(&connection)) + u64::from(header.len) > u64::from(self.rx_alloc)
            || self.upstream.len() + data.len() > self.rx_alloc as usize
        {
            self.rst(header.src_port, header.dst_port);
            self.drop_connection();
            return;
        }
        let Some(connection) = self.connection.as_mut() else {
            return;
        };
        connection.rx_received = connection.rx_received.wrapping_add(header.len);
        self.upstream.extend(data.iter().copied());
    }

    fn on_credit(&mut self, header: &VsockHeader) {
        if self.connection.is_none() {
            self.rst(header.src_port, header.dst_port);
            return;
        }
        self.note_peer_credit(header);
    }

    fn on_credit_request(&mut self, header: &VsockHeader) {
        if self.connection.is_none() {
            self.rst(header.src_port, header.dst_port);
            return;
        }
        if !self.note_peer_credit(header) {
            return;
        }
        let Some(connection) = self.connection.as_mut() else {
            return;
        };
        connection.is_receive_credit_requested = queued_bytes(connection) != 0;
        let snapshot = *connection;
        if !self.respond(&snapshot, OP_CREDIT_UPDATE, 0) {
            self.drop_connection();
        }
    }

    fn request_credit(&mut self) -> bool {
        let Some(connection) = self.connection else {
            return false;
        };
        if connection.is_credit_requested {
            return false;
        }
        if self.queue_reply(Reply {
            generation: 0,
            header: VsockHeader {
                op: OP_CREDIT_REQUEST,
                buf_alloc: self.rx_alloc,
                fwd_cnt: connection.rx_fwd_cnt,
                ..Self::host_header(self.host_port, self.guest_port)
            },
            payload: Vec::new(),
        }) && let Some(connection) = self.connection.as_mut()
        {
            connection.is_credit_requested = true;
            return true;
        }
        false
    }

    #[must_use]
    fn available_send_credit(&self) -> usize {
        self.connection
            .filter(|connection| !connection.tx_shutdown)
            .map_or(0, |connection| {
                let unacknowledged =
                    unacked_bytes(connection.tx_fwd_cnt, connection.peer_fwd_cnt) as usize;
                (connection.peer_buf_alloc as usize)
                    .saturating_sub(unacknowledged)
                    .min(self.max_tx_bytes.saturating_sub(unacknowledged))
            })
    }

    fn send_capacity(&self) -> usize {
        if self.replies.len() >= MAX_QUEUED_REPLIES - RESERVED_CONTROL_REPLY_SLOTS {
            return 0;
        }
        self.available_send_credit()
            .min(MAX_DATA_BYTES as usize)
            .min(self.max_tx_bytes.saturating_sub(self.reply_bytes))
    }

    pub fn deliver(&mut self, data: Vec<u8>) -> Result<(), VsockError> {
        let Some(connection) = self.connection else {
            return Err(VsockError::UnknownConnection);
        };
        if connection.tx_shutdown {
            return Err(VsockError::UnknownConnection);
        }
        if data.is_empty() {
            return Ok(());
        }
        let len = u32::try_from(data.len()).map_err(|_| VsockError::Backpressure)?;
        if data.len() > self.send_capacity() {
            if data.len() <= self.max_tx_bytes && data.len() > self.available_send_credit() {
                self.request_credit();
            }
            return Err(VsockError::Backpressure);
        }
        self.connection = Some(Connection {
            tx_fwd_cnt: connection.tx_fwd_cnt.wrapping_add(len),
            ..connection
        });
        if !self.queue_reply(Reply {
            generation: 0,
            header: VsockHeader {
                len,
                op: OP_RW,
                buf_alloc: self.rx_alloc,
                fwd_cnt: connection.rx_fwd_cnt,
                ..Self::host_header(self.host_port, self.guest_port)
            },
            payload: data,
        }) {
            self.connection = Some(connection);
            return Err(VsockError::Backpressure);
        }
        Ok(())
    }

    pub fn shutdown(&mut self) -> Result<(), VsockError> {
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
        Ok(())
    }

    #[must_use]
    pub fn guest_send_closed(&self) -> bool {
        self.connection
            .is_some_and(|connection| connection.rx_shutdown)
    }
    fn advance_receive_credit(&mut self, count: usize) {
        let Some(connection) = self.connection.as_mut() else {
            return;
        };
        connection.rx_fwd_cnt = connection
            .rx_fwd_cnt
            .wrapping_add(u32::try_from(count).unwrap_or(u32::MAX));
        let snapshot = *connection;
        if queued_bytes(&snapshot) == 0 {
            connection.is_receive_credit_requested = false;
        }
        if self.host_port != AGENT_VSOCK_PORT
            && !snapshot.is_receive_credit_requested
            && snapshot
                .rx_fwd_cnt
                .wrapping_sub(snapshot.rx_credit_update_fwd_cnt)
                < self.rx_alloc.min(snapshot.peer_buf_alloc) / 2
            && self
                .replies
                .back()
                .is_none_or(|reply| reply.header.op != OP_CREDIT_UPDATE)
        {
            return;
        }
        if !self.respond(&snapshot, OP_CREDIT_UPDATE, 0) {
            self.drop_connection();
        }
    }

    fn take_reply(&mut self, max_bytes: usize) -> Option<Reply> {
        if self
            .replies
            .front()
            .is_none_or(|reply| reply.payload.len() > max_bytes)
        {
            return None;
        }
        let reply = self.replies.pop_front()?;
        self.reply_bytes -= reply.payload.len();
        Some(reply)
    }

    #[cfg(test)]
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
    fn consume_upstream(&mut self, max_bytes: usize) {
        let count = max_bytes.min(self.upstream.len());
        if count != 0 {
            drop(self.upstream.drain(..count));
            self.advance_receive_credit(count);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    Agent,
    Control,
    Tcp,
    Udp,
    Publication,
}

impl Role {
    const fn buffers(self) -> (u32, usize) {
        match self {
            Self::Agent => (AGENT_RX_ALLOC, MAX_AGENT_TX_BYTES),
            Self::Control => (CONTROL_RX_ALLOC, MAX_CONTROL_TX_BYTES),
            Self::Tcp | Self::Udp | Self::Publication => (FLOW_RX_ALLOC, MAX_FLOW_TX_BYTES),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ConnectionId {
    pub role: Role,
    pub guest_port: u32,
    pub host_port: u32,
    pub generation: u64,
}

struct Endpoint {
    role: Role,
    stream: StreamConnection,
    generation: u64,
    retiring: Option<u64>,
}

impl Endpoint {
    fn new(role: Role, guest_port: u32, host_port: u32, generation: u64) -> Self {
        let (rx_alloc, max_tx_bytes) = role.buffers();
        Self {
            role,
            stream: StreamConnection::new(guest_port, host_port, rx_alloc, max_tx_bytes),
            generation,
            retiring: None,
        }
    }

    fn identity(&self, generation: u64) -> ConnectionId {
        ConnectionId {
            role: self.role,
            guest_port: self.stream.guest_port,
            host_port: self.stream.host_port,
            generation,
        }
    }

    fn connected(&self) -> Option<ConnectionId> {
        self.stream
            .connection
            .map(|_| self.identity(self.generation))
    }

    fn is_live(&self) -> bool {
        self.stream.connection.is_some() || self.stream.is_connecting
    }

    fn retire(&mut self, generation: u64) {
        if self.is_live() || self.retiring.is_none() {
            self.retiring = Some(self.generation);
            self.generation = generation;
        }
        self.stream.drop_connection();
        self.stream
            .replies
            .retain(|reply| reply.header.op == OP_RST);
        self.stream.reply_bytes = 0;
    }
}

/// Fixed agent and control endpoints followed by at most [`MAX_NETWORK_SOCKETS`] flows.
pub struct VsockSwitch {
    endpoints: Vec<Endpoint>,
    next_generation: u64,
    network_enabled: bool,
    network_socket_capacity: usize,
    next_reply: usize,
    next_flow_reply: usize,
    rejected: VecDeque<Reply>,
}

const FIXED_ENDPOINTS: usize = 2;

impl VsockSwitch {
    #[must_use]
    pub fn new() -> Self {
        Self::with_network_socket_capacity(true, MAX_NETWORK_SOCKETS)
    }

    #[must_use]
    #[cfg(any(test, feature = "fuzzing"))]
    pub fn with_network(network_enabled: bool) -> Self {
        Self::with_network_socket_capacity(network_enabled, MAX_NETWORK_SOCKETS)
    }

    #[must_use]
    pub fn with_network_socket_capacity(
        network_enabled: bool,
        network_socket_capacity: usize,
    ) -> Self {
        Self {
            endpoints: vec![
                Endpoint::new(Role::Agent, AGENT_VSOCK_PORT, AGENT_VSOCK_PORT, 1),
                Endpoint::new(Role::Control, CONTROL_VSOCK_PORT, CONTROL_VSOCK_PORT, 2),
            ],
            next_generation: 3,
            network_enabled,
            network_socket_capacity: network_socket_capacity.min(MAX_NETWORK_SOCKETS),
            next_reply: 0,
            next_flow_reply: 0,
            rejected: VecDeque::new(),
        }
    }

    fn allocate_generation(&mut self) -> u64 {
        let generation = self.next_generation;
        self.next_generation = generation
            .checked_add(1)
            .unwrap_or_else(|| std::process::abort());
        generation
    }

    fn classify(&self, guest_port: u32, host_port: u32) -> Option<Role> {
        match (guest_port, host_port) {
            (AGENT_VSOCK_PORT, AGENT_VSOCK_PORT) => Some(Role::Agent),
            (CONTROL_VSOCK_PORT, CONTROL_VSOCK_PORT) if self.network_enabled => Some(Role::Control),
            (guest_port, TCP_VSOCK_PORT)
                if self.network_enabled && vsock::is_flow_guest_port(guest_port) =>
            {
                Some(Role::Tcp)
            }
            (guest_port, UDP_VSOCK_PORT)
                if self.network_enabled && vsock::is_flow_guest_port(guest_port) =>
            {
                Some(Role::Udp)
            }
            (PUBLICATION_VSOCK_PORT, host_port)
                if self.network_enabled && PUBLICATION_HOST_PORTS.contains(&host_port) =>
            {
                Some(Role::Publication)
            }
            _ => None,
        }
    }

    fn endpoint_index(&self, guest_port: u32, host_port: u32) -> Option<usize> {
        self.endpoints.iter().position(|endpoint| {
            endpoint.stream.guest_port == guest_port && endpoint.stream.host_port == host_port
        })
    }

    fn connection_index(&self, connection: ConnectionId) -> Option<usize> {
        self.endpoint_index(connection.guest_port, connection.host_port)
            .filter(|&index| self.endpoints[index].connected() == Some(connection))
    }

    fn reject(&mut self, header: &VsockHeader) {
        if header.op != OP_RST && self.rejected.len() < 32 {
            let generation = self
                .endpoint_index(header.src_port, header.dst_port)
                .map_or(0, |index| self.endpoints[index].generation);
            self.rejected.push_back(Reply {
                generation,
                header: VsockHeader {
                    op: OP_RST,
                    ..StreamConnection::host_header(header.dst_port, header.src_port)
                },
                payload: Vec::new(),
            });
        }
    }

    #[must_use]
    pub fn network_socket_count(&self) -> usize {
        self.endpoints.len() - FIXED_ENDPOINTS
    }

    pub fn rx(&mut self, header: &VsockHeader, bytes: &[u8]) -> Option<ConnectionId> {
        let Some(role) = self.classify(header.src_port, header.dst_port) else {
            self.reject(header);
            return None;
        };
        let index = if let Some(index) = self.endpoint_index(header.src_port, header.dst_port) {
            index
        } else {
            if !matches!(role, Role::Tcp | Role::Udp)
                || header.op != OP_REQUEST
                || header.type_ != TYPE_STREAM
                || header.src_cid != GUEST_CID
                || header.dst_cid != HOST_CID
                || header.len != 0
                || !bytes.is_empty()
                || header.flags != 0
                || header.fwd_cnt != 0
                || self.network_socket_count() >= self.network_socket_capacity
            {
                self.reject(header);
                return None;
            }
            self.rejected.retain(|reply| {
                reply.header.dst_port != header.src_port || reply.header.src_port != header.dst_port
            });
            let generation = self.allocate_generation();
            self.endpoints.push(Endpoint::new(
                role,
                header.src_port,
                header.dst_port,
                generation,
            ));
            self.endpoints.len() - 1
        };
        if self.endpoints[index].retiring.is_some() {
            self.reject(header);
            return None;
        }
        let touched = self.endpoints[index].identity(self.endpoints[index].generation);
        let was_live = self.endpoints[index].is_live();
        self.endpoints[index].stream.rx(header, bytes);
        if was_live && !self.endpoints[index].is_live() {
            self.retire_endpoint(index);
        }
        Some(touched)
    }

    fn retire_endpoint(&mut self, index: usize) {
        let generation = self.allocate_generation();
        self.endpoints[index].retire(generation);
    }

    /// Queue a host-initiated request to the guest publication listener.
    pub fn connect_publication(&mut self, host_port: u32) -> Result<ConnectionId, VsockError> {
        if !self.network_enabled
            || !PUBLICATION_HOST_PORTS.contains(&host_port)
            || self.network_socket_count() >= self.network_socket_capacity
        {
            return Err(VsockError::Backpressure);
        }
        if self
            .endpoint_index(PUBLICATION_VSOCK_PORT, host_port)
            .is_some()
        {
            return Err(VsockError::Busy);
        }
        let generation = self.allocate_generation();
        let mut endpoint = Endpoint::new(
            Role::Publication,
            PUBLICATION_VSOCK_PORT,
            host_port,
            generation,
        );
        if !endpoint.stream.request() {
            return Err(VsockError::Backpressure);
        }
        let connection = endpoint.identity(generation);
        self.endpoints.push(endpoint);
        Ok(connection)
    }

    #[must_use]
    pub fn is_connecting(&self, connection: ConnectionId) -> bool {
        self.endpoint_index(connection.guest_port, connection.host_port)
            .is_some_and(|index| {
                let endpoint = &self.endpoints[index];
                endpoint.generation == connection.generation && endpoint.stream.is_connecting
            })
    }

    #[must_use]
    pub fn connection(&self, role: Role) -> Option<ConnectionId> {
        match role {
            Role::Agent => self.connection_for(AGENT_VSOCK_PORT, AGENT_VSOCK_PORT),
            Role::Control => self.connection_for(CONTROL_VSOCK_PORT, CONTROL_VSOCK_PORT),
            Role::Tcp | Role::Udp | Role::Publication => None,
        }
    }

    #[must_use]
    pub fn connection_for(&self, guest_port: u32, host_port: u32) -> Option<ConnectionId> {
        self.endpoint_index(guest_port, host_port)
            .and_then(|index| self.endpoints[index].connected())
    }

    #[must_use]
    pub fn is_current(&self, connection: ConnectionId) -> bool {
        self.connection_index(connection).is_some()
    }

    #[must_use]
    #[cfg(any(test, feature = "fuzzing"))]
    pub fn connections(&self) -> Vec<ConnectionId> {
        self.endpoints
            .iter()
            .filter_map(Endpoint::connected)
            .collect()
    }

    #[must_use]
    pub fn flow_connections(&self) -> Vec<ConnectionId> {
        self.endpoints
            .iter()
            .skip(FIXED_ENDPOINTS)
            .filter_map(Endpoint::connected)
            .collect()
    }

    fn stream_mut(
        &mut self,
        connection: ConnectionId,
    ) -> Result<&mut StreamConnection, VsockError> {
        let index = self
            .connection_index(connection)
            .ok_or(VsockError::UnknownConnection)?;
        Ok(&mut self.endpoints[index].stream)
    }

    /// Return true when the retired generation and its queued reset have been released.
    pub fn retire_connection(&mut self, connection: ConnectionId) -> bool {
        let Some(index) = self.endpoint_index(connection.guest_port, connection.host_port) else {
            return false;
        };
        let endpoint = &self.endpoints[index];
        if endpoint.role != connection.role
            || endpoint.retiring != Some(connection.generation)
            || !endpoint.stream.replies.is_empty()
        {
            return false;
        }
        if index >= FIXED_ENDPOINTS {
            self.endpoints.remove(index);
        } else {
            let generation = self.allocate_generation();
            let endpoint = &mut self.endpoints[index];
            endpoint.retiring = None;
            endpoint.generation = generation;
        }
        self.rejected.retain(|reply| {
            reply.header.dst_port != connection.guest_port
                || reply.header.src_port != connection.host_port
        });
        true
    }

    pub fn retirements(&self) -> impl Iterator<Item = ConnectionId> + '_ {
        self.endpoints.iter().filter_map(|endpoint| {
            endpoint
                .retiring
                .map(|generation| endpoint.identity(generation))
        })
    }

    #[must_use]
    pub fn is_retiring(&self, connection: ConnectionId) -> bool {
        self.endpoint_index(connection.guest_port, connection.host_port)
            .is_some_and(|index| {
                let endpoint = &self.endpoints[index];
                endpoint.role == connection.role && endpoint.retiring == Some(connection.generation)
            })
    }

    pub fn reset_connections(&mut self) {
        for index in 0..self.endpoints.len() {
            if self.endpoints[index].is_live() {
                self.retire_endpoint(index);
            }
            self.endpoints[index].stream.replies.clear();
        }
        self.rejected.clear();
    }

    pub(crate) fn reset_network_connections(&mut self) {
        for index in 1..self.endpoints.len() {
            let endpoint = &mut self.endpoints[index];
            if endpoint.is_live() {
                let guest_port = endpoint.stream.guest_port;
                let host_port = endpoint.stream.host_port;
                endpoint.stream.rst(guest_port, host_port);
                self.retire_endpoint(index);
            }
        }
    }

    pub fn disable_network(&mut self) {
        self.network_enabled = false;
        self.reset_network_connections();
    }

    #[must_use]
    #[cfg(test)]
    pub fn input_budget(&self, connection: ConnectionId) -> usize {
        self.connection_index(connection)
            .map_or(0, |index| self.endpoints[index].stream.rx_alloc as usize)
    }

    #[must_use]
    pub fn output_budget(&self, connection: ConnectionId) -> usize {
        self.connection_index(connection)
            .map_or(0, |index| self.endpoints[index].stream.max_tx_bytes)
    }

    #[must_use]
    pub fn available_send_credit(&self, connection: ConnectionId) -> usize {
        self.connection_index(connection).map_or(0, |index| {
            self.endpoints[index].stream.available_send_credit()
        })
    }

    #[must_use]
    pub fn send_capacity(&self, connection: ConnectionId) -> usize {
        self.connection_index(connection)
            .map_or(0, |index| self.endpoints[index].stream.send_capacity())
    }

    /// Return true when a fresh credit request was queued.
    pub fn request_credit(&mut self, connection: ConnectionId) -> Result<bool, VsockError> {
        Ok(self.stream_mut(connection)?.request_credit())
    }

    pub fn deliver(&mut self, connection: ConnectionId, bytes: Vec<u8>) -> Result<(), VsockError> {
        if bytes.len() > MAX_DATA_BYTES as usize {
            return Err(VsockError::Backpressure);
        }
        self.stream_mut(connection)?.deliver(bytes)
    }

    pub fn shutdown(&mut self, connection: ConnectionId) -> Result<(), VsockError> {
        self.stream_mut(connection)?.shutdown()
    }

    pub fn reset_connection(&mut self, connection: ConnectionId) -> Result<(), VsockError> {
        let index = self
            .endpoint_index(connection.guest_port, connection.host_port)
            .filter(|&index| {
                let endpoint = &self.endpoints[index];
                endpoint.generation == connection.generation && endpoint.is_live()
            })
            .ok_or(VsockError::UnknownConnection)?;
        self.endpoints[index]
            .stream
            .rst(connection.guest_port, connection.host_port);
        self.retire_endpoint(index);
        Ok(())
    }

    #[must_use]
    pub fn guest_receive_closed(&self, connection: ConnectionId) -> bool {
        self.connection_index(connection).is_some_and(|index| {
            self.endpoints[index]
                .stream
                .connection
                .is_some_and(|connection| connection.peer_receive_closed)
        })
    }

    #[must_use]
    pub fn guest_send_closed(&self, connection: ConnectionId) -> bool {
        self.connection_index(connection)
            .is_some_and(|index| self.endpoints[index].stream.guest_send_closed())
    }

    #[must_use]
    pub fn peek_upstream(&self, connection: ConnectionId, max_bytes: usize) -> Vec<u8> {
        let Some(index) = self.connection_index(connection) else {
            return Vec::new();
        };
        let (first, second) = self.endpoints[index].stream.upstream.as_slices();
        let mut bytes = Vec::with_capacity(max_bytes.min(first.len() + second.len()));
        bytes.extend_from_slice(&first[..first.len().min(max_bytes)]);
        bytes.extend_from_slice(&second[..second.len().min(max_bytes.saturating_sub(first.len()))]);
        bytes
    }

    pub fn consume_upstream(
        &mut self,
        connection: ConnectionId,
        max_bytes: usize,
    ) -> Result<(), VsockError> {
        let index = self
            .connection_index(connection)
            .ok_or(VsockError::UnknownConnection)?;
        self.endpoints[index].stream.consume_upstream(max_bytes);
        if self.endpoints[index].stream.connection.is_none() {
            self.retire_endpoint(index);
        }
        Ok(())
    }

    #[must_use]
    pub fn is_reply_current(&self, reply: &Reply) -> bool {
        self.endpoint_index(reply.header.dst_port, reply.header.src_port)
            .map_or(reply.generation == 0, |index| {
                let endpoint = &self.endpoints[index];
                endpoint.generation == reply.generation
                    && (reply.header.op != OP_RW
                        || !endpoint
                            .stream
                            .connection
                            .is_some_and(|connection| connection.peer_receive_closed))
            })
    }

    #[must_use]
    pub fn has_pending_replies_for(&self, connection: ConnectionId) -> bool {
        self.endpoint_index(connection.guest_port, connection.host_port)
            .is_some_and(|index| {
                let endpoint = &self.endpoints[index];
                (endpoint.generation == connection.generation
                    || endpoint.retiring == Some(connection.generation))
                    && !endpoint.stream.replies.is_empty()
            })
    }

    #[must_use]
    pub fn pending_reply_count(&self) -> usize {
        self.endpoints
            .iter()
            .map(|endpoint| endpoint.stream.replies.len())
            .sum::<usize>()
            + self.rejected.len()
    }

    fn take_reply_from(&mut self, index: usize, max_bytes: usize) -> Option<Reply> {
        self.endpoints[index]
            .stream
            .take_reply(max_bytes)
            .map(|reply| Reply {
                generation: self.endpoints[index].generation,
                ..reply
            })
    }

    fn take_flow_reply(&mut self, max_bytes: usize) -> Option<Reply> {
        let count = self.network_socket_count();
        // ponytail: scans at most MAX_NETWORK_SOCKETS flows; use an active queue if throughput needs it.
        for offset in 0..count {
            let index = FIXED_ENDPOINTS + (self.next_flow_reply + offset) % count;
            if let Some(reply) = self.take_reply_from(index, max_bytes) {
                self.next_flow_reply = (index - FIXED_ENDPOINTS + 1) % count;
                return Some(reply);
            }
        }
        None
    }

    pub fn take_reply(&mut self, max_bytes: usize) -> Option<Reply> {
        for offset in 0..3 {
            let class = (self.next_reply + offset) % 3;
            let reply = match class {
                0 | 1 => self.take_reply_from(class, max_bytes),
                2 => self.take_flow_reply(max_bytes),
                _ => unreachable!(),
            };
            if let Some(reply) = reply {
                self.next_reply = (class + 1) % 3;
                return Some(reply);
            }
        }
        self.rejected.pop_front()
    }

    pub fn take_replies_up_to(&mut self, max_items: usize, max_bytes: usize) -> Vec<Reply> {
        let mut replies = Vec::new();
        let mut remaining = max_bytes;
        while replies.len() < max_items {
            let Some(reply) = self.take_reply(remaining) else {
                break;
            };
            remaining -= reply.payload.len();
            replies.push(reply);
        }
        replies
    }

    pub fn take_replies(&mut self) -> Vec<Reply> {
        self.take_replies_up_to(usize::MAX, usize::MAX)
    }
}

impl Default for VsockSwitch {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "fuzzing")]
/// # Panics
/// Panics if hostile traffic violates a queue or credit bound.
pub fn fuzz_rx_sequence(mut bytes: &[u8]) {
    let mut switch = VsockSwitch::new();
    for (guest_port, host_port) in [
        (AGENT_VSOCK_PORT, AGENT_VSOCK_PORT),
        (CONTROL_VSOCK_PORT, CONTROL_VSOCK_PORT),
        (TCP_VSOCK_PORT, TCP_VSOCK_PORT),
        (UDP_VSOCK_PORT, UDP_VSOCK_PORT),
    ] {
        switch.rx(
            &VsockHeader {
                src_cid: GUEST_CID,
                dst_cid: HOST_CID,
                src_port: guest_port,
                dst_port: host_port,
                type_: TYPE_STREAM,
                op: OP_REQUEST,
                buf_alloc: AGENT_RX_ALLOC,
                ..StreamConnection::host_header(host_port, guest_port)
            },
            &[],
        );
    }
    let _ = switch.connect_publication(PUBLICATION_HOST_PORTS.start);
    switch.take_replies();
    for _ in 0..1024 {
        let Some((&operation, rest)) = bytes.split_first() else {
            break;
        };
        if rest.len() < 2 {
            break;
        }
        let len = usize::from(u16::from_le_bytes([rest[0], rest[1]])).min(rest.len() - 2);
        let payload = &rest[2..2 + len];
        bytes = &rest[2 + len..];
        let connections = switch.connections();
        let connection = connections
            .get(usize::from(operation) % connections.len().max(1))
            .copied();
        match operation % 9 {
            0 => {
                if let Ok((header, body)) = VsockHeader::parse(payload) {
                    switch.rx(&header, body);
                }
            }
            1 => {
                if let Some(connection) = connection {
                    let _ = switch.deliver(connection, payload.to_vec());
                }
            }
            2 => {
                if let Some(connection) = connection {
                    let _ = switch.consume_upstream(connection, len);
                }
            }
            3 => switch.reset_connections(),
            4 => {
                if let Some(connection) = connection {
                    let _ = switch.reset_connection(connection);
                }
            }
            5 => {
                if let Some(connection) = connection {
                    let _ = switch.shutdown(connection);
                }
            }
            6 => {
                switch.take_replies_up_to(32, 64 * 1024);
            }
            7 => {
                for connection in switch.retirements().collect::<Vec<_>>() {
                    switch.retire_connection(connection);
                }
            }
            8 => {
                let _ = switch
                    .connect_publication(PUBLICATION_HOST_PORTS.start + u32::from(operation >> 4));
            }
            _ => unreachable!(),
        }
        assert!(switch.network_socket_count() <= MAX_NETWORK_SOCKETS);
        for endpoint in &switch.endpoints {
            assert!(endpoint.stream.upstream.len() <= endpoint.stream.rx_alloc as usize);
            assert_eq!(
                endpoint.stream.upstream.capacity(),
                endpoint.stream.rx_alloc as usize
            );
            assert!(endpoint.stream.reply_bytes <= endpoint.stream.max_tx_bytes);
            assert!(endpoint.stream.replies.len() <= MAX_QUEUED_REPLIES);
            if let Some(connection) = endpoint.stream.connection {
                assert_eq!(
                    usize::try_from(queued_bytes(&connection)).unwrap_or(usize::MAX),
                    endpoint.stream.upstream.len()
                );
                assert!(
                    unacked_bytes(connection.tx_fwd_cnt, connection.peer_fwd_cnt) as usize
                        <= endpoint.stream.max_tx_bytes
                );
                assert!(
                    connection
                        .rx_fwd_cnt
                        .wrapping_sub(connection.rx_credit_update_fwd_cnt)
                        <= endpoint.stream.rx_alloc
                );
            }
        }
        assert!(switch.rejected.len() <= 32);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CONTROL_VSOCK_PORT, FLOW_RX_ALLOC, GUEST_CID, HOST_CID, MAX_QUEUED_REPLIES,
        OP_CREDIT_REQUEST, OP_CREDIT_UPDATE, OP_REQUEST, OP_RW, OP_SHUTDOWN,
        PUBLICATION_HOST_PORTS, StreamConnection, TCP_VSOCK_PORT, TYPE_STREAM, UDP_VSOCK_PORT,
        VsockError, VsockHeader, VsockSwitch, ack_ahead, unacked_bytes,
    };

    #[test]
    fn credit_wrap_uses_modular_distance() {
        assert!(!ack_ahead(0, 0));
        assert!(ack_ahead(0, u32::MAX));
        assert!(!ack_ahead(u32::MAX, 0));
        assert_eq!(unacked_bytes(0, u32::MAX), 1);

        let mut switch = VsockSwitch::new();
        let request = VsockHeader {
            src_cid: GUEST_CID,
            dst_cid: HOST_CID,
            src_port: 12345,
            dst_port: TCP_VSOCK_PORT,
            len: 0,
            type_: TYPE_STREAM,
            op: OP_REQUEST,
            flags: 0,
            buf_alloc: u32::MAX,
            fwd_cnt: 0,
        };
        switch.rx(&request, &[]);
        switch.take_replies();
        let connection = switch.connection_for(12345, TCP_VSOCK_PORT).unwrap();
        let index = switch.connection_index(connection).unwrap();
        let stream = &mut switch.endpoints[index].stream;
        stream.max_tx_bytes = 4;
        let counters = stream.connection.as_mut().unwrap();
        counters.tx_fwd_cnt = u32::MAX - 1;
        counters.peer_fwd_cnt = u32::MAX - 1;
        switch.deliver(connection, b"four".to_vec()).unwrap();
        switch.take_replies();
        assert_eq!(switch.available_send_credit(connection), 0);
        let mut credit = VsockHeader {
            op: super::OP_CREDIT_UPDATE,
            fwd_cnt: 0,
            ..request
        };
        switch.rx(&credit, &[]);
        assert_eq!(switch.available_send_credit(connection), 2);
        switch.deliver(connection, b"ab".to_vec()).unwrap();
        switch.take_replies();
        credit.fwd_cnt = u32::MAX;
        switch.rx(&credit, &[]);
        assert_eq!(switch.available_send_credit(connection), 0);
        assert_eq!(
            switch.deliver(connection, b"x".to_vec()),
            Err(VsockError::Backpressure)
        );
    }

    fn credit_test_stream(host_port: u32) -> (StreamConnection, VsockHeader) {
        let mut stream = StreamConnection::new(12345, host_port, 8, 16);
        let opening = VsockHeader {
            src_cid: GUEST_CID,
            dst_cid: HOST_CID,
            src_port: 12345,
            dst_port: host_port,
            buf_alloc: 16,
            op: OP_REQUEST,
            ..StreamConnection::host_header(host_port, 12345)
        };
        stream.rx(&opening, &[]);
        stream.take_replies_up_to(usize::MAX, usize::MAX);
        (stream, opening)
    }

    #[test]
    fn network_receive_credit_batches_without_delaying_explicit_requests() {
        for host_port in [
            CONTROL_VSOCK_PORT,
            TCP_VSOCK_PORT,
            UDP_VSOCK_PORT,
            PUBLICATION_HOST_PORTS.start,
        ] {
            let (mut stream, opening) = credit_test_stream(host_port);
            stream.rx(
                &VsockHeader {
                    op: OP_RW,
                    len: 8,
                    ..opening
                },
                b"abcdefgh",
            );
            stream.consume_upstream(0);
            stream.consume_upstream(1);
            assert!(stream.replies.is_empty());
            stream.deliver(b"reply".to_vec()).unwrap();
            assert_eq!(stream.connection.unwrap().rx_credit_update_fwd_cnt, 0);
            stream.consume_upstream(2);
            assert_eq!(stream.replies.len(), 1);
            stream.rx(
                &VsockHeader {
                    op: OP_CREDIT_REQUEST,
                    ..opening
                },
                &[],
            );
            let replies = stream.take_replies_up_to(usize::MAX, usize::MAX);
            assert_eq!(
                replies
                    .iter()
                    .map(|reply| reply.header.op)
                    .collect::<Vec<_>>(),
                [OP_RW, OP_CREDIT_UPDATE]
            );
            assert_eq!(
                replies
                    .iter()
                    .map(|reply| reply.header.fwd_cnt)
                    .collect::<Vec<_>>(),
                [1, 3]
            );
            assert_eq!(stream.connection.unwrap().rx_credit_update_fwd_cnt, 3);
            stream.consume_upstream(1);
            assert_eq!(stream.replies[0].header.fwd_cnt, 4);
            assert!(stream.connection.unwrap().is_receive_credit_requested);
            stream.take_replies_up_to(usize::MAX, usize::MAX);
            stream.consume_upstream(3);
            assert_eq!(stream.replies.len(), 1);
            assert_eq!(stream.replies[0].header.fwd_cnt, 7);
            assert!(stream.connection.unwrap().is_receive_credit_requested);
            stream.take_replies_up_to(usize::MAX, usize::MAX);
            stream.consume_upstream(1);
            assert_eq!(stream.replies.len(), 1);
            assert_eq!(stream.replies[0].header.fwd_cnt, 8);
            assert_eq!(stream.connection.unwrap().rx_credit_update_fwd_cnt, 8);
            assert!(!stream.connection.unwrap().is_receive_credit_requested);
        }
    }

    #[test]
    fn early_credit_request_survives_partial_drains_and_counter_wrap() {
        let (mut stream, opening) = credit_test_stream(UDP_VSOCK_PORT);
        stream.rx(
            &VsockHeader {
                op: OP_RW,
                len: 3,
                ..opening
            },
            b"abc",
        );
        let start = u32::MAX - 1;
        let connection = stream.connection.as_mut().unwrap();
        connection.rx_received = start.wrapping_add(3);
        connection.rx_fwd_cnt = start;
        connection.rx_credit_update_fwd_cnt = start;
        stream.rx(
            &VsockHeader {
                op: OP_CREDIT_REQUEST,
                ..opening
            },
            &[],
        );
        assert_eq!(stream.replies[0].header.fwd_cnt, start);
        stream.take_replies_up_to(usize::MAX, usize::MAX);
        stream.consume_upstream(1);
        assert_eq!(stream.replies[0].header.fwd_cnt, u32::MAX);
        assert!(stream.connection.unwrap().is_receive_credit_requested);
        stream.take_replies_up_to(usize::MAX, usize::MAX);
        stream.consume_upstream(2);
        assert_eq!(stream.replies[0].header.fwd_cnt, 1);
        assert!(!stream.connection.unwrap().is_receive_credit_requested);
        stream.take_replies_up_to(usize::MAX, usize::MAX);
        stream.rx(
            &VsockHeader {
                op: OP_RW,
                len: 1,
                ..opening
            },
            b"d",
        );
        stream.consume_upstream(1);
        assert!(stream.replies.is_empty());
        stream.rx(
            &VsockHeader {
                op: OP_CREDIT_REQUEST,
                ..opening
            },
            &[],
        );
        assert_eq!(stream.replies[0].header.fwd_cnt, 2);
        assert!(!stream.connection.unwrap().is_receive_credit_requested);
    }

    #[test]
    fn requested_credit_flush_failure_retires_demand_before_port_reuse() {
        for consume_after_request in [false, true] {
            let (mut stream, opening) = credit_test_stream(UDP_VSOCK_PORT);
            stream.rx(
                &VsockHeader {
                    op: OP_RW,
                    len: 3,
                    ..opening
                },
                b"abc",
            );
            let request = VsockHeader {
                op: OP_CREDIT_REQUEST,
                ..opening
            };
            if consume_after_request {
                stream.rx(&request, &[]);
                stream.take_replies_up_to(usize::MAX, usize::MAX);
            }
            for _ in 0..MAX_QUEUED_REPLIES {
                assert!(stream.rst(opening.src_port, opening.dst_port));
            }
            if consume_after_request {
                stream.consume_upstream(1);
            } else {
                stream.rx(&request, &[]);
            }
            assert!(stream.connection.is_none());
            assert!(stream.upstream.is_empty());
            assert_eq!(stream.replies.len(), MAX_QUEUED_REPLIES);
            stream.take_replies_up_to(usize::MAX, usize::MAX);
            stream.rx(&opening, &[]);
            assert!(!stream.connection.unwrap().is_receive_credit_requested);
        }
    }

    /// A discarded data header cannot count as standalone credit already queued.
    /// The next half-window update restores unidirectional progress without a request.
    #[test]
    fn discarded_piggyback_keeps_unidirectional_receive_credit_progress() {
        let (mut stream, opening) = credit_test_stream(UDP_VSOCK_PORT);
        stream.rx(
            &VsockHeader {
                op: OP_RW,
                len: 8,
                ..opening
            },
            b"abcdefgh",
        );
        stream.consume_upstream(3);
        stream.deliver(b"reply".to_vec()).unwrap();
        assert_eq!(stream.replies[0].header.fwd_cnt, 3);
        stream.rx(
            &VsockHeader {
                op: OP_SHUTDOWN,
                flags: 1,
                ..opening
            },
            &[],
        );
        assert!(stream.replies.is_empty());
        stream.consume_upstream(1);
        assert_eq!(stream.replies[0].header.op, OP_CREDIT_UPDATE);
        assert_eq!(stream.replies[0].header.fwd_cnt, 4);
        stream.take_replies_up_to(usize::MAX, usize::MAX);
        stream.rx(
            &VsockHeader {
                op: OP_RW,
                len: 4,
                ..opening
            },
            b"more",
        );
        assert_eq!(stream.upstream.len(), 8);
        stream.consume_upstream(8);
        assert_eq!(stream.replies[0].header.fwd_cnt, 12);
        assert!(stream.connection.is_some());
    }

    #[test]
    fn batched_receive_credit_wrap_preserves_fifo_order() {
        let (mut stream, opening) = credit_test_stream(TCP_VSOCK_PORT);
        stream.rx(
            &VsockHeader {
                op: OP_RW,
                len: 8,
                ..opening
            },
            b"abcdefgh",
        );
        let start = u32::MAX - 1;
        let connection = stream.connection.as_mut().unwrap();
        connection.rx_received = start.wrapping_add(8);
        connection.rx_fwd_cnt = start;
        connection.rx_credit_update_fwd_cnt = start;
        stream.consume_upstream(4);
        stream.deliver(b"reply".to_vec()).unwrap();
        stream.consume_upstream(4);
        let replies = stream.take_replies_up_to(usize::MAX, usize::MAX);
        assert_eq!(
            replies
                .iter()
                .map(|reply| reply.header.op)
                .collect::<Vec<_>>(),
            [OP_CREDIT_UPDATE, OP_RW, OP_CREDIT_UPDATE]
        );
        assert_eq!(
            replies
                .iter()
                .map(|reply| reply.header.fwd_cnt)
                .collect::<Vec<_>>(),
            [2, 2, 6]
        );
        assert_eq!(stream.connection.unwrap().rx_credit_update_fwd_cnt, 6);
    }

    #[test]
    fn smaller_peer_window_and_dynamic_shrink_flush_deferred_receive_credit() {
        let (mut stream, opening) = credit_test_stream(UDP_VSOCK_PORT);
        stream.rx(
            &VsockHeader {
                op: OP_RW,
                len: 3,
                ..opening
            },
            b"abc",
        );
        stream.consume_upstream(3);
        assert!(stream.upstream.is_empty());
        assert!(stream.replies.is_empty());
        stream.rx(
            &VsockHeader {
                op: OP_CREDIT_UPDATE,
                buf_alloc: 2,
                ..opening
            },
            &[],
        );
        assert_eq!(stream.replies.len(), 1);
        assert_eq!(stream.replies[0].header.fwd_cnt, 3);
        assert_eq!(stream.connection.unwrap().rx_credit_update_fwd_cnt, 3);
        stream.take_replies_up_to(usize::MAX, usize::MAX);
        stream.rx(
            &VsockHeader {
                op: OP_RW,
                len: 2,
                buf_alloc: 2,
                ..opening
            },
            b"de",
        );
        stream.consume_upstream(1);
        assert_eq!(stream.replies[0].header.fwd_cnt, 4);
        assert_eq!(stream.connection.unwrap().peer_buf_alloc, 2);
        assert_eq!(stream.upstream.len(), 1);
    }

    #[test]
    fn failed_window_shrink_credit_flush_retires_the_connection() {
        let (mut stream, opening) = credit_test_stream(TCP_VSOCK_PORT);
        stream.rx(
            &VsockHeader {
                op: OP_RW,
                len: 3,
                ..opening
            },
            b"abc",
        );
        stream.consume_upstream(3);
        for _ in 0..MAX_QUEUED_REPLIES {
            assert!(stream.rst(opening.src_port, opening.dst_port));
        }
        stream.rx(
            &VsockHeader {
                op: OP_CREDIT_UPDATE,
                buf_alloc: 2,
                ..opening
            },
            &[],
        );
        assert!(stream.connection.is_none());
        assert!(stream.upstream.is_empty());
        assert_eq!(stream.replies.len(), MAX_QUEUED_REPLIES);
    }

    #[test]
    fn failed_credit_queue_and_empty_delivery_do_not_advance_advertised_credit() {
        let (mut stream, opening) = credit_test_stream(TCP_VSOCK_PORT);
        stream.rx(
            &VsockHeader {
                op: OP_RW,
                len: 8,
                ..opening
            },
            b"abcdefgh",
        );
        stream.consume_upstream(3);
        stream.deliver(b"".to_vec()).unwrap();
        assert!(stream.replies.is_empty());
        for _ in 0..MAX_QUEUED_REPLIES {
            assert!(stream.rst(opening.src_port, opening.dst_port));
        }
        let snapshot = stream.connection.unwrap();
        assert!(!stream.respond(&snapshot, OP_CREDIT_UPDATE, 0));
        assert_eq!(stream.connection.unwrap().rx_credit_update_fwd_cnt, 0);
        stream.consume_upstream(1);
        assert!(stream.connection.is_none());
        assert!(stream.upstream.is_empty());
        assert_eq!(stream.replies.len(), MAX_QUEUED_REPLIES);
    }

    #[test]
    fn upstream_byte_fifo_preserves_fragment_order_capacity_and_overflow_isolation() {
        let mut switch = VsockSwitch::new();
        let request = VsockHeader {
            src_cid: GUEST_CID,
            dst_cid: HOST_CID,
            src_port: 12345,
            dst_port: TCP_VSOCK_PORT,
            len: 0,
            type_: TYPE_STREAM,
            op: OP_REQUEST,
            flags: 0,
            buf_alloc: FLOW_RX_ALLOC,
            fwd_cnt: 0,
        };
        let other = VsockHeader {
            src_port: 12346,
            ..request
        };
        switch.rx(&request, &[]);
        switch.rx(&other, &[]);
        let connection = switch
            .connection_for(request.src_port, request.dst_port)
            .unwrap();
        let unaffected = switch
            .connection_for(other.src_port, other.dst_port)
            .unwrap();
        let index = switch.connection_index(connection).unwrap();
        let capacity = switch.endpoints[index].stream.upstream.capacity();
        assert_eq!(capacity, FLOW_RX_ALLOC as usize);
        switch.take_replies();
        switch.consume_upstream(connection, 0).unwrap();
        switch.consume_upstream(connection, usize::MAX).unwrap();
        assert_eq!(switch.take_replies(), []);
        switch.rx(
            &VsockHeader {
                op: OP_RW,
                len: 5,
                ..other
            },
            b"other",
        );
        let data = VsockHeader {
            op: OP_RW,
            len: FLOW_RX_ALLOC - 129,
            ..request
        };
        switch.rx(&data, &vec![b'a'; capacity - 129]);
        let tiny = VsockHeader { len: 1, ..data };
        for byte in 0_u8..=128 {
            switch.rx(&tiny, &[byte]);
        }
        assert_eq!(switch.endpoints[index].stream.upstream.len(), capacity);
        assert_eq!(switch.endpoints[index].stream.upstream.capacity(), capacity);
        let consumed = capacity - 64;
        switch.consume_upstream(connection, consumed).unwrap();
        assert_eq!(switch.take_replies()[0].header.fwd_cnt, FLOW_RX_ALLOC - 64);
        switch.rx(
            &VsockHeader {
                len: FLOW_RX_ALLOC - 64,
                ..data
            },
            &vec![b'z'; consumed],
        );
        assert_ne!(switch.endpoints[index].stream.upstream.as_slices().1, b"");
        assert_eq!(switch.endpoints[index].stream.upstream.capacity(), capacity);
        assert_eq!(
            switch.peek_upstream(connection, usize::MAX),
            (65_u8..=128)
                .chain(std::iter::repeat_n(b'z', consumed))
                .collect::<Vec<_>>()
        );
        switch.rx(&tiny, b"x");
        assert!(
            switch
                .connection_for(request.src_port, request.dst_port)
                .is_none()
        );
        assert_eq!(
            switch.consume_upstream(connection, 1),
            Err(VsockError::UnknownConnection)
        );
        assert!(switch.endpoints[index].stream.upstream.is_empty());
        assert_eq!(switch.endpoints[index].stream.upstream.capacity(), capacity);
        assert_eq!(
            switch.connection_for(other.src_port, other.dst_port),
            Some(unaffected)
        );
        assert_eq!(switch.peek_upstream(unaffected, usize::MAX), b"other");
    }
}
