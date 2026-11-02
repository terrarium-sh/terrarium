//! Fixed endpoint classes and device queue payload budgets.

pub const HOST_CID: u32 = 2;
pub const GUEST_CID: u32 = 3;
pub const AGENT_PORT: u32 = 6000;
pub const CONTROL_PORT: u32 = 6001;
pub const TCP_PORT: u32 = 6002;
pub const UDP_PORT: u32 = 6003;
/// Guest listening port for frontend-initiated publication streams.
pub const PUBLICATION_PORT: u32 = 6004;
/// Host source ports for publication streams, the only host ports the frontend opens.
pub const PUBLICATION_HOST_PORTS: std::ops::Range<u32> = 0x0010_0000..0x0020_0000;
pub const MAX_NETWORK_SOCKETS: usize = 1024;
/// The largest payload of one vsock packet.
pub const MAX_PACKET_DATA_BYTES: u32 = 64 * 1024;
pub const AGENT_UPSTREAM_BYTES: u32 = 64 * 1024;
pub const AGENT_REPLY_BYTES: u32 = 256 * 1024;
pub const CONTROL_UPSTREAM_BYTES: u32 = 32 * 1024;
pub const CONTROL_REPLY_BYTES: u32 = 128 * 1024;
pub const FLOW_UPSTREAM_BYTES: u32 = 64 * 1024;
pub const FLOW_REPLY_BYTES: u32 = 80 * 1024;
pub const MAX_FLOW_UPSTREAM_BYTES: usize = MAX_NETWORK_SOCKETS * FLOW_UPSTREAM_BYTES as usize;
pub const MAX_FLOW_REPLY_BYTES: usize = MAX_NETWORK_SOCKETS * FLOW_REPLY_BYTES as usize;
pub const MAX_QUEUED_REPLY_BYTES: usize =
    AGENT_REPLY_BYTES as usize + CONTROL_REPLY_BYTES as usize + MAX_FLOW_REPLY_BYTES;

/// Guest source ports a per-socket TCP or UDP stream may use.
#[must_use]
pub const fn is_flow_guest_port(port: u32) -> bool {
    port != 0 && port != AGENT_PORT && port != CONTROL_PORT && port != PUBLICATION_PORT
}

const _: () = {
    assert!(is_flow_guest_port(TCP_PORT) && is_flow_guest_port(UDP_PORT));
    let fixed_ports = [
        AGENT_PORT,
        CONTROL_PORT,
        TCP_PORT,
        UDP_PORT,
        PUBLICATION_PORT,
    ];
    let mut index = 0;
    while index < fixed_ports.len() {
        assert!(fixed_ports[index] >= AGENT_PORT && fixed_ports[index] <= PUBLICATION_PORT);
        assert!(fixed_ports[index] < PUBLICATION_HOST_PORTS.start);
        index += 1;
    }
};
