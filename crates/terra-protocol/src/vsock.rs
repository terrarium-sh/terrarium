//! Fixed endpoint classes and device queue payload budgets.

pub const VERSION: u16 = 1;
pub const HOST_CID: u32 = 2;
pub const GUEST_CID: u32 = 3;
pub const AGENT_PORT: u32 = 6000;
pub const CONTROL_PORT: u32 = 6001;
pub const TCP_PORT: u32 = 6002;
pub const UDP_PORT: u32 = 6003;
/// Guest listening port for frontend-initiated publication streams.
pub const PUBLICATION_PORT: u32 = 6004;
/// Host source ports for publication streams; the frontend never opens any other host port.
pub const PUBLICATION_HOST_PORTS: std::ops::Range<u32> = 0x0010_0000..0x0020_0000;
pub const MAX_NETWORK_SOCKETS: usize = 1024;
pub const AGENT_UPSTREAM_BYTES: usize = 64 * 1024;
pub const AGENT_REPLY_BYTES: usize = 256 * 1024;
pub const CONTROL_UPSTREAM_BYTES: usize = 32 * 1024;
pub const CONTROL_REPLY_BYTES: usize = 128 * 1024;
pub const FLOW_UPSTREAM_BYTES: usize = 48 * 1024;
pub const FLOW_REPLY_BYTES: usize = 80 * 1024;
pub const MAX_FLOW_UPSTREAM_BYTES: usize = MAX_NETWORK_SOCKETS * FLOW_UPSTREAM_BYTES;
pub const MAX_FLOW_REPLY_BYTES: usize = MAX_NETWORK_SOCKETS * FLOW_REPLY_BYTES;
pub const MAX_QUEUED_UPSTREAM_BYTES: usize =
    AGENT_UPSTREAM_BYTES + CONTROL_UPSTREAM_BYTES + MAX_FLOW_UPSTREAM_BYTES;
pub const MAX_QUEUED_REPLY_BYTES: usize =
    AGENT_REPLY_BYTES + CONTROL_REPLY_BYTES + MAX_FLOW_REPLY_BYTES;

/// Guest source ports a per-socket TCP or UDP stream may use.
#[must_use]
pub const fn is_flow_guest_port(port: u32) -> bool {
    port != 0 && port != AGENT_PORT && port != CONTROL_PORT && port != PUBLICATION_PORT
}

const _: () = assert!(MAX_FLOW_UPSTREAM_BYTES + MAX_FLOW_REPLY_BYTES == 128 * 1024 * 1024);
const _: () = assert!(crate::application::MAX_FRAME_BYTES <= FLOW_UPSTREAM_BYTES);
const _: () = assert!(crate::application::MAX_FRAME_BYTES <= FLOW_REPLY_BYTES);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flow_ports_exclude_reserved_endpoints_and_budgets_sum_agent_control_and_flows() {
        for port in [0, AGENT_PORT, CONTROL_PORT, PUBLICATION_PORT] {
            assert!(!is_flow_guest_port(port));
        }
        for port in [1, TCP_PORT, UDP_PORT, u32::MAX] {
            assert!(is_flow_guest_port(port));
        }
        for port in [AGENT_PORT, CONTROL_PORT, TCP_PORT, UDP_PORT] {
            assert!(!PUBLICATION_HOST_PORTS.contains(&port));
        }
        assert_eq!(MAX_QUEUED_UPSTREAM_BYTES, 49248 * 1024);
        assert_eq!(MAX_QUEUED_REPLY_BYTES, 82304 * 1024);
    }
}
