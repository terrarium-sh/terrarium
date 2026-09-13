//! Native authorization for a network component's WASI sockets.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use terra_network::{Policy, PolicyHandle, PortMapping};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, sockets::SocketAddrUse};

pub fn build_network_context(
    policy: PolicyHandle,
    policy_calls: Arc<tokio::sync::Semaphore>,
    host_service_ports: Vec<Option<u16>>,
    published_ports: Vec<PortMapping>,
) -> WasiCtx {
    WasiCtxBuilder::new()
        .max_random_size(crate::MAX_SINGLE_BYTES)
        .allow_tcp(true)
        .allow_udp(true)
        .allow_ip_name_lookup(true)
        .socket_addr_check(move |address, purpose| {
            let policy = Arc::clone(&policy);
            let policy_calls = Arc::clone(&policy_calls);
            let host_service_ports = host_service_ports.clone();
            let published_ports = published_ports.clone();
            Box::pin(authorize_socket_async(
                policy,
                policy_calls,
                host_service_ports,
                published_ports,
                address,
                purpose,
            ))
        })
        .build()
}

async fn authorize_socket_async(
    policy: PolicyHandle,
    policy_calls: Arc<tokio::sync::Semaphore>,
    host_service_ports: Vec<Option<u16>>,
    published_ports: Vec<PortMapping>,
    address: SocketAddr,
    purpose: SocketAddrUse,
) -> bool {
    crate::component::policy::run_policy_decision(policy, policy_calls, move |policy| {
        authorize_socket(
            policy,
            &host_service_ports,
            &published_ports,
            address,
            purpose,
        )
    })
    .await
    .unwrap_or(false)
}

fn authorize_socket(
    policy: &dyn Policy,
    host_service_ports: &[Option<u16>],
    published_ports: &[PortMapping],
    address: SocketAddr,
    purpose: SocketAddrUse,
) -> bool {
    if !policy.is_available() {
        return false;
    }
    match purpose {
        SocketAddrUse::UdpBind => address.ip().is_unspecified() && address.port() == 0,
        SocketAddrUse::TcpBind => {
            (address.ip().is_unspecified() && address.port() == 0)
                || (is_host_loopback(address.ip())
                    && published_ports
                        .iter()
                        .any(|mapping| mapping.host == address.port()))
        }
        SocketAddrUse::TcpListen => {
            is_host_loopback(address.ip())
                && published_ports
                    .iter()
                    .any(|mapping| mapping.host == address.port())
        }
        SocketAddrUse::TcpAccept => address.ip().is_loopback(),
        SocketAddrUse::TcpConnect | SocketAddrUse::UdpSend | SocketAddrUse::UdpReceive => {
            let host_service = is_host_loopback(address.ip())
                && host_service_ports
                    .iter()
                    .any(|port| port.is_none_or(|port| port == address.port()));
            !(address.port() == 53 && policy.blocks_direct_dns())
                && (host_service || policy.allows(address.ip(), Some(address.port())))
        }
    }
}

fn is_host_loopback(ip: IpAddr) -> bool {
    ip == IpAddr::V4(Ipv4Addr::LOCALHOST) || ip == IpAddr::V6(Ipv6Addr::LOCALHOST)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        net::{IpAddr, Ipv4Addr},
        thread,
        time::Duration,
    };

    struct Restricted;

    impl Policy for Restricted {
        fn allows(&self, ip: IpAddr, port: Option<u16>) -> bool {
            ip == Ipv4Addr::new(192, 0, 2, 1) && matches!(port, Some(443 | 53))
        }

        fn blocks_direct_dns(&self) -> bool {
            true
        }
    }

    #[test]
    fn unavailable_policy_denies_even_cached_loopback_and_listener_grants() {
        struct Unavailable;
        impl Policy for Unavailable {
            fn is_available(&self) -> bool {
                false
            }
            fn allows(&self, _: IpAddr, _: Option<u16>) -> bool {
                true
            }
        }
        for purpose in [
            SocketAddrUse::TcpConnect,
            SocketAddrUse::TcpBind,
            SocketAddrUse::TcpListen,
            SocketAddrUse::TcpAccept,
        ] {
            assert!(!authorize_socket(
                &Unavailable,
                &[Some(5432)],
                &[PortMapping::new(5432, 5432)],
                SocketAddr::from(([127, 0, 0, 1], 5432)),
                purpose
            ));
        }
    }

    #[test]
    fn sockets_cannot_bypass_port_policy_dns_or_open_listeners() {
        let allowed = SocketAddr::from(([192, 0, 2, 1], 443));
        for purpose in [
            SocketAddrUse::TcpConnect,
            SocketAddrUse::UdpSend,
            SocketAddrUse::UdpReceive,
        ] {
            assert!(authorize_socket(&Restricted, &[], &[], allowed, purpose));
            assert!(!authorize_socket(
                &Restricted,
                &[],
                &[],
                SocketAddr::from(([192, 0, 2, 1], 53)),
                purpose
            ));
            assert!(!authorize_socket(
                &Restricted,
                &[],
                &[],
                SocketAddr::from(([127, 0, 0, 1], 443)),
                purpose
            ));
        }
        assert!(authorize_socket(
            &Restricted,
            &[],
            &[],
            SocketAddr::from(([0, 0, 0, 0], 0)),
            SocketAddrUse::UdpBind
        ));
        assert!(authorize_socket(
            &Restricted,
            &[],
            &[],
            SocketAddr::from(([0, 0, 0, 0], 0)),
            SocketAddrUse::TcpBind
        ));
        for purpose in [SocketAddrUse::TcpBind, SocketAddrUse::UdpBind] {
            assert!(!authorize_socket(&Restricted, &[], &[], allowed, purpose));
        }
        assert!(!authorize_socket(
            &Restricted,
            &[],
            &[],
            allowed,
            SocketAddrUse::TcpListen
        ));
        assert!(!authorize_socket(
            &Restricted,
            &[],
            &[],
            allowed,
            SocketAddrUse::TcpAccept
        ));
    }

    #[test]
    fn host_service_grant_only_opens_its_loopback_port() {
        assert!(authorize_socket(
            &Restricted,
            &[Some(5432)],
            &[],
            SocketAddr::from(([127, 0, 0, 1], 5432)),
            SocketAddrUse::TcpConnect,
        ));
        assert!(!authorize_socket(
            &Restricted,
            &[Some(5432)],
            &[],
            SocketAddr::from(([127, 0, 0, 1], 22)),
            SocketAddrUse::TcpConnect,
        ));
        let gateway = terra_network::GuestNetworkConfig::default().gateway_ip;
        assert!(!authorize_socket(
            &Restricted,
            &[Some(5432)],
            &[],
            SocketAddr::from((gateway, 5432)),
            SocketAddrUse::TcpConnect,
        ));
    }

    #[test]
    fn published_port_grant_only_opens_its_listener() {
        let mapping = PortMapping::new(8080, 80);
        for purpose in [SocketAddrUse::TcpBind, SocketAddrUse::TcpListen] {
            assert!(authorize_socket(
                &Restricted,
                &[],
                &[mapping],
                SocketAddr::from(([127, 0, 0, 1], 8080)),
                purpose,
            ));
            assert!(!authorize_socket(
                &Restricted,
                &[],
                &[mapping],
                SocketAddr::from(([127, 0, 0, 1], 8081)),
                purpose,
            ));
        }
        assert!(authorize_socket(
            &Restricted,
            &[],
            &[mapping],
            SocketAddr::from(([127, 0, 0, 1], 12345)),
            SocketAddrUse::TcpAccept,
        ));
        for purpose in [
            SocketAddrUse::TcpBind,
            SocketAddrUse::TcpListen,
            SocketAddrUse::TcpConnect,
        ] {
            assert!(!authorize_socket(
                &Restricted,
                &[Some(8080)],
                &[mapping],
                SocketAddr::from(([127, 0, 0, 2], 8080)),
                purpose,
            ));
        }
    }

    struct Slow;

    impl Policy for Slow {
        fn allows(&self, _: IpAddr, _: Option<u16>) -> bool {
            thread::sleep(Duration::from_millis(50));
            false
        }
    }

    #[tokio::test]
    async fn socket_policy_callback_does_not_block_the_event_loop() {
        let policy: PolicyHandle = Arc::new(Slow);
        assert!(
            tokio::time::timeout(
                Duration::from_millis(10),
                authorize_socket_async(
                    policy,
                    Arc::new(tokio::sync::Semaphore::new(1)),
                    Vec::new(),
                    Vec::new(),
                    SocketAddr::from(([192, 0, 2, 1], 443)),
                    SocketAddrUse::TcpConnect,
                ),
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn saturated_socket_policy_callback_denies() {
        assert!(
            !authorize_socket_async(
                Arc::new(Restricted),
                Arc::new(tokio::sync::Semaphore::new(0)),
                Vec::new(),
                Vec::new(),
                SocketAddr::from(([192, 0, 2, 1], 443)),
                SocketAddrUse::TcpConnect,
            )
            .await
        );
    }
}
