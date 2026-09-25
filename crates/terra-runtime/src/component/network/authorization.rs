//! Native authorization for a network component's WASI sockets.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use super::{AsyncPolicy, DecisionFuture, NameLookup, Policy, PolicyHandle, PortMapping};
use futures_util::FutureExt;
use std::panic::AssertUnwindSafe;
use tokio::sync::Semaphore;
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, sockets::SocketAddrUse};

pub(crate) const MAX_POLICY_CALLS: usize = 8;

enum Backend {
    Async {
        metadata: PolicyHandle,
        decisions: Arc<dyn AsyncPolicy>,
    },
    Blocking(PolicyHandle),
}

#[derive(Clone)]
pub(crate) struct PolicyClient {
    backend: Arc<Backend>,
    calls: Arc<Semaphore>,
}

impl PolicyClient {
    pub(crate) fn new(policy: PolicyHandle, calls: Arc<Semaphore>) -> Self {
        let backend = match Arc::clone(&policy).asynchronous() {
            Some(decisions) => Backend::Async {
                metadata: policy,
                decisions,
            },
            None => Backend::Blocking(policy),
        };
        Self {
            backend: Arc::new(backend),
            calls,
        }
    }

    async fn authorize_socket(
        &self,
        host_service_ports: Arc<[Option<u16>]>,
        published_ports: Arc<[PortMapping]>,
        address: SocketAddr,
        purpose: SocketAddrUse,
    ) -> bool {
        let Ok(permit) = Arc::clone(&self.calls).try_acquire_owned() else {
            return false;
        };
        match self.backend.as_ref() {
            Backend::Async {
                metadata,
                decisions,
            } => {
                match authorize_socket_grants(
                    metadata.as_ref(),
                    &host_service_ports,
                    &published_ports,
                    address,
                    purpose,
                ) {
                    Some(allowed) => allowed,
                    None => {
                        // WASI socket checks require a Sync future; policy futures only require Send.
                        receive_decision(decisions.allows(
                            address.ip(),
                            Some(address.port()),
                            Box::new(permit),
                        ))
                        .map(|allowed| allowed.unwrap_or(false))
                        .shared()
                        .await
                    }
                }
            }
            Backend::Blocking(policy) => {
                let policy = Arc::clone(policy);
                tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    authorize_socket(
                        policy.as_ref(),
                        &host_service_ports,
                        &published_ports,
                        address,
                        purpose,
                    )
                })
                .await
                .unwrap_or(false)
            }
        }
    }

    pub(crate) async fn lookup_name(&self, name: String) -> Option<NameLookup> {
        let permit = Arc::clone(&self.calls).try_acquire_owned().ok()?;
        match self.backend.as_ref() {
            Backend::Async { decisions, .. } => {
                receive_decision(decisions.lookup_name(name, Box::new(permit))).await
            }
            Backend::Blocking(policy) => {
                let policy = Arc::clone(policy);
                tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    policy.lookup_name(&name)
                })
                .await
                .ok()
            }
        }
    }

    pub(crate) async fn accept_resolved(
        &self,
        name: String,
        addresses: Vec<IpAddr>,
    ) -> Option<Vec<IpAddr>> {
        let permit = Arc::clone(&self.calls).try_acquire_owned().ok()?;
        match self.backend.as_ref() {
            Backend::Async { decisions, .. } => {
                receive_decision(decisions.accept_resolved(name, addresses, Box::new(permit))).await
            }
            Backend::Blocking(policy) => {
                let policy = Arc::clone(policy);
                tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    policy.accept_resolved(&name, &addresses)
                })
                .await
                .ok()
            }
        }
    }
}

async fn receive_decision<T>(response: DecisionFuture<T>) -> Option<T> {
    AssertUnwindSafe(response).catch_unwind().await.ok()
}

pub(super) fn build_network_context(
    policy: PolicyClient,
    host_service_ports: Vec<Option<u16>>,
    published_ports: Vec<PortMapping>,
) -> WasiCtx {
    let host_service_ports: Arc<[Option<u16>]> = Arc::from(host_service_ports);
    let published_ports: Arc<[PortMapping]> = Arc::from(published_ports);
    WasiCtxBuilder::new()
        .max_random_size(crate::MAX_SINGLE_BYTES)
        .allow_tcp(true)
        .allow_udp(true)
        .allow_ip_name_lookup(true)
        .socket_addr_check(move |address, purpose| {
            let policy = policy.clone();
            let host_service_ports = host_service_ports.clone();
            let published_ports = published_ports.clone();
            Box::pin(async move {
                policy
                    .authorize_socket(host_service_ports, published_ports, address, purpose)
                    .await
            })
        })
        .build()
}

fn authorize_socket(
    policy: &dyn Policy,
    host_service_ports: &[Option<u16>],
    published_ports: &[PortMapping],
    address: SocketAddr,
    purpose: SocketAddrUse,
) -> bool {
    authorize_socket_grants(
        policy,
        host_service_ports,
        published_ports,
        address,
        purpose,
    )
    .unwrap_or_else(|| policy.allows(address.ip(), Some(address.port())))
}

/// `None` requires an egress decision from the policy worker.
fn authorize_socket_grants(
    policy: &dyn Policy,
    host_service_ports: &[Option<u16>],
    published_ports: &[PortMapping],
    address: SocketAddr,
    purpose: SocketAddrUse,
) -> Option<bool> {
    if !policy.is_available() {
        return Some(false);
    }
    Some(match purpose {
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
            if address.port() == 53 && policy.blocks_direct_dns() {
                false
            } else if host_service {
                true
            } else {
                return None;
            }
        }
    })
}

fn is_host_loopback(ip: IpAddr) -> bool {
    ip == IpAddr::V4(Ipv4Addr::LOCALHOST) || ip == IpAddr::V6(Ipv6Addr::LOCALHOST)
}

#[cfg(test)]
mod tests {
    use super::super::{DecisionLease, GuestNetworkConfig};
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
        let gateway = GuestNetworkConfig::default().gateway_ip;
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

    struct AsyncProbe;

    impl Policy for AsyncProbe {
        fn asynchronous(self: Arc<Self>) -> Option<Arc<dyn AsyncPolicy>> {
            Some(self)
        }
        fn allows(&self, _: IpAddr, _: Option<u16>) -> bool {
            panic!("synchronous fallback")
        }
    }

    impl AsyncPolicy for AsyncProbe {
        fn allows(&self, _: IpAddr, _: Option<u16>, lease: DecisionLease) -> DecisionFuture<bool> {
            Box::pin(async move {
                let _lease = lease;
                let visited = std::cell::Cell::new(false);
                tokio::task::yield_now().await;
                visited.set(true);
                visited.get()
            })
        }
        fn lookup_name(&self, _: String, lease: DecisionLease) -> DecisionFuture<NameLookup> {
            Box::pin(async move {
                let _lease = lease;
                panic!("lookup failed")
            })
        }
        fn accept_resolved(
            &self,
            _: String,
            _: Vec<IpAddr>,
            lease: DecisionLease,
        ) -> DecisionFuture<Vec<IpAddr>> {
            Box::pin(async move {
                let _lease = lease;
                panic!("resolution failed")
            })
        }
    }

    #[tokio::test]
    async fn custom_async_policies_support_send_futures_and_fail_closed_on_panic() {
        let calls = Arc::new(Semaphore::new(1));
        let client = PolicyClient::new(Arc::new(AsyncProbe), calls.clone());
        assert!(
            client
                .authorize_socket(
                    Arc::default(),
                    Arc::default(),
                    SocketAddr::from(([192, 0, 2, 1], 443)),
                    SocketAddrUse::TcpConnect
                )
                .await
        );
        assert!(client.lookup_name("test".into()).await.is_none());
        assert!(
            client
                .accept_resolved("test".into(), vec![])
                .await
                .is_none()
        );
        assert_eq!(calls.available_permits(), 1);
    }

    #[tokio::test]
    async fn cancelled_synchronous_policy_waiters_retain_admission() {
        struct BlockedLookup {
            entered: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
            release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
        }
        impl Policy for BlockedLookup {
            fn allows(&self, _: IpAddr, _: Option<u16>) -> bool {
                false
            }
            fn lookup_name(&self, _: &str) -> NameLookup {
                self.entered
                    .lock()
                    .unwrap()
                    .take()
                    .unwrap()
                    .send(())
                    .unwrap();
                self.release
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(2))
                    .unwrap();
                NameLookup::Denied
            }
        }
        let (entered, started) = tokio::sync::oneshot::channel();
        let (release, blocked) = std::sync::mpsc::channel();
        let calls = Arc::new(Semaphore::new(1));
        let client = PolicyClient::new(
            Arc::new(BlockedLookup {
                entered: std::sync::Mutex::new(Some(entered)),
                release: std::sync::Mutex::new(blocked),
            }),
            calls.clone(),
        );
        {
            let response = client.lookup_name("blocked.test".into());
            tokio::pin!(response);
            tokio::select! {
                result = &mut response => panic!("unexpected response: {}", result.is_some()),
                result = started => result.unwrap(),
            }
        }
        assert_eq!(calls.available_permits(), 0);
        assert!(client.lookup_name("another.test".into()).await.is_none());
        drop(client);
        release.send(()).unwrap();
        let _permit = tokio::time::timeout(Duration::from_secs(1), calls.acquire())
            .await
            .unwrap()
            .unwrap();
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
                PolicyClient::new(policy, Arc::new(Semaphore::new(1))).authorize_socket(
                    Arc::default(),
                    Arc::default(),
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
            !PolicyClient::new(Arc::new(Restricted), Arc::new(Semaphore::new(0)))
                .authorize_socket(
                    Arc::default(),
                    Arc::default(),
                    SocketAddr::from(([192, 0, 2, 1], 443)),
                    SocketAddrUse::TcpConnect,
                )
                .await
        );
    }
}
