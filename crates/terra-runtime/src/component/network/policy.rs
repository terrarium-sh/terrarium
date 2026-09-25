//! Egress authorization and DNS policy contracts for native socket adapters.

use std::{future::Future, net::IpAddr, pin::Pin, sync::Arc};

pub type DecisionLease = Box<dyn Send>;

pub type DecisionFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// Retain the lease with accepted work until completion, including after caller cancellation.
pub trait AsyncPolicy: Send + Sync {
    fn allows(&self, ip: IpAddr, port: Option<u16>, lease: DecisionLease) -> DecisionFuture<bool>;
    fn lookup_name(&self, name: String, lease: DecisionLease) -> DecisionFuture<NameLookup>;
    fn accept_resolved(
        &self,
        name: String,
        addresses: Vec<IpAddr>,
        lease: DecisionLease,
    ) -> DecisionFuture<Vec<IpAddr>>;
}

/// The result a policy permits for one standard name lookup.
pub enum NameLookup {
    Static(Vec<IpAddr>),
    /// The hostname to resolve; implementations must validate and normalize it.
    Resolve(String),
    Denied,
}

/// Native egress decisions; implementations must avoid blocking host I/O.
pub trait Policy: Send + Sync {
    /// Opt into nonblocking decisions and metadata checks; `None` keeps synchronous calls isolated.
    fn asynchronous(self: Arc<Self>) -> Option<Arc<dyn AsyncPolicy>> {
        None
    }

    fn is_available(&self) -> bool {
        true
    }

    /// Whether an outbound flow to `ip` may be opened, decided before any host
    /// socket exists. `port` is `None` for a portless flow (an ICMP echo),
    /// which only an any-port rule covers.
    fn allows(&self, ip: IpAddr, port: Option<u16>) -> bool;

    /// Ports on the virtual gateway that are backed by host loopback services.
    /// `None` grants every port.
    fn host_service_ports(&self) -> &[Option<u16>] {
        &[]
    }

    fn lookup_name(&self, _name: &str) -> NameLookup {
        NameLookup::Denied
    }

    /// Filters resolver results and records the addresses that may later be
    /// used by an authorized socket operation.
    fn accept_resolved(&self, _name: &str, _addresses: &[IpAddr]) -> Vec<IpAddr> {
        Vec::new()
    }

    /// Whether direct connections to DNS ports would bypass name grants.
    fn blocks_direct_dns(&self) -> bool {
        false
    }
}

pub type PolicyHandle = Arc<dyn Policy>;

#[cfg(test)]
mod tests {
    use super::*;

    /// The least a policy can implement.
    struct AllowAll;

    impl Policy for AllowAll {
        fn allows(&self, _ip: IpAddr, _port: Option<u16>) -> bool {
            true
        }
    }

    /// Saying nothing must not opt a policy into resolving names.
    #[test]
    fn the_defaults_add_nothing_a_policy_did_not_ask_for() {
        let p: &dyn Policy = &AllowAll;
        assert!(matches!(p.lookup_name("example.test"), NameLookup::Denied));
        assert!(p.accept_resolved("example.test", &[]).is_empty());
        assert!(!p.blocks_direct_dns());
    }

    /// Every hook, through the handle the gateway holds — so this covers the
    /// dynamic dispatch too.
    #[test]
    fn a_custom_policy_answers_every_hook_through_the_handle() {
        struct Custom;

        const STANDIN: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1));

        impl Policy for Custom {
            fn allows(&self, ip: IpAddr, port: Option<u16>) -> bool {
                ip == STANDIN && port == Some(5432)
            }

            fn lookup_name(&self, name: &str) -> NameLookup {
                if name == "db.test" {
                    NameLookup::Static(vec![STANDIN])
                } else {
                    NameLookup::Denied
                }
            }

            fn accept_resolved(&self, name: &str, addresses: &[IpAddr]) -> Vec<IpAddr> {
                if name == "api.test" {
                    addresses.to_vec()
                } else {
                    Vec::new()
                }
            }

            fn blocks_direct_dns(&self) -> bool {
                true
            }
        }

        let egress: PolicyHandle = Arc::new(Custom);
        let other: IpAddr = "1.1.1.1".parse().unwrap();

        assert!(egress.allows(STANDIN, Some(5432)));
        assert!(!egress.allows(STANDIN, Some(22)));
        assert!(!egress.allows(STANDIN, None));
        assert!(!egress.allows(other, Some(5432)));

        assert!(matches!(egress.lookup_name("db.test"), NameLookup::Static(b) if b == [STANDIN]));
        assert_eq!(egress.accept_resolved("api.test", &[other]), [other]);
        assert!(egress.blocks_direct_dns());

        // Cloning shares the policy rather than copying it.
        let cloned = egress.clone();
        assert!(cloned.allows(STANDIN, Some(5432)));
        assert_eq!(Arc::strong_count(&egress), 2);
    }
}
