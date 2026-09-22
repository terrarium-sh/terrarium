//! WIT adapter for an isolated network policy sidecar.

use futures_util::FutureExt;
use std::net::IpAddr;
use std::sync::{Arc, mpsc};
use terra_network::{NameLookup, Policy as NetworkPolicy};
use wasmtime::component::Component;
use wasmtime::{Engine, Store, StoreLimits, StoreLimitsBuilder};
use wasmtime_wasi::{ResourceTable, WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

wasmtime::component::bindgen!({
    path: "../../components/policy/wit",
    world: "policy",
    exports: { default: async },
});
use exports::terra::policy::decisions::Lookup;
pub use exports::terra::policy::decisions::{Config, HostRecord, Mode};

const CALL_FUEL: u64 = 5_000_000;
const MAX_CONFIG_BYTES: usize = 64 * 1024;
const MAX_ADDRESSES: usize = 4096;
pub(crate) const MAX_NAME_BYTES: usize = 254;

struct Host {
    ctx: WasiCtx,
    table: ResourceTable,
    limits: StoreLimits,
}

impl WasiView for Host {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.ctx,
            table: &mut self.table,
        }
    }
}

pub struct PolicyFactory {
    engine: Engine,
    component: Component,
}

impl PolicyFactory {
    pub fn from_trusted_artifact(artifact: crate::TrustedArtifact) -> wasmtime::Result<Self> {
        let engine = crate::engine::policy_engine()?;
        let component = artifact.deserialize(&engine)?;
        Ok(Self { engine, component })
    }

    pub fn instantiate(
        &self,
        config: &Config,
        memory_bytes: usize,
    ) -> wasmtime::Result<ComponentPolicy> {
        let bytes = config
            .allow
            .iter()
            .map(String::len)
            .chain(
                config
                    .hosts
                    .iter()
                    .map(|record| record.name.len().saturating_add(record.addr.len())),
            )
            .chain(config.host_addresses.iter().map(String::len))
            .try_fold(0usize, usize::checked_add);
        if config.allow.len() > MAX_ADDRESSES
            || config.hosts.len() > MAX_ADDRESSES
            || config.host_addresses.len() > MAX_ADDRESSES
            || bytes.is_none_or(|bytes| bytes > MAX_CONFIG_BYTES)
        {
            return Err(wasmtime::Error::msg(
                "network policy exceeds 4096 rules or 64 KiB; reduce network.allow and network.hosts",
            ));
        }
        let host = Host {
            ctx: WasiCtxBuilder::new()
                .allow_tcp(false)
                .allow_udp(false)
                .allow_ip_name_lookup(false)
                .build(),
            table: ResourceTable::new(),
            limits: StoreLimitsBuilder::new()
                .memory_size(memory_bytes)
                .memories(1)
                .instances(16)
                .tables(8)
                .table_elements(1024)
                .build(),
        };
        let mut store = Store::new(&self.engine, host);
        store.limiter(|host| &mut host.limits);
        store.set_epoch_deadline(u64::MAX);
        store.set_fuel(CALL_FUEL)?;
        let mut linker = crate::component::context::device_component_linker(&self.engine)?;
        crate::component::clocks::add_monotonic_now(&mut linker)?;
        let bindings = complete_decision(Policy::instantiate_async(
            &mut store,
            &self.component,
            &linker,
        ))?;
        let grants = complete_decision(
            bindings
                .terra_policy_decisions()
                .call_configure(&mut store, config),
        )?
        .map_err(wasmtime::Error::msg)?;
        let (sender, receiver) =
            mpsc::sync_channel::<Decision>(crate::component::network::MAX_POLICY_CALLS);
        let available = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let worker = std::thread::Builder::new()
            .name("network-policy".into())
            .spawn(move || {
                let mut state = State { store, bindings };
                while let Ok(decide) = receiver.recv() {
                    if !decide(&mut state) {
                        break;
                    }
                }
            })?;
        Ok(ComponentPolicy {
            sender: Some(sender),
            available,
            worker: Some(worker),
            host_ports: grants.host_ports,
            blocks_direct_dns: grants.blocks_direct_dns,
        })
    }
}

// Policy performs no I/O; unexpected suspension must deny rather than block a socket check.
fn complete_decision<T>(
    future: impl std::future::Future<Output = wasmtime::Result<T>>,
) -> wasmtime::Result<T> {
    future
        .now_or_never()
        .ok_or_else(|| wasmtime::Error::msg("network policy unexpectedly suspended"))?
}

struct State {
    store: Store<Host>,
    bindings: Policy,
}

/// Returns whether the worker may accept another request.
type Decision = Box<dyn FnOnce(&mut State) -> bool + Send>;

pub struct ComponentPolicy {
    sender: Option<mpsc::SyncSender<Decision>>,
    available: Arc<std::sync::atomic::AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
    host_ports: Vec<Option<u16>>,
    blocks_direct_dns: bool,
}

impl Drop for ComponentPolicy {
    fn drop(&mut self) {
        // The worker's recv loop ends when the sender drops, so release it before joining.
        self.sender.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl ComponentPolicy {
    fn enqueue<T: Send + 'static>(
        &self,
        call: impl FnOnce(&Policy, &mut Store<Host>) -> wasmtime::Result<T> + Send + 'static,
        reply: impl FnOnce(Option<T>) + Send + 'static,
    ) {
        let available = Arc::clone(&self.available);
        let decision: Decision = Box::new(move |state| {
            let result = state
                .store
                .set_fuel(CALL_FUEL)
                .and_then(|()| call(&state.bindings, &mut state.store));
            let succeeded = result.is_ok();
            if !succeeded {
                available.store(false, std::sync::atomic::Ordering::Release);
            }
            reply(result.ok());
            succeeded
        });
        if self.is_available()
            && let Some(sender) = &self.sender
        {
            let _ = sender.try_send(decision);
        }
    }

    fn call<T: Send + 'static>(
        &self,
        call: impl FnOnce(&Policy, &mut Store<Host>) -> wasmtime::Result<T> + Send + 'static,
    ) -> Option<T> {
        let (reply, response) = mpsc::sync_channel(1);
        self.enqueue(call, move |result| {
            let _ = reply.send(result);
        });
        response.recv().ok().flatten()
    }

    fn call_async<T: Send + 'static, F>(
        &self,
        call: F,
        lease: terra_network::policy::DecisionLease,
    ) -> impl std::future::Future<Output = Option<T>> + Send + use<T, F>
    where
        F: FnOnce(&Policy, &mut Store<Host>) -> wasmtime::Result<T> + Send + 'static,
    {
        let (reply, response) = tokio::sync::oneshot::channel();
        self.enqueue(call, move |result| {
            drop(lease);
            let _ = reply.send(result);
        });
        async move { response.await.ok().flatten() }
    }
}

impl NetworkPolicy for ComponentPolicy {
    fn asynchronous(self: Arc<Self>) -> Option<Arc<dyn terra_network::policy::AsyncPolicy>> {
        Some(self)
    }

    fn is_available(&self) -> bool {
        self.available.load(std::sync::atomic::Ordering::Acquire)
            && self
                .worker
                .as_ref()
                .is_some_and(|worker| !worker.is_finished())
    }

    fn allows(&self, address: IpAddr, port: Option<u16>) -> bool {
        self.call(move |bindings, store| decide_allows(bindings, store, address, port))
            .unwrap_or(false)
    }

    fn host_service_ports(&self) -> &[Option<u16>] {
        &self.host_ports
    }

    fn lookup_name(&self, name: &str) -> NameLookup {
        if name.len() > MAX_NAME_BYTES {
            return NameLookup::Denied;
        }
        let name = name.to_owned();
        self.call(move |bindings, store| decide_lookup(bindings, store, &name))
            .unwrap_or(NameLookup::Denied)
    }

    fn accept_resolved(&self, name: &str, addresses: &[IpAddr]) -> Vec<IpAddr> {
        if name.len() > MAX_NAME_BYTES || addresses.len() > MAX_ADDRESSES {
            return Vec::new();
        }
        let name = name.to_owned();
        let addresses = addresses
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        self.call(move |bindings, store| decide_resolved(bindings, store, &name, &addresses))
            .unwrap_or_default()
    }

    fn blocks_direct_dns(&self) -> bool {
        self.blocks_direct_dns
    }
}

impl terra_network::policy::AsyncPolicy for ComponentPolicy {
    fn allows(
        &self,
        address: IpAddr,
        port: Option<u16>,
        lease: terra_network::policy::DecisionLease,
    ) -> terra_network::policy::DecisionFuture<bool> {
        let response = self.call_async(
            move |bindings, store| decide_allows(bindings, store, address, port),
            lease,
        );
        Box::pin(async move { response.await.unwrap_or(false) })
    }
    fn lookup_name(
        &self,
        name: String,
        lease: terra_network::policy::DecisionLease,
    ) -> terra_network::policy::DecisionFuture<NameLookup> {
        if name.len() > MAX_NAME_BYTES {
            return Box::pin(async { NameLookup::Denied });
        }
        let response = self.call_async(
            move |bindings, store| decide_lookup(bindings, store, &name),
            lease,
        );
        Box::pin(async move { response.await.unwrap_or(NameLookup::Denied) })
    }

    fn accept_resolved(
        &self,
        name: String,
        addresses: Vec<IpAddr>,
        lease: terra_network::policy::DecisionLease,
    ) -> terra_network::policy::DecisionFuture<Vec<IpAddr>> {
        if name.len() > MAX_NAME_BYTES || addresses.len() > MAX_ADDRESSES {
            return Box::pin(async { Vec::new() });
        }
        let addresses = addresses
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        let response = self.call_async(
            move |bindings, store| decide_resolved(bindings, store, &name, &addresses),
            lease,
        );
        Box::pin(async move { response.await.unwrap_or_default() })
    }
}

fn decide_allows(
    bindings: &Policy,
    store: &mut Store<Host>,
    address: IpAddr,
    port: Option<u16>,
) -> wasmtime::Result<bool> {
    complete_decision(bindings.terra_policy_decisions().call_allows(
        store,
        &address.to_string(),
        port,
    ))
}

fn decide_lookup(
    bindings: &Policy,
    store: &mut Store<Host>,
    name: &str,
) -> wasmtime::Result<NameLookup> {
    Ok(
        match complete_decision(
            bindings
                .terra_policy_decisions()
                .call_lookup_name(store, name),
        )? {
            Lookup::Static(addresses) => addresses
                .iter()
                .map(|address| address.parse())
                .collect::<Result<Vec<_>, _>>()
                .map_or(NameLookup::Denied, NameLookup::Static),
            Lookup::Resolve => NameLookup::Resolve,
            Lookup::Denied => NameLookup::Denied,
        },
    )
}

fn decide_resolved(
    bindings: &Policy,
    store: &mut Store<Host>,
    name: &str,
    addresses: &[String],
) -> wasmtime::Result<Vec<IpAddr>> {
    Ok(complete_decision(
        bindings
            .terra_policy_decisions()
            .call_accept_resolved(store, name, addresses),
    )?
    .iter()
    .filter_map(|address| address.parse().ok())
    .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::component::network::PolicyClient;
    use std::sync::{Arc, OnceLock};

    #[allow(unsafe_code)]
    fn factory() -> &'static PolicyFactory {
        static FACTORY: OnceLock<PolicyFactory> = OnceLock::new();
        FACTORY.get_or_init(|| {
            let engine = crate::engine::policy_engine().unwrap();
            let artifact = Box::leak(
                crate::engine::precompile_component(&engine, crate::test_fixtures::wasm::POLICY)
                    .unwrap()
                    .into_boxed_slice(),
            );
            // SAFETY: `artifact` was produced from this trusted component by this engine.
            let artifact = unsafe { crate::TrustedArtifact::from_trusted_bytes(artifact) };
            let component = artifact.deserialize(&engine).unwrap();
            PolicyFactory { engine, component }
        })
    }

    fn instantiate(config: &Config) -> wasmtime::Result<ComponentPolicy> {
        factory().instantiate(config, 16 << 20)
    }

    fn config(allow: &[&str]) -> Config {
        Config {
            mode: Mode::Allowlist,
            allow: allow.iter().map(ToString::to_string).collect(),
            hosts: Vec::new(),
            host_addresses: Vec::new(),
        }
    }

    #[test]
    fn asynchronous_policy_does_not_use_the_tokio_blocking_pool() {
        let policy: terra_network::PolicyHandle =
            Arc::new(instantiate(&config(&["api.test:443"])).unwrap());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        let (started, ready) = mpsc::sync_channel(1);
        let (release, blocked) = mpsc::sync_channel(1);
        let occupied = runtime.spawn_blocking(move || {
            started.send(()).unwrap();
            blocked.recv().unwrap();
        });
        ready.recv().unwrap();
        let result = runtime.block_on(async {
            tokio::time::timeout(std::time::Duration::from_secs(1), async {
                PolicyClient::new(policy, Arc::new(tokio::sync::Semaphore::new(1)))
                    .lookup_name("api.test".into())
                    .await
            })
            .await
        });
        release.send(()).unwrap();
        runtime.block_on(occupied).unwrap();
        assert!(matches!(result.unwrap(), Some(NameLookup::Resolve)));
    }

    #[tokio::test]
    async fn cancelled_async_policy_waiter_retains_admission_until_reply() {
        let policy = Arc::new(instantiate(&config(&["1.1.1.1:443"])).unwrap());
        let (started, ready) = tokio::sync::oneshot::channel();
        let (release, blocked) = mpsc::sync_channel(1);
        policy.enqueue(
            move |_, _| {
                started.send(()).unwrap();
                blocked.recv().unwrap();
                Ok(())
            },
            |_| {},
        );
        ready.await.unwrap();
        let calls = Arc::new(tokio::sync::Semaphore::new(1));
        let client = PolicyClient::new(policy.clone(), calls.clone());
        let operation = client.lookup_name("api.test".into());
        let result = tokio::time::timeout(std::time::Duration::from_millis(20), operation).await;
        let retained = calls.available_permits();
        release.send(()).unwrap();
        assert!(result.is_err());
        assert_eq!(retained, 0);
        let permit = tokio::time::timeout(std::time::Duration::from_secs(1), calls.acquire())
            .await
            .unwrap()
            .unwrap();
        drop(permit);
        let response = policy.call_async(
            |_, _| Err::<(), _>(wasmtime::Error::msg("trap")),
            Box::new(()),
        );
        assert!(response.await.is_none());
        assert!(!policy.is_available());
        assert!(
            !terra_network::policy::AsyncPolicy::allows(
                policy.as_ref(),
                "1.1.1.1".parse().unwrap(),
                Some(443),
                Box::new(()),
            )
            .await
        );
    }

    #[tokio::test]
    async fn worker_failure_releases_leases_of_rejected_and_abandoned_requests() {
        let policy = instantiate(&config(&[])).unwrap();
        let (entered, started) = tokio::sync::oneshot::channel();
        let (release, blocked) = mpsc::channel();
        policy.enqueue(
            move |_, _| {
                entered.send(()).unwrap();
                blocked
                    .recv_timeout(std::time::Duration::from_secs(2))
                    .unwrap();
                Err::<(), _>(wasmtime::Error::msg("worker failed"))
            },
            |_| {},
        );
        started.await.unwrap();
        let capacity = crate::component::network::MAX_POLICY_CALLS;
        let calls = Arc::new(tokio::sync::Semaphore::new(capacity + 1));
        for _ in 0..capacity {
            let lease = calls.clone().try_acquire_owned().unwrap();
            drop(policy.call_async(
                |_, _| -> wasmtime::Result<()> { panic!("request ran after worker failure") },
                Box::new(lease),
            ));
        }
        let lease = calls.clone().try_acquire_owned().unwrap();
        assert!(
            policy
                .call_async(|_, _| Ok(()), Box::new(lease))
                .await
                .is_none()
        );
        assert_eq!(calls.available_permits(), 1);
        let available = Arc::clone(&policy.available);
        let _ = release.send(());
        drop(policy);
        let _permits = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            calls.acquire_many(u32::try_from(capacity + 1).unwrap()),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(!available.load(std::sync::atomic::Ordering::Acquire));
    }

    #[test]
    fn wasm_policy_learns_only_public_answers_for_granted_names_and_ports() {
        let policy = instantiate(&config(&["*.example.test:443"])).unwrap();
        let public = "1.1.1.1".parse().unwrap();
        let private = "10.0.0.1".parse().unwrap();
        assert!(!policy.allows(public, Some(443)));
        assert!(matches!(
            policy.lookup_name("api.example.test"),
            NameLookup::Resolve
        ));
        assert!(matches!(
            policy.lookup_name("other.test"),
            NameLookup::Denied
        ));
        assert_eq!(
            policy.accept_resolved("api.example.test", &[public, private]),
            [public]
        );
        assert!(policy.allows(public, Some(443)));
        assert!(!policy.allows(public, Some(80)));
        assert!(!policy.allows(private, Some(443)));
        assert!(
            instantiate(&config(&[]))
                .unwrap()
                .accept_resolved("api.example.test", &[public])
                .is_empty()
        );
    }

    #[test]
    fn fully_qualified_dns_names_fit_and_excessive_queries_leave_policy_available() {
        let name = [
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61),
        ]
        .join(".");
        let policy = instantiate(&config(&[&name])).unwrap();
        let qualified = format!("{name}.");
        assert_eq!(qualified.len(), MAX_NAME_BYTES);
        assert!(matches!(
            policy.lookup_name(&qualified),
            NameLookup::Resolve
        ));
        let public = "1.1.1.1".parse().unwrap();
        assert_eq!(policy.accept_resolved(&qualified, &[public]), [public]);
        let excessive = "x".repeat(MAX_NAME_BYTES + 1);
        assert!(matches!(policy.lookup_name(&excessive), NameLookup::Denied));
        assert!(policy.accept_resolved(&excessive, &[public]).is_empty());
        assert!(
            policy
                .accept_resolved(&name, &vec![public; MAX_ADDRESSES + 1])
                .is_empty()
        );
        assert!(policy.is_available());
        assert!(policy.allows(public, Some(443)));
    }

    #[test]
    fn wasm_policy_keeps_static_host_grants_scoped_and_configuration_immutable() {
        let mut configuration = config(&["database.test:5432"]);
        configuration.hosts.push(HostRecord {
            name: "database.test".into(),
            addr: "HOST_LOOPBACK".into(),
        });
        let policy = instantiate(&configuration).unwrap();
        assert_eq!(policy.host_service_ports(), &[Some(5432), Some(5432)]);
        let NameLookup::Static(addresses) = policy.lookup_name("Database.Test.") else {
            panic!("static answer");
        };
        assert_eq!(addresses.len(), 2);
        for address in addresses {
            assert!(!policy.allows(address, Some(5432)));
            assert!(!policy.allows(address, Some(22)));
        }
        let response = policy.call(|bindings, store| {
            complete_decision(
                bindings
                    .terra_policy_decisions()
                    .call_configure(store, &config(&["HOST_LOOPBACK"])),
            )
        });
        assert!(response.unwrap().is_err());
        assert_eq!(policy.host_service_ports(), &[Some(5432), Some(5432)]);
    }

    #[test]
    fn sidecar_state_is_separate_under_concurrent_calls() {
        let policy = Arc::new(instantiate(&config(&["api.test:443"])).unwrap());
        let other = instantiate(&config(&[])).unwrap();
        std::thread::scope(|scope| {
            for _ in 0..4 {
                let policy = &policy;
                scope.spawn(move || {
                    let public = "1.1.1.1".parse().unwrap();
                    assert_eq!(policy.accept_resolved("api.test", &[public]), [public]);
                    assert!(policy.allows(public, Some(443)));
                });
            }
        });
        assert!(!other.allows("1.1.1.1".parse().unwrap(), Some(443)));
    }

    /// Network host callbacks run inside Wasmtime's event loop, which forbids
    /// starting another store's event loop on the same thread.
    #[tokio::test]
    async fn policy_decisions_can_run_inside_another_components_event_loop() {
        let policy = instantiate(&config(&["api.test:443"])).unwrap();
        let engine = crate::engine::device_engine().unwrap();
        let mut store = Store::new(&engine, ());
        store
            .run_concurrent(async |_| {
                let public = "1.1.1.1".parse().unwrap();
                assert!(matches!(
                    policy.lookup_name("api.test"),
                    NameLookup::Resolve
                ));
                assert_eq!(policy.accept_resolved("api.test", &[public]), [public]);
                assert!(policy.allows(public, Some(443)));
            })
            .await
            .unwrap();
    }

    #[test]
    fn fuel_exhaustion_permanently_disables_policy() {
        let policy = instantiate(&config(&["HOST_LOOPBACK:5432"])).unwrap();
        let module = wasmtime::Module::new(
            &factory().engine,
            "(module (func (export \"spin\") (loop br 0)))",
        )
        .unwrap();
        assert!(
            policy
                .call(move |_, store| {
                    let instance = complete_decision(wasmtime::Instance::new_async(
                        &mut *store,
                        &module,
                        &[],
                    ))?;
                    let result = complete_decision(
                        instance
                            .get_typed_func::<(), ()>(&mut *store, "spin")?
                            .call_async(store, ()),
                    );
                    assert_eq!(
                        result
                            .as_ref()
                            .unwrap_err()
                            .downcast_ref::<wasmtime::Trap>(),
                        Some(&wasmtime::Trap::OutOfFuel)
                    );
                    result
                })
                .is_none()
        );
        assert!(!policy.is_available());
        assert!(!policy.allows("1.1.1.1".parse().unwrap(), Some(443)));
        assert!(matches!(policy.lookup_name("api.test"), NameLookup::Denied));
        assert!(
            policy
                .accept_resolved("api.test", &["1.1.1.1".parse().unwrap()])
                .is_empty()
        );
    }

    #[test]
    fn suspension_fails_closed_and_component_memory_is_limited() {
        assert!(complete_decision::<()>(std::future::pending()).is_err());
        assert!(factory().instantiate(&config(&[]), 1).is_err());
    }

    #[test]
    fn sidecar_rejects_excessive_configuration_and_ambient_imports() {
        let mut excessive = config(&[]);
        excessive.allow = vec![String::new(); MAX_ADDRESSES + 1];
        assert!(instantiate(&excessive).is_err());
        excessive.allow = vec!["a".repeat(MAX_CONFIG_BYTES + 1)];
        assert!(instantiate(&excessive).is_err());
        let mut linker =
            crate::component::context::device_component_linker::<Host>(&factory().engine).unwrap();
        crate::component::clocks::add_monotonic_now(&mut linker).unwrap();
        for (interface, name, export) in [
            (
                "wasi:filesystem/types@0.3.1",
                "descriptor",
                "(type (sub resource))",
            ),
            (
                "wasi:sockets/types@0.3.1",
                "tcp-socket",
                "(type (sub resource))",
            ),
            (
                "terra:host/memory@0.1.0",
                "ram-bytes",
                "(func (result u64))",
            ),
            (
                "wasi:random/random@0.3.1",
                "get-random-u64",
                "(func (result u64))",
            ),
            (
                "wasi:clocks/monotonic-clock@0.3.1",
                "get-resolution",
                "(func (result u64))",
            ),
            (
                "wasi:clocks/monotonic-clock@0.3.1",
                "wait-until",
                "(func (param \"when\" u64))",
            ),
        ] {
            let probe = Component::new(
                &factory().engine,
                format!(
                    "(component (import \"{interface}\" (instance (export \"{name}\" {export}))))"
                ),
            )
            .unwrap();
            assert!(linker.instantiate_pre(&probe).is_err(), "{interface}");
        }
    }
}
