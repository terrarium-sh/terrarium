//! WIT adapter for an isolated network policy sidecar.

use std::net::IpAddr;
use std::sync::{Arc, Mutex, mpsc};
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

pub(crate) async fn run_policy_decision<T: Send + 'static>(
    policy: terra_network::PolicyHandle,
    calls: Arc<tokio::sync::Semaphore>,
    decision: impl FnOnce(&dyn NetworkPolicy) -> T + Send + 'static,
) -> Option<T> {
    let permit = calls.try_acquire_owned().ok()?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        decision(policy.as_ref())
    })
    .await
    .ok()
}

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
    /// # Safety
    /// The artifact must come from this build's trusted policy compilation.
    #[allow(unsafe_code)]
    pub unsafe fn from_build_artifact(artifact: &'static [u8]) -> wasmtime::Result<Self> {
        let engine = crate::engine::policy_engine()?;
        // SAFETY: the caller guarantees the artifact's trusted build provenance.
        let component = unsafe { crate::engine::trusted_component(&engine, artifact)? };
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
        let linker = crate::engine::device_component_linker(&self.engine)?;
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
        let (sender, receiver) = mpsc::sync_channel::<Decision>(1);
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
            sender: Mutex::new(Some(sender)),
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
    let mut future = std::pin::pin!(future);
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    match future.as_mut().poll(&mut context) {
        std::task::Poll::Ready(result) => result,
        std::task::Poll::Pending => Err(wasmtime::Error::msg(
            "network policy unexpectedly suspended",
        )),
    }
}

struct State {
    store: Store<Host>,
    bindings: Policy,
}

/// Returns whether the worker may accept another request.
type Decision = Box<dyn FnOnce(&mut State) -> bool + Send>;

pub struct ComponentPolicy {
    sender: Mutex<Option<mpsc::SyncSender<Decision>>>,
    worker: Option<std::thread::JoinHandle<()>>,
    host_ports: Vec<Option<u16>>,
    blocks_direct_dns: bool,
}

impl ComponentPolicy {
    fn call<T: Send + 'static>(
        &self,
        call: impl FnOnce(&Policy, &mut Store<Host>) -> wasmtime::Result<T> + Send + 'static,
    ) -> Option<T> {
        let mut sender = self.sender.lock().ok()?;
        let (reply, response) = mpsc::sync_channel(1);
        let decision = Box::new(move |state: &mut State| {
            let result = state
                .store
                .set_fuel(CALL_FUEL)
                .and_then(|()| call(&state.bindings, &mut state.store));
            let succeeded = result.is_ok();
            let _ = reply.send(result);
            succeeded
        });
        let result = sender
            .as_ref()?
            .send(decision)
            .ok()
            .and_then(|()| response.recv().ok())
            .and_then(Result::ok);
        if result.is_none() {
            *sender = None;
        }
        result
    }
}

impl Drop for ComponentPolicy {
    fn drop(&mut self) {
        self.sender
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl NetworkPolicy for ComponentPolicy {
    fn is_available(&self) -> bool {
        self.sender.lock().is_ok_and(|sender| sender.is_some())
            && self
                .worker
                .as_ref()
                .is_some_and(|worker| !worker.is_finished())
    }

    fn allows(&self, address: IpAddr, port: Option<u16>) -> bool {
        self.call(move |bindings, store| {
            complete_decision(bindings.terra_policy_decisions().call_allows(
                store,
                &address.to_string(),
                port,
            ))
        })
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
        match self.call(move |bindings, store| {
            complete_decision(
                bindings
                    .terra_policy_decisions()
                    .call_lookup_name(store, &name),
            )
        }) {
            Some(Lookup::Static(addresses)) => addresses
                .iter()
                .map(|address| address.parse())
                .collect::<Result<Vec<_>, _>>()
                .map_or(NameLookup::Denied, NameLookup::Static),
            Some(Lookup::Resolve) => NameLookup::Resolve,
            Some(Lookup::Denied) | None => NameLookup::Denied,
        }
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
        self.call(move |bindings, store| {
            complete_decision(
                bindings
                    .terra_policy_decisions()
                    .call_accept_resolved(store, &name, &addresses),
            )
        })
        .unwrap_or_default()
        .iter()
        .filter_map(|address| address.parse().ok())
        .collect()
    }

    fn blocks_direct_dns(&self) -> bool {
        self.blocks_direct_dns
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, OnceLock};

    #[allow(unsafe_code)]
    fn factory() -> &'static PolicyFactory {
        static FACTORY: OnceLock<PolicyFactory> = OnceLock::new();
        FACTORY.get_or_init(|| {
            let engine = crate::engine::policy_engine().unwrap();
            let artifact = Box::leak(
                crate::engine::precompile_component(
                    &engine,
                    include_bytes!("../../../../components/policy/target/wasm32-wasip3/release/terra_policy_component.wasm"),
                )
                .unwrap()
                .into_boxed_slice(),
            );
            // SAFETY: `artifact` was produced from this trusted component by this engine.
            let component = unsafe { crate::engine::trusted_component(&engine, artifact) }.unwrap();
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
        let linker = crate::engine::device_component_linker::<Host>(&factory().engine).unwrap();
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
