#![allow(clippy::expect_used)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use terra_runtime::{
    SyntheticRam,
    box_runtime::{BoxHost, BoxRuntime},
    component::{
        Interrupt,
        vmm::{
            Completion, Exit,
            boot::BootEntry,
            machine::{Device, DeviceKind},
            virtualization::{
                Architecture, MachineConfig, PreparedMachine, StartedVcpus, VirtualMachine,
            },
        },
    },
    engine::{DeviceContext, device_component_linker, device_engine},
};
use wasmtime::{Store, component::Component};

struct TestVm(SyntheticRam);

impl VirtualMachine for TestVm {
    fn memory(&self) -> wasmtime::Result<SyntheticRam> {
        Ok(self.0.clone())
    }
}

async fn attach_test_machine(
    runtime: BoxRuntime,
    ram: SyntheticRam,
) -> (
    BoxRuntime,
    terra_runtime::component::vmm::virtualization::MachineHandle<TestVm>,
) {
    let devices = [
        (DeviceKind::Block, 11),
        (DeviceKind::Block, 12),
        (DeviceKind::Net, 13),
        (DeviceKind::Vsock, 14),
        (DeviceKind::Memory, 15),
    ]
    .into_iter()
    .zip(0..)
    .map(|((kind, irq), slot)| Device {
        kind,
        irq,
        mmio_base: 0xd000_0000 + slot * 0x1000,
    })
    .collect();
    let config =
        MachineConfig::new(Architecture::X86, ram.size(), 1, devices).expect("machine config");
    let mut prepared = PreparedMachine::new(config, TestVm(ram));
    prepared
        .accept_boot(BootEntry {
            entry: 0x10_0000,
            boot_argument: 0x7000,
        })
        .expect("native boot acceptance");
    runtime.attach_machine(prepared).await.expect("attach VM")
}

fn no_interrupt() -> Interrupt {
    Arc::new(|_| Ok(()))
}

fn router(engine: &wasmtime::Engine) -> Component {
    Component::new(
        engine,
        include_bytes!("../../../components/target/wasm32-wasip3/release/terra_vmm_component.wasm"),
    )
    .expect("router component")
}

fn memory(engine: &wasmtime::Engine) -> Component {
    Component::new(
        engine,
        include_bytes!("../../../components/target/wasm32-wasip3/release/terra_mem_component.wasm"),
    )
    .expect("memory component")
}

async fn prepare_test_vcpus(
    runtime: BoxRuntime,
) -> wasmtime::Result<(
    terra_runtime::box_runtime::PreparedBoxRuntime,
    Vec<terra_runtime::component::vmm::NativeVcpu>,
)> {
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let (runtime, _reaper) = runtime
        .prepare_vcpus(move |controls, _| {
            sender.send(controls).expect("test setup");
            Ok(StartedVcpus::new((), || Ok(()), |()| Ok(Vec::new())))
        })
        .await?;
    Ok((runtime, receiver.recv().expect("test setup")))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn wasm_vmm_routes_native_exits_and_stops_with_the_box() {
    let engine = device_engine().expect("engine");
    let ram = SyntheticRam::new(8 << 20).expect("RAM");
    let mut runtime = BoxRuntime::new(&engine, BoxHost::new()).expect("runtime");
    runtime
        .initialize_mmio(&router(&engine))
        .await
        .expect("router");
    let (mut runtime, machine) = attach_test_machine(runtime, ram.clone()).await;
    let ram_grant = machine.ram();
    let memory = terra_runtime::component::mem::grant_shared(
        &mut runtime,
        move || Ok(DeviceContext::with_ram(ram_grant.resolve()?)),
        &memory(&engine),
        no_interrupt(),
    )
    .expect("memory device");
    let (runtime, startup) = prepare_test_vcpus(runtime).await.expect("vCPU grants");
    assert_eq!(machine.machine().0.size(), ram.size());
    let runtime = runtime.start();
    let vcpu = startup.into_iter().next().expect("vCPU");
    assert_eq!(machine.machine().0.size(), ram.size());

    let pio = tokio::task::block_in_place(|| {
        vcpu.exchange(
            terra_runtime::component::vmm::mmio::terra::mmio::platform::Exit::PioRead(
                terra_runtime::component::vmm::mmio::terra::mmio::platform::PioRead {
                    port: 0x3f8,
                    length: 1,
                },
            ),
        )
    })
    .expect("PIO completion");
    assert!(matches!(pio, Completion::PioZero));

    let msr = tokio::task::block_in_place(|| {
        vcpu.exchange(Exit::Rdmsr(
            terra_runtime::component::vmm::mmio::terra::mmio::platform::Msr {
                index: 0x10,
                value: 0,
            },
        ))
    })
    .expect("MSR completion");
    assert!(matches!(msr, Completion::Rdmsr(0)));

    let unsupported_msr = tokio::task::block_in_place(|| {
        vcpu.exchange(Exit::Rdmsr(
            terra_runtime::component::vmm::mmio::terra::mmio::platform::Msr {
                index: u32::MAX,
                value: 0,
            },
        ))
    })
    .expect("unsupported MSR completion");
    assert!(matches!(unsupported_msr, Completion::MsrFault));

    let mmio = tokio::task::block_in_place(|| {
        vcpu.exchange(Exit::MmioRead(
            terra_runtime::component::vmm::mmio::terra::mmio::platform::MmioRead {
                address: 0xd000_4000,
                width: 4,
            },
        ))
    })
    .expect("MMIO completion");
    assert!(matches!(mmio, Completion::MmioRead(0x7472_6976)));

    let arm_read = tokio::task::block_in_place(|| {
        vcpu.exchange_arm_exception(
            0xd000_4000,
            (0x24 << 26) | (1 << 24) | (2 << 22) | (4 << 16),
            |_| {
                Err(wasmtime::Error::msg(
                    "loads must not read a source register",
                ))
            },
        )
    })
    .expect("ARM MMIO read");
    assert!(matches!(
        arm_read,
        Completion::ArmRead(terra_runtime::component::vmm::platform::ArmRead {
            register: Some(4),
            value: 0x7472_6976
        })
    ));
    let mut reads = Vec::new();
    let arm_write = tokio::task::block_in_place(|| {
        vcpu.exchange_arm_exception(
            0xd000_4024,
            (0x24 << 26) | (1 << 24) | (2 << 22) | (7 << 16) | (1 << 6),
            |register| {
                reads.push(register);
                Ok(0)
            },
        )
    })
    .expect("ARM MMIO write");
    assert_eq!(reads, [7]);
    assert!(matches!(
        arm_write,
        Completion::ArmRead(terra_runtime::component::vmm::platform::ArmRead {
            register: None,
            ..
        })
    ));
    let mut reads = Vec::new();
    let hvc = tokio::task::block_in_place(|| {
        vcpu.exchange_arm_exception(0, 0x16 << 26, |register| {
            reads.push(register);
            Ok(if register == 0 { 0x8400_0000 } else { 0 })
        })
    })
    .expect("ARM HVC");
    assert_eq!(reads, [0, 1, 2, 3]);
    assert!(matches!(hvc, Completion::HvcReturn(0x0001_0000)));

    memory.close().expect("memory close");
    let shutdown_started = std::time::Instant::now();
    let stopped = tokio::task::block_in_place(|| vcpu.exchange(Exit::Shutdown));
    assert!(stopped.is_err(), "shutdown has no re-entry completion");
    assert!(
        shutdown_started.elapsed() < Duration::from_secs(1),
        "dropping the Wasm vCPU resource disconnects the native rendezvous promptly"
    );
    tokio::time::timeout(Duration::from_secs(5), runtime.join())
        .await
        .expect("runtime shutdown deadline")
        .expect("runtime shutdown");
}

#[tokio::test]
async fn vcpu_preparation_requires_a_router_and_boot() {
    let engine = device_engine().expect("test setup");
    for router_present in [false, true] {
        let mut runtime = BoxRuntime::new(&engine, BoxHost::new()).expect("test setup");
        if router_present {
            runtime
                .initialize_mmio(&router(&engine))
                .await
                .expect("test setup");
        }
        assert!(prepare_test_vcpus(runtime).await.is_err());
    }
    let mut runtime = BoxRuntime::new(&engine, BoxHost::new()).expect("test setup");
    runtime
        .initialize_mmio(&router(&engine))
        .await
        .expect("test setup");
    let (runtime, _) =
        attach_test_machine(runtime, SyntheticRam::new(8 << 20).expect("test setup")).await;
    let (_prepared, vcpus) = prepare_test_vcpus(runtime).await.expect("test setup");
    assert_eq!(vcpus.len(), 1);
}

#[tokio::test]
async fn device_components_receive_no_platform_or_vcpu_grant() {
    let engine = device_engine().expect("engine");
    let mut store = Store::new(&engine, DeviceContext::new(4096).expect("device host"));
    let linker = device_component_linker(&engine).expect("device linker");
    assert!(
        linker
            .instantiate_async(&mut store, &router(&engine))
            .await
            .is_err(),
        "only the box router linker may grant the platform interface"
    );
}

#[tokio::test]
async fn failed_startup_disconnects_native_vcpus() {
    let engine = device_engine().expect("engine");
    let mut runtime = BoxRuntime::new(&engine, BoxHost::new()).expect("runtime");
    runtime
        .initialize_mmio(&router(&engine))
        .await
        .expect("router");
    let (runtime, _) = attach_test_machine(runtime, SyntheticRam::new(8 << 20).expect("RAM")).await;
    let (sender, receiver) = std::sync::mpsc::channel();
    let started = runtime
        .prepare_vcpus(move |controls, _| {
            sender.send(controls).expect("native controls");
            Err::<StartedVcpus, _>(wasmtime::Error::msg("injected startup failure"))
        })
        .await;
    assert!(started.is_err());
    let controls = receiver.recv().expect("escaped native controls");
    tokio::task::spawn_blocking(move || {
        let started = std::time::Instant::now();
        assert!(controls[0].exchange(Exit::Halt).is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
    })
    .await
    .expect("native probe");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vcpu_failure_preserves_teardown_order_before_runtime_join() {
    use terra_runtime::component::vmm::{
        lifecycle::Outcome, machine::DeviceKind, teardown::DeviceShutdown,
    };

    let engine = device_engine().expect("engine");
    let mut runtime = BoxRuntime::new(&engine, BoxHost::new()).expect("runtime");
    runtime
        .initialize_mmio(&router(&engine))
        .await
        .expect("router");
    let (mut runtime, _) =
        attach_test_machine(runtime, SyntheticRam::new(8 << 20).expect("RAM")).await;
    let order = Arc::new(std::sync::Mutex::new(Vec::new()));
    let devices = Arc::clone(&order);
    runtime
        .add_device_shutdown(DeviceShutdown::new(DeviceKind::Memory, async move {
            devices.lock().expect("order").push("device");
            Ok(())
        }))
        .expect("device grant");
    let interrupts = Arc::clone(&order);
    runtime
        .grant_interrupt_shutdown(async move {
            interrupts.lock().expect("order").push("interrupt");
            Ok(())
        })
        .expect("interrupt grant");
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let stop = Arc::clone(&order);
    let reap = Arc::clone(&order);
    let (runtime, reaper) = runtime
        .prepare_vcpus(move |mut controls, _| {
            sender
                .send(controls.pop().expect("vCPU"))
                .expect("native controller");
            Ok(StartedVcpus::new(
                controls,
                move || {
                    stop.lock().expect("order").push("stop");
                    Ok(())
                },
                move |controls| {
                    drop(controls);
                    reap.lock().expect("order").push("reap");
                    Ok(vec![Ok(())])
                },
            ))
        })
        .await
        .expect("launch");
    let cpu = receiver.recv().expect("native controller");
    let mut outcome = runtime.lifecycle_notifier().subscribe();
    let running = runtime.start();
    tokio::task::spawn_blocking(move || {
        assert!(
            cpu.exchange(Exit::HvcResult(
                terra_runtime::component::vmm::platform::HvcResult {
                    target: u8::MAX,
                    status: 0,
                },
            ))
            .is_err()
        );
    })
    .await
    .expect("native fault");
    tokio::time::timeout(Duration::from_secs(2), outcome.changed())
        .await
        .expect("failure outcome timeout")
        .expect("failure outcome");
    assert_eq!(*outcome.borrow_and_update(), Some(Outcome::ComponentFailed));
    assert!(running.join().await.is_err());
    assert_eq!(
        *order.lock().expect("order"),
        ["stop", "reap", "device", "interrupt"]
    );
    reaper.wait().await.expect("native recovery shares reaping");
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn wasi_requests_cpu_stop_before_publishing_terminal_outcomes() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use terra_runtime::component::vmm::lifecycle::{Event, Outcome};
    use terra_runtime::component::vmm::{machine::DeviceKind, teardown::DeviceShutdown};

    let engine = device_engine().expect("engine");
    for event in [
        Event::GuestExit(23),
        Event::ComponentFailed,
        Event::Deadline,
    ] {
        let mut runtime = BoxRuntime::new(&engine, BoxHost::new()).expect("runtime");
        runtime
            .initialize_mmio(&router(&engine))
            .await
            .expect("router");
        let (mut runtime, machine) =
            attach_test_machine(runtime, SyntheticRam::new(8 << 20).expect("RAM")).await;
        let calls = Arc::new(AtomicUsize::new(0));
        let stops = Arc::clone(&calls);
        let reaped = Arc::new(AtomicUsize::new(0));
        let finished = Arc::clone(&reaped);
        let stop_requested = Arc::clone(&calls);
        let (reaper_started, started) = tokio::sync::oneshot::channel();
        let (release, released) = std::sync::mpsc::sync_channel(1);
        let closed = Arc::new(std::sync::Mutex::new(Vec::new()));
        let shutdowns = [
            DeviceKind::Block,
            DeviceKind::Vsock,
            DeviceKind::Memory,
            DeviceKind::Net,
            DeviceKind::Fs,
        ]
        .into_iter()
        .map(|kind| {
            let closed = Arc::clone(&closed);
            let reaped = Arc::clone(&reaped);
            DeviceShutdown::new(kind, async move {
                assert_eq!(reaped.load(Ordering::SeqCst), 1);
                closed.lock().expect("close observer").push(kind);
                if event == Event::ComponentFailed && kind == DeviceKind::Memory {
                    Err("close failed".to_owned())
                } else {
                    Ok(())
                }
            })
        })
        .collect::<Vec<_>>();
        for shutdown in shutdowns {
            runtime
                .add_device_shutdown(shutdown)
                .expect("shutdown grant");
        }
        let interrupt_calls = Arc::new(AtomicUsize::new(0));
        let released_interrupts = Arc::clone(&interrupt_calls);
        let closed_devices = Arc::clone(&closed);
        let live_machine = machine.clone();
        runtime
            .grant_interrupt_shutdown(async move {
                assert!(live_machine.machine().0.size() > 0);
                assert_eq!(closed_devices.lock().expect("close observer").len(), 5);
                released_interrupts.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .expect("interrupt grant");
        let teardown = runtime.native_teardown();
        let lifecycle = runtime.lifecycle_notifier();
        let mut outcome = lifecycle.subscribe();
        let (runtime, controls) = runtime
            .prepare_vcpus(move |controls, _| {
                Ok(StartedVcpus::new(
                    controls,
                    move || {
                        stops.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    },
                    move |controls| {
                        assert_eq!(stop_requested.load(Ordering::SeqCst), 1);
                        reaper_started.send(()).expect("reaper observer");
                        released
                            .recv_timeout(Duration::from_secs(2))
                            .expect("release reaper");
                        let count = controls.len();
                        drop(controls);
                        finished.store(1, Ordering::SeqCst);
                        Ok(vec![Ok(()); count])
                    },
                ))
            })
            .await
            .expect("launch");
        let running = runtime.start();
        let expected = match event {
            Event::GuestExit(code) => {
                lifecycle.guest_exit(code);
                Outcome::GuestExit(code)
            }
            Event::ComponentFailed => {
                lifecycle.component_failed();
                Outcome::ComponentFailed
            }
            Event::Deadline => {
                lifecycle.deadline();
                Outcome::Deadline
            }
        };
        tokio::time::timeout(Duration::from_secs(2), started)
            .await
            .expect("WASI starts native reaping")
            .expect("reaper started");
        assert!(
            !outcome.has_changed().expect("lifecycle source"),
            "lifecycle must wait for native reaping"
        );
        release.send(()).expect("release reaper");
        tokio::time::timeout(Duration::from_secs(2), outcome.changed())
            .await
            .expect("WASI lifecycle timeout")
            .expect("lifecycle outcome");
        assert_eq!(*outcome.borrow_and_update(), Some(expected));
        assert!(
            machine.machine().0.size() > 0,
            "native handles retain the VM through cleanup"
        );
        assert!(machine.ram().resolve().is_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(reaped.load(Ordering::SeqCst), 1);
        let teardown = teardown
            .wait_until(Instant::now() + Duration::from_secs(2))
            .await;
        if event == Event::ComponentFailed {
            assert_eq!(teardown, Err("close failed".to_owned()));
        } else {
            teardown.expect("native teardown");
        }
        assert_eq!(interrupt_calls.load(Ordering::SeqCst), 1);

        assert_eq!(
            *closed.lock().expect("close observer"),
            [
                DeviceKind::Memory,
                DeviceKind::Fs,
                DeviceKind::Net,
                DeviceKind::Vsock,
                DeviceKind::Block
            ]
        );
        assert_eq!(
            closed.lock().expect("close observer").len(),
            5,
            "native recovery must not close devices twice"
        );
        drop(controls);
        running.abort_and_join().await;
    }
}

#[tokio::test]
async fn deferred_device_failure_prevents_cpu_launch() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let engine = device_engine().expect("engine");
    let ram = SyntheticRam::new(8 << 20).expect("RAM");
    let mut runtime = BoxRuntime::new(&engine, BoxHost::new()).expect("runtime");
    runtime
        .initialize_mmio(&router(&engine))
        .await
        .expect("router");
    let (mut runtime, _) = attach_test_machine(runtime, ram.clone()).await;
    let _channel = terra_runtime::component::block::instantiate_shared(
        &mut runtime,
        terra_runtime::component::block::host::BlockHost::new(
            ram,
            terra_runtime::component::block::backing::DiskGrant::Mem(
                terra_runtime::BoundedDisk::new(0, false),
            ),
        ),
        &memory(&engine),
        true,
        no_interrupt(),
    )
    .expect("grant is deferred until composition");
    let launched = Arc::new(AtomicBool::new(false));
    let cpu_started = Arc::clone(&launched);
    let startup = runtime.prepare_vcpus(move |controls, _| {
        cpu_started.store(true, Ordering::SeqCst);
        Ok(StartedVcpus::new(
            controls,
            || Ok(()),
            |controls| {
                drop(controls);
                Ok(Vec::new())
            },
        ))
    });
    assert!(
        tokio::time::timeout(Duration::from_secs(3), startup)
            .await
            .expect("startup fails promptly")
            .is_err()
    );
    assert!(!launched.load(Ordering::SeqCst));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wasi_composes_multiple_deferred_workers_with_their_final_mappings() {
    use terra_runtime::BoundedDisk;

    use terra_runtime::component::block::backing::DiskGrant;

    let engine = device_engine().expect("engine");
    let ram = SyntheticRam::new(8 << 20).expect("RAM");
    let mut runtime = BoxRuntime::new(&engine, BoxHost::new()).expect("runtime");
    runtime
        .initialize_mmio(&router(&engine))
        .await
        .expect("router");
    let (mut runtime, _) = attach_test_machine(runtime, ram.clone()).await;
    let block = Component::new(
        &engine,
        include_bytes!(
            "../../../components/target/wasm32-wasip3/release/terra_block_component.wasm"
        ),
    )
    .expect("block component");
    let mut channels = Vec::new();
    for bytes in [4096, 8192, 12288] {
        let host = terra_runtime::component::block::host::BlockHost::new(
            ram.clone(),
            DiskGrant::Mem(BoundedDisk::new(bytes, false)),
        );
        let channel = terra_runtime::component::block::instantiate_shared(
            &mut runtime,
            host,
            &block,
            false,
            no_interrupt(),
        )
        .expect("deferred block grant");
        if bytes == 12288 {
            channel
                .map_mmio(&mut runtime, 0xe000_0000, 0x1000)
                .expect("explicit mapping for an additional device");
        }
        channels.push(channel);
    }
    let (runtime, startup) = prepare_test_vcpus(runtime).await.expect("startup grant");
    let running = runtime.start();
    let controls = startup;
    tokio::task::spawn_blocking(move || {
        for (channel, sectors) in channels.into_iter().zip([8_u32, 16, 24]) {
            assert_eq!(
                channel.read(0, 4).expect("magic"),
                0x7472_6976_u32.to_le_bytes()
            );
            assert_eq!(
                channel.read(0x100, 4).expect("capacity"),
                sectors.to_le_bytes()
            );
            channel.close().expect("close block");
        }
    })
    .await
    .expect("native MMIO probes");
    drop(controls);
    running.join().await.expect("joined runtime");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)]
async fn wasi_lifecycle_closes_a_device_through_the_running_mmio_bridge() {
    use terra_runtime::component::vmm::lifecycle::Outcome;
    use terra_runtime::component::vmm::machine::DeviceKind;

    let engine = device_engine().expect("engine");
    let ram = SyntheticRam::new(8 << 20).expect("RAM");
    let mut runtime = BoxRuntime::new(&engine, BoxHost::new()).expect("runtime");
    runtime
        .initialize_mmio(&router(&engine))
        .await
        .expect("router");
    let (mut runtime, _) = attach_test_machine(runtime, ram.clone()).await;
    let channel = terra_runtime::component::mem::instantiate_shared(
        &mut runtime,
        DeviceContext::with_ram(ram),
        &memory(&engine),
        no_interrupt(),
    )
    .expect("memory grant");
    let delivered = Arc::new(std::sync::Mutex::new(Vec::new()));
    let injections = Arc::clone(&delivered);
    let ioapic = runtime
        .grant_ioapic(Arc::new(move |interrupt| {
            injections
                .lock()
                .expect("interrupt observer")
                .push(interrupt);
            Ok(())
        }))
        .await
        .expect("IOAPIC grant");
    assert!(runtime.grant_ioapic(Arc::new(|_| Ok(()))).await.is_err());
    let memory_irq = ioapic
        .bind_interrupt(DeviceKind::Memory, 0)
        .expect("bind memory interrupt");
    assert!(ioapic.bind_interrupt(DeviceKind::Memory, 1).is_err());
    let interrupt_handle = ioapic.clone();
    runtime
        .grant_interrupt_shutdown(async move {
            interrupt_handle
                .close()
                .await
                .map_err(|error| error.to_string())
        })
        .expect("interrupt grant");
    let teardown = runtime.native_teardown();
    let (runtime, startup) = prepare_test_vcpus(runtime).await.expect("startup grant");
    let lifecycle = runtime.lifecycle_notifier();
    let mut outcome = lifecycle.subscribe();
    let running = runtime.start();
    let controls = startup;
    tokio::task::block_in_place(|| {
        ioapic.access(0, 4, true, 0x2e).expect("select pin 15");
        ioapic
            .access(0x10, 4, true, 0x40)
            .expect("route pin 15 to vector 64");
        memory_irq(true).expect("assert memory IRQ by kind");
        ioapic.access(0, 4, false, 0).expect("drain IRQ queue");
    });
    {
        let interrupts = delivered.lock().expect("interrupt observer");
        assert_eq!(interrupts.len(), 1);
        assert_eq!(interrupts[0].vector, 0x40);
        assert_eq!(interrupts[0].destination, 0);
    }
    lifecycle.guest_exit(0);
    tokio::time::timeout(Duration::from_secs(3), outcome.changed())
        .await
        .expect("teardown completes without a nested store loop")
        .expect("lifecycle outcome");
    assert_eq!(*outcome.borrow_and_update(), Some(Outcome::GuestExit(0)));
    teardown
        .wait_until(Instant::now() + Duration::from_secs(3))
        .await
        .expect("native teardown closes the device and interrupts");
    assert!(channel.read(0, 4).is_err());
    assert!(memory_irq(false).is_err());
    assert!(ioapic.set_line(0, false).is_err());
    drop(controls);
    running.join().await.expect("runtime stopped");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wasi_irq_lines_drain_assertions_before_vm_release() {
    use terra_runtime::component::vmm::machine::DeviceKind;

    let engine = device_engine().expect("engine");
    let mut runtime = BoxRuntime::new(&engine, BoxHost::new()).expect("runtime");
    runtime
        .initialize_mmio(&router(&engine))
        .await
        .expect("router");
    let ram = SyntheticRam::new(8 << 20).expect("RAM");
    let (mut runtime, _) = attach_test_machine(runtime, ram.clone()).await;
    terra_runtime::component::mem::instantiate_shared(
        &mut runtime,
        DeviceContext::with_ram(ram),
        &memory(&engine),
        no_interrupt(),
    )
    .expect("memory grant");
    let delivered = Arc::new(std::sync::Mutex::new(Vec::new()));
    let injections = Arc::clone(&delivered);
    let lines = runtime
        .grant_irq_lines(move |gsi, level| {
            injections
                .lock()
                .expect("interrupt observer")
                .push((gsi, level));
            Ok(())
        })
        .await
        .expect("IRQ grant");
    assert!(runtime.grant_irq_lines(|_, _| Ok(())).await.is_err());
    assert!(runtime.grant_ioapic(Arc::new(|_| Ok(()))).await.is_err());
    let memory_irq = lines
        .bind_interrupt(DeviceKind::Memory, 0)
        .expect("bind memory interrupt");
    assert!(lines.bind_interrupt(DeviceKind::Memory, 1).is_err());
    for _ in 0..256 {
        memory_irq(true).expect("queue accepts its full capacity");
    }
    assert!(memory_irq(false).is_err());
    let interrupt_handle = lines.clone();
    runtime
        .grant_interrupt_shutdown(async move {
            interrupt_handle
                .close()
                .await
                .map_err(|error| error.to_string())
        })
        .expect("cleanup grant");
    let teardown = runtime.native_teardown();
    let (runtime, startup) = prepare_test_vcpus(runtime).await.expect("startup grant");
    let lifecycle = runtime.lifecycle_notifier();
    let running = runtime.start();
    let controls = startup;
    lifecycle.guest_exit(0);
    tokio::time::timeout(
        Duration::from_secs(3),
        teardown.wait_until(Instant::now() + Duration::from_secs(3)),
    )
    .await
    .expect("IRQ cleanup completes")
    .expect("IRQ cleanup");
    assert_eq!(
        *delivered.lock().expect("interrupt observer"),
        [(15, true), (15, false)]
    );
    assert!(memory_irq(false).is_err());
    drop(controls);
    running.join().await.expect("runtime stopped");
}

#[tokio::test]
async fn failed_native_reaping_retains_vm_and_dependent_cleanup() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use terra_runtime::component::vmm::teardown::DeviceShutdown;

    let engine = device_engine().expect("engine");
    let mut runtime = BoxRuntime::new(&engine, BoxHost::new()).expect("runtime");
    runtime
        .initialize_mmio(&router(&engine))
        .await
        .expect("router");
    let (mut runtime, machine) =
        attach_test_machine(runtime, SyntheticRam::new(8 << 20).expect("RAM")).await;
    let backend = Arc::downgrade(&machine.machine());
    drop(machine);
    let closes = Arc::new(AtomicUsize::new(0));
    let device_closes = Arc::clone(&closes);
    runtime
        .add_device_shutdown(DeviceShutdown::new(DeviceKind::Memory, async move {
            device_closes.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }))
        .expect("shutdown grant");
    let interrupt_closes = Arc::clone(&closes);
    runtime
        .grant_interrupt_shutdown(async move {
            interrupt_closes.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
        .expect("interrupt cleanup");
    runtime
        .register_loop(Box::new(|_| {
            Box::pin(async { Err(wasmtime::Error::msg("injected VMM trap")) })
        }))
        .expect("failure loop");
    let (runtime, reaper) = runtime
        .prepare_vcpus(|controls, _| {
            Ok(StartedVcpus::new(
                controls,
                || Ok(()),
                |controls| {
                    drop(controls);
                    Err("injected reaper timeout".to_owned())
                },
            ))
        })
        .await
        .expect("native startup");
    assert!(runtime.start().join().await.is_err());
    assert!(reaper.wait().await.is_err());
    assert!(
        backend.upgrade().is_some(),
        "unconfirmed reaping must retain the VM"
    );
    assert_eq!(closes.load(Ordering::SeqCst), 0);
}
