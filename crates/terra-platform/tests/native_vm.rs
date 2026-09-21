#![allow(clippy::expect_used)]

#[cfg(any(
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ),
    all(target_os = "macos", target_arch = "aarch64"),
    all(
        target_os = "windows",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
mod supported_host {
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    use terra_platform::vm::{
        BootState, GicConfig, InterruptControllerConfig, PreparedVm, VcpuAction, VcpuExit,
        VcpuHandler, VcpuOutcome, VmConfig,
    };

    const RAM_BYTES: u64 = 16 * 1024 * 1024;
    const MARKER: u32 = 0xa5a5_a5a5;
    static NATIVE_HYPERVISOR: Mutex<()> = Mutex::new(());

    fn one_vcpu_config() -> VmConfig {
        VmConfig {
            ram_base: if cfg!(target_arch = "aarch64") {
                terra_limits::ARM_RAM_BASE
            } else {
                0
            },
            ram_bytes: RAM_BYTES,
            vcpus: 1,
            interrupt_controller: if cfg!(target_arch = "aarch64") {
                InterruptControllerConfig::Arm(GicConfig {
                    distributor_base: terra_limits::ARM_GIC_DIST_BASE,
                    distributor_size: terra_limits::ARM_GIC_DIST_SIZE,
                    redistributor_base: terra_limits::ARM_GIC_REDIST_BASE,
                    redistributor_size: terra_limits::ARM_GIC_REDIST_SIZE,
                })
            } else {
                InterruptControllerConfig::X86
            },
            irq_routes: Vec::new(),
        }
    }

    #[test]
    #[ignore = "requires a native hypervisor"]
    fn prepared_vm_rejects_missing_handlers_before_boot() {
        let _native_hypervisor = NATIVE_HYPERVISOR.lock().expect("lock native hypervisor");
        let config = one_vcpu_config();
        let prepared = PreparedVm::create(&config, None).expect("prepare native VM");

        assert!(
            prepared
                .start(
                    BootState {
                        entry: 0,
                        boot_argument: 0,
                    },
                    Vec::new(),
                )
                .is_err()
        );

        PreparedVm::create(&config, None).expect("release failed prepared VM");
    }

    #[test]
    #[ignore = "requires a native hypervisor"]
    fn dropping_an_unstarted_vm_releases_the_native_hypervisor() {
        let _native_hypervisor = NATIVE_HYPERVISOR.lock().expect("lock native hypervisor");
        let config = one_vcpu_config();
        let prepared = PreparedVm::create(&config, None).expect("prepare native VM");
        drop(prepared);
        PreparedVm::create(&config, None).expect("recreate native VM");
    }

    struct MarkerHandler(Arc<Mutex<Vec<VcpuOutcome>>>);

    impl VcpuHandler for MarkerHandler {
        fn exchange(&mut self, exit: VcpuExit) -> Result<VcpuAction, String> {
            Err(format!("unexpected native vCPU exit: {exit:?}"))
        }

        fn finished(&mut self, outcome: VcpuOutcome) {
            self.0
                .lock()
                .expect("record native vCPU outcome")
                .push(outcome);
        }
    }

    fn stage_guest(memory: &terra_platform::memory::GuestMemory) -> (BootState, u64) {
        #[cfg(target_arch = "x86_64")]
        {
            let entry = 0x1000;
            let marker = 0x2000;
            memory
                .write(
                    entry,
                    &[
                        0x48, 0xb8, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc7, 0x00,
                        0xa5, 0xa5, 0xa5, 0xa5, 0xeb, 0xfe,
                    ],
                )
                .expect("stage x86 marker loop");
            memory
                .write(terra_limits::X86_PML4_ADDR, &(0xa000_u64 | 3).to_le_bytes())
                .expect("stage x86 PML4");
            memory
                .write(0xa000, &(0xb000_u64 | 3).to_le_bytes())
                .expect("stage x86 page-directory pointer table");
            memory
                .write(0xb000, &(0x83_u64).to_le_bytes())
                .expect("stage x86 page directory");
            (
                BootState {
                    entry,
                    boot_argument: 0,
                },
                marker,
            )
        }
        #[cfg(target_arch = "aarch64")]
        {
            let entry = terra_limits::ARM_RAM_BASE;
            let marker = entry + 0x100;
            let code = [
                0xd2a8_0000_u32,
                0x5294_b4a1,
                0x72b4_b4a1,
                0xb901_0001,
                0x1400_0000,
            ];
            let bytes = code.map(u32::to_le_bytes).concat();
            memory.write(entry, &bytes).expect("stage ARM marker loop");
            (
                BootState {
                    entry,
                    boot_argument: 0,
                },
                marker,
            )
        }
    }

    fn marker_was_written(memory: &terra_platform::memory::GuestMemory, marker: u64) -> bool {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let bytes = memory
                .read(marker, std::mem::size_of::<u32>())
                .expect("read marker");
            if u32::from_le_bytes(bytes.try_into().expect("marker width")) == MARKER {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    #[ignore = "requires a native hypervisor"]
    fn native_vcpu_stop_is_repeatable_and_releases_its_vm() {
        let _native_hypervisor = NATIVE_HYPERVISOR.lock().expect("lock native hypervisor");
        let mut config = one_vcpu_config();
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        let vcpus = 1;
        #[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
        let vcpus = 2;
        config.vcpus = vcpus;
        let prepared = PreparedVm::create(&config, None).expect("prepare native VM");
        let memory = prepared.handle().memory();
        let (boot, marker) = stage_guest(&memory);
        let finished = Arc::new(Mutex::new(Vec::new()));
        let mut running = prepared
            .start(
                boot,
                (0..vcpus)
                    .map(|_| Box::new(MarkerHandler(Arc::clone(&finished))) as Box<dyn VcpuHandler>)
                    .collect(),
            )
            .expect("start native vCPU");
        let marker_was_written = marker_was_written(&memory, marker);
        running.request_stop();
        running.request_stop();
        let outcomes = running.join().expect("bounded native vCPU join");
        assert_eq!(outcomes.len(), usize::from(vcpus));
        assert!(outcomes.into_iter().all(|outcome| outcome.is_ok()));
        assert!(running.join().expect("repeat native vCPU join").is_empty());
        assert!(
            marker_was_written,
            "native vCPU did not execute marker loop"
        );
        assert!(
            finished
                .lock()
                .expect("read native vCPU outcome")
                .contains(&VcpuOutcome::Stopped)
        );
        drop(running);
        drop(memory);
        PreparedVm::create(&config, None).expect("recreate native VM after vCPU cleanup");
    }

    #[cfg(all(target_arch = "aarch64", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn arm_native_config_rejects_the_wrong_interrupt_controller_and_vcpu_count() {
        let mut config = one_vcpu_config();
        config.interrupt_controller = InterruptControllerConfig::X86;
        assert_eq!(
            PreparedVm::create(&config, None)
                .err()
                .expect("reject x86 controller"),
            "ARM interrupt controller required"
        );
        let mut config = one_vcpu_config();
        config.vcpus = 0;
        assert_eq!(
            PreparedVm::create(&config, None)
                .err()
                .expect("reject zero vCPUs"),
            "invalid vCPU count: 0"
        );
    }
}
