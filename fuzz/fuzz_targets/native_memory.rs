#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use terra_runtime::SyntheticRam;
use terra_runtime::component::block::host::terra::host::memory::Host;
use terra_runtime::component::vmm::{
    boot::BootEntry,
    virtualization::{Architecture, MachineConfig, PreparedMachine, VirtualMachine},
};
use terra_runtime::engine::DeviceContext;

#[derive(Arbitrary, Debug)]
struct Input {
    offset: u64,
    length: u64,
    bytes: Vec<u8>,
}

struct Machine(SyntheticRam);

impl VirtualMachine for Machine {
    fn memory(&self) -> wasmtime::Result<SyntheticRam> {
        Ok(self.0.clone())
    }
}

fuzz_target!(|input: Input| {
    let Some(mut host) = DeviceContext::new(4096) else {
        return;
    };
    let Ok(before) = host.read(0, 4096) else {
        return;
    };
    if host.write(input.offset, input.bytes.clone()).is_err() {
        assert_eq!(host.read(0, 4096), Ok(before));
    } else {
        assert_eq!(
            host.read(input.offset, input.bytes.len() as u64),
            Ok(input.bytes)
        );
    }
    if let Ok(bytes) = host.read(input.offset, input.length) {
        assert_eq!(bytes.len() as u64, input.length);
        assert!(
            input
                .offset
                .checked_add(input.length)
                .is_some_and(|end| end <= 4096)
        );
    }
    let Some(ram) = SyntheticRam::new(4096) else {
        return;
    };
    let Ok(config) = MachineConfig::new(Architecture::Arm, 4096, 1, Vec::new()) else {
        return;
    };
    let mut prepared = PreparedMachine::new(config, Machine(ram));
    let entry = BootEntry {
        entry: input.offset,
        boot_argument: input.length,
    };
    if prepared.accept_boot(entry).is_ok() {
        assert!(input.offset < 4096 && input.offset.is_multiple_of(4));
        assert_eq!(input.length, 0);
        assert!(prepared.accept_boot(entry).is_err());
    }
});
