#![allow(clippy::unwrap_used)]

use terra_runtime::component::block::backing::{BackingError, BlockBacking, FileDisk};
use terra_runtime::engine::{DeviceHost, terra::host::memory::Host};

#[test]
fn hostile_memory_imports_reject_overflow_and_oversized_copies() {
    let mut host = DeviceHost::new(4096).unwrap();
    host.write(0, vec![0xa5; 4096]).unwrap();
    for (offset, length) in [(u64::MAX, 2), (4095, 2), (0, u64::MAX)] {
        assert!(host.read(offset, length).is_err());
    }
    assert!(host.write(u64::MAX, vec![0; 2]).is_err());
    assert!(host.write(0, vec![0; 16 * 1024 + 1]).is_err());
    assert_eq!(host.read(0, 4096).unwrap(), vec![0xa5; 4096]);
}

#[test]
fn file_grants_enforce_capacity_and_readonly_independently_of_wasm() {
    let file = tempfile::NamedTempFile::new().unwrap();
    file.as_file().set_len(4096).unwrap();
    let mut writable = FileDisk::open(file.path(), false).unwrap();
    let mut readonly = FileDisk::open(file.path(), true).unwrap();
    writable.write_at(4095, &[0xa5]).unwrap();
    for offset in [4096, u64::MAX] {
        assert_eq!(
            writable.write_at(offset, &[0]),
            Err(BackingError::OutOfRange)
        );
        assert_eq!(
            writable.read_at(offset, &mut [0]),
            Err(BackingError::OutOfRange)
        );
    }
    assert_eq!(readonly.write_at(0, &[0]), Err(BackingError::ReadOnly));
    let mut last = [0];
    readonly.read_at(4095, &mut last).unwrap();
    assert_eq!(last, [0xa5]);
    assert_eq!(file.as_file().metadata().unwrap().len(), 4096);
}

#[test]
fn file_grants_retain_the_opened_file_after_path_replacement() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("disk");
    std::fs::write(&path, [1; 16]).unwrap();
    let mut disk = FileDisk::open(&path, false).unwrap();
    std::fs::rename(&path, directory.path().join("original")).unwrap();
    std::fs::write(&path, [2; 16]).unwrap();
    disk.write_at(0, &[3]).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), [2; 16]);
    assert_eq!(
        std::fs::read(directory.path().join("original")).unwrap()[0],
        3
    );
    let null_device = if cfg!(windows) { "NUL" } else { "/dev/null" };
    assert!(FileDisk::open(std::path::Path::new(null_device), false).is_err());
}

#[test]
fn boot_results_require_mapped_aligned_addresses_and_one_acceptance() {
    use terra_runtime::component::vmm::{
        boot::BootEntry,
        virtualization::{Architecture, MachineConfig, PreparedMachine, VirtualMachine},
    };
    struct Machine(terra_runtime::SyntheticRam);
    impl VirtualMachine for Machine {
        fn memory(&self) -> wasmtime::Result<terra_runtime::SyntheticRam> {
            Ok(self.0.clone())
        }
    }
    let config = MachineConfig::new(Architecture::Arm, 4096, 1, Vec::new()).unwrap();
    let mut machine = PreparedMachine::new(
        config,
        Machine(terra_runtime::SyntheticRam::new(4096).unwrap()),
    );
    for (entry, boot_argument) in [(u64::MAX, 0), (4096, 0), (1, 0), (0, 4096), (0, u64::MAX)] {
        assert!(
            machine
                .accept_boot(BootEntry {
                    entry,
                    boot_argument
                })
                .is_err()
        );
    }
    machine
        .accept_boot(BootEntry {
            entry: 0,
            boot_argument: 0,
        })
        .unwrap();
    assert!(
        machine
            .accept_boot(BootEntry {
                entry: 0,
                boot_argument: 0
            })
            .is_err()
    );
}
