#![allow(clippy::expect_used, clippy::unwrap_used)]

use terra_runtime::component::block::backing::BoundedDisk;
use terra_runtime::component::block::backing::DiskError;
use terra_runtime::component::block::backing::{BackingError, BlockBacking, FileDisk};
use terra_runtime::component::context::DeviceContext;
use terra_runtime::component::context::InterruptSignals;
use terra_runtime::component::context::MAX_SIGNALS_PER_WINDOW;
use terra_runtime::component::context::MemoryHost as _;
use terra_runtime::memory::MemoryError;
use terra_runtime::memory::{BoundedMemory, GuestRam};

#[test]
fn hostile_memory_imports_reject_overflow_and_oversized_copies() {
    let mut host = DeviceContext::new(4096).unwrap();
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
    assert_eq!(readonly.discard(0, 1), Err(BackingError::ReadOnly));
    assert_eq!(writable.discard(4096, 1), Err(BackingError::OutOfRange));
    writable.discard(4095, 1).unwrap();
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

#[cfg(target_os = "linux")]
#[test]
fn file_discard_reclaims_allocated_blocks() {
    use std::os::unix::fs::MetadataExt as _;

    let file = tempfile::NamedTempFile::new().unwrap();
    file.as_file().set_len(1 << 20).unwrap();
    let mut disk = FileDisk::open(file.path(), false).unwrap();
    disk.write_at(0, &vec![0xa5; 128 << 10]).unwrap();
    let allocated = file.as_file().metadata().unwrap().blocks();
    disk.discard(0, 128 << 10).unwrap();
    assert!(file.as_file().metadata().unwrap().blocks() < allocated);
}

#[cfg(windows)]
#[test]
fn file_discard_reclaims_allocated_bytes() {
    let file = tempfile::NamedTempFile::new().unwrap();
    file.as_file().set_len(1 << 20).unwrap();
    let mut disk = FileDisk::open(file.path(), false).unwrap();
    disk.write_at(0, &vec![0xa5; 128 << 10]).unwrap();
    let allocated = read_allocated_bytes(file.as_file());
    disk.discard(0, 128 << 10).unwrap();
    assert!(read_allocated_bytes(file.as_file()) < allocated);
}

#[cfg(windows)]
fn read_allocated_bytes(file: &std::fs::File) -> u64 {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_STANDARD_INFO, FileStandardInfo, GetFileInformationByHandleEx,
    };

    let mut info = FILE_STANDARD_INFO::default();
    #[allow(unsafe_code)]
    let result = unsafe {
        // SAFETY: `file` owns the handle and `info` has the exact output-buffer size.
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileStandardInfo,
            (&raw mut info).cast(),
            u32::try_from(core::mem::size_of::<FILE_STANDARD_INFO>()).unwrap(),
        )
    };
    assert_ne!(result, 0);
    u64::try_from(info.AllocationSize).unwrap()
}

#[test]
fn boot_results_require_mapped_aligned_addresses_and_one_acceptance() {
    use terra_runtime::component::vmm::{BootEntry, PreparedMachine, VirtualMachine};
    use terra_runtime::machine::{Architecture, MachineConfig};
    struct Machine(terra_runtime::memory::GuestRam);
    impl VirtualMachine for Machine {
        fn memory(&self) -> wasmtime::Result<terra_runtime::memory::GuestRam> {
            Ok(self.0.clone())
        }
    }
    let config = MachineConfig::new(Architecture::Arm, 4096, 1, Vec::new()).unwrap();
    let mut machine = PreparedMachine::new(
        config,
        Machine(terra_runtime::memory::GuestRam::new(4096).unwrap()),
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

fn ram_64k() -> GuestRam {
    GuestRam::new(64 * 1024).expect("64 KiB RAM")
}

#[test]
fn oob_read_fails_closed() {
    let ram = ram_64k();
    let mem = BoundedMemory::new(&ram);
    assert_eq!(
        mem.read(ram.address_limit(), 1),
        Err(MemoryError::OutOfRange)
    );
    assert_eq!(
        mem.read(0, ram.address_limit() + 1),
        Err(MemoryError::TooLarge)
    );
}

#[test]
fn offset_plus_len_overflow_fails_closed() {
    let ram = ram_64k();
    let mem = BoundedMemory::new(&ram);
    assert_eq!(mem.read(u64::MAX - 4, 16), Err(MemoryError::OutOfRange));
}

#[test]
fn round_trip_through_synthetic_ram() {
    let ram = ram_64k();
    let mem = BoundedMemory::new(&ram);
    mem.write(128, b"virtio").expect("in-range write");
    assert_eq!(mem.read(128, 6).expect("in-range read"), b"virtio");
}

#[test]
fn nonzero_guest_base_keeps_capacity_and_address_bounds_distinct() {
    use terra_platform::memory::GuestMemory;

    let ram = GuestRam::from_memory(GuestMemory::allocate_at(0x10_0000, 0x4000).expect("RAM"));
    let memory = BoundedMemory::new(&ram);

    assert_eq!(ram.mapped_bytes(), 0x4000);
    assert_eq!(ram.address_limit(), 0x10_4000);
    memory.write(0x10_0000, b"RAM").expect("mapped write");
    assert_eq!(memory.read(0x10_0000, 3).expect("mapped read"), b"RAM");
    assert_eq!(memory.read(0, 1), Err(MemoryError::OutOfRange));
    assert_eq!(
        memory.read(ram.address_limit(), 1),
        Err(MemoryError::OutOfRange)
    );
}

#[test]
fn readonly_disk_resists_writes_and_truncation() {
    let mut disk = BoundedDisk::new(4096, true);
    assert_eq!(disk.write(0, b"x"), Err(DiskError::ReadOnly));
    assert!(disk.read(0, 4).is_ok());
    assert_eq!(disk.read(4090, 16), Err(DiskError::OutOfRange));
}

#[test]
fn writable_disk_enforces_capacity() {
    let mut disk = BoundedDisk::new(512, false);
    disk.write(0, &[7u8; 16]).expect("in-capacity write");
    assert_eq!(disk.write(500, &[7u8; 16]), Err(DiskError::OutOfRange));
}

#[test]
fn interrupt_storm_coalesces_and_drops() {
    let mut irq = InterruptSignals::new();
    for _ in 0..(MAX_SIGNALS_PER_WINDOW + 10) {
        irq.signal();
    }
    assert!(irq.take());
    assert!(!irq.take());
    assert_eq!(irq.delivered(), 1);
    assert_eq!(irq.dropped(), 10);
    irq.end_window();
    irq.signal();
    assert!(irq.take());
}

#[cfg(unix)]
#[test]
fn memory_hole_is_rejected_before_partial_write() {
    use terra_platform::memory::GuestMemory;
    let ram =
        GuestRam::from_memory(GuestMemory::from_ranges(&[(0, 0x1000), (0x2000, 0x1000)]).unwrap());
    let memory = BoundedMemory::new(&ram);
    memory.write(0xff0, &[0x42; 16]).unwrap();
    assert_eq!(memory.write(0xff0, &[0x99; 32]), Err(MemoryError::Unmapped));
    assert_eq!(memory.read(0xff0, 16).unwrap(), vec![0x42; 16]);
}

#[cfg(unix)]
#[test]
fn hostile_memory_imports_cannot_cross_mapping_holes() {
    use terra_platform::memory::GuestMemory;
    use terra_runtime::memory::GuestRam;

    let ram = GuestRam::from_memory(GuestMemory::from_ranges(&[(0, 4096), (8192, 4096)]).unwrap());
    let mut host = DeviceContext::with_ram(ram);
    host.write(0, vec![0xa5; 4096]).unwrap();
    assert!(host.read(4095, 4098).is_err());
    assert!(host.write(4095, vec![0; 4098]).is_err());
    assert_eq!(host.read(0, 4096).unwrap(), vec![0xa5; 4096]);
}

#[test]
fn synthetic_ram_shapes_match() {
    assert!(GuestRam::new(256 * 1024).is_some());
}

#[cfg(unix)]
#[test]
fn shared_ram_aliases_one_mapping() {
    use terra_platform::memory::GuestMemory;
    let mem = GuestMemory::allocate(64 * 1024).expect("maps");
    let first = GuestRam::from_memory(mem.clone());
    let second = GuestRam::from_memory(mem.clone());
    assert_eq!(first.address_limit(), 64 * 1024);
    BoundedMemory::new(&first)
        .write(512, b"shared")
        .expect("writes");
    assert_eq!(
        BoundedMemory::new(&second).read(512, 6).expect("reads"),
        b"shared"
    );
    assert_eq!(mem.read(512, 6).expect("mapped"), b"shared");
}
