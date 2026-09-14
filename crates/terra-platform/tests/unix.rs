#![cfg(unix)]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use terra_runtime::engine::{DeviceHost, terra::host::memory::Host};

#[test]
fn hostile_memory_imports_cannot_cross_mapping_holes() {
    use std::sync::Arc;
    use terra_runtime::SyntheticRam;
    use vm_memory::{GuestAddress, GuestMemoryMmap};

    let mapping =
        GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096), (GuestAddress(8192), 4096)])
            .unwrap();
    let mut host = DeviceHost::with_ram(SyntheticRam::from_shared(Arc::new(mapping)).unwrap());
    host.write(0, vec![0xa5; 4096]).unwrap();
    assert!(host.read(4095, 4098).is_err());
    assert!(host.write(4095, vec![0; 4098]).is_err());
    assert_eq!(host.read(0, 4096).unwrap(), vec![0xa5; 4096]);
}
