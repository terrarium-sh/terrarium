#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use terra_device_transport::{
    MmioTransport, SPLIT_RING_DESC_F_NEXT, count_pending_queue_entries, split_ring_chain,
};

#[derive(Arbitrary, Debug)]
struct Operation {
    address: u64,
    data: Vec<u8>,
    read_len: u8,
}

fuzz_target!(|data: &[u8]| {
    let mut input = Unstructured::new(data);
    let Ok((next, available, size, head, max_descriptors)) =
        input.arbitrary::<(u16, u16, u16, u16, u8)>()
    else {
        return;
    };
    if let Some(count) = count_pending_queue_entries(next, available, size) {
        assert_ne!(size, 0);
        assert!(count <= size);
        assert_eq!(count, available.wrapping_sub(next));
    }
    if let Ok(chain) = split_ring_chain(
        data,
        head,
        size,
        usize::from(max_descriptors),
        SPLIT_RING_DESC_F_NEXT,
    ) {
        assert!(chain.len() <= usize::from(max_descriptors));
        let Some((last, preceding)) = chain.split_last() else {
            return;
        };
        for descriptor in preceding {
            assert_ne!(descriptor.flags & SPLIT_RING_DESC_F_NEXT, 0);
        }
        assert_eq!(last.flags & SPLIT_RING_DESC_F_NEXT, 0);
    }

    let mut transport = MmioTransport::new(0x1000, 0x2000, 0x4000, 2, u64::MAX, 256, vec![0; 8])
        .with_queue_count(4);
    let Ok(operations) = input.arbitrary_iter::<Operation>() else {
        return;
    };
    for operation in operations.take(64).flatten() {
        let _ = transport.write(operation.address, &operation.data);
        let _ = transport.read(operation.address, usize::from(operation.read_len));
    }
});
