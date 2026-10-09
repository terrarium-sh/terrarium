#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use terra_device_transport::{
    MmioTransport, SPLIT_RING_DESC_F_NEXT, resync_pending_queue_entries, split_ring_chain,
};

#[derive(Arbitrary, Debug)]
struct Operation {
    address: u64,
    width: u8,
    value: u64,
    read_len: u8,
}

fuzz_target!(|data: &[u8]| {
    let mut input = Unstructured::new(data);
    let Ok((next, available, size, head, max_descriptors)) =
        input.arbitrary::<(u16, u16, u16, u16, u8)>()
    else {
        return;
    };
    let mut cursor = next;
    let count = resync_pending_queue_entries(&mut cursor, available, size);
    if size != 0 && available.wrapping_sub(next) <= size {
        assert_eq!(count, available.wrapping_sub(next));
        assert_eq!(cursor, next);
    } else {
        assert_eq!(count, 0);
        assert_eq!(cursor, available);
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

    let mut transport =
        MmioTransport::new(0x4000, 2, u64::MAX, 256, vec![0; 8]).with_queue_count(4);
    let Ok(operations) = input.arbitrary_iter::<Operation>() else {
        return;
    };
    for operation in operations.take(64).flatten() {
        let _ = transport.write(operation.address, operation.width, operation.value);
        let _ = transport.read(operation.address, operation.read_len);
    }
});
