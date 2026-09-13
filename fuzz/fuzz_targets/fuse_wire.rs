#![no_main]

use libfuzzer_sys::fuzz_target;
use terra_fs_component::wire::{self, EINVAL, HEADER, OUT_HEADER};

fn u32_at(bytes: &[u8], start: usize) -> Option<u32> {
    bytes
        .get(start..start + 4)?
        .try_into()
        .ok()
        .map(u32::from_le_bytes)
}

fuzz_target!(|bytes: &[u8]| {
    match wire::request(bytes) {
        Ok(request) => {
            assert!(bytes.len() >= HEADER);
            assert!(u32_at(bytes, 0).is_some_and(|length| {
                usize::try_from(length).is_ok_and(|length| length >= HEADER)
            }));
            assert_eq!(
                u32::try_from(request.body.len() + HEADER).ok(),
                u32_at(bytes, 0)
            );
        }
        Err(error) => assert_eq!(error, EINVAL),
    }
    if let Ok(reply) = wire::init(bytes) {
        assert_eq!(reply.len(), wire::INIT_OUT);
        assert_eq!(u32_at(&reply, 0), Some(7));
    }
    let reply = wire::reply(17, EINVAL, bytes);
    assert_eq!(
        u32_at(&reply, 0).and_then(|length| usize::try_from(length).ok()),
        Some(OUT_HEADER + bytes.len())
    );
    assert_eq!(u32_at(&reply, 4), Some((-EINVAL).cast_unsigned()));
});
