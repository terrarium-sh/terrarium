#![no_main]

use libfuzzer_sys::fuzz_target;
use terra_vsock_device::{VSOCK_HEADER_BYTES, VsockHeader};

fuzz_target!(|bytes: &[u8]| {
    match VsockHeader::parse(bytes) {
        Ok((header, payload)) => {
            assert!(bytes.len() >= VSOCK_HEADER_BYTES);
            assert_eq!(header.encode(), bytes[..VSOCK_HEADER_BYTES]);
            assert_eq!(payload, &bytes[VSOCK_HEADER_BYTES..]);
        }
        Err(_) => assert!(bytes.len() < VSOCK_HEADER_BYTES),
    }
});
