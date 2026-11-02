#![no_main]

use libfuzzer_sys::fuzz_target;
use terra_protocol::application::{
    Frame as _, GuestFrame, HostFrame, MAX_FRAME_BYTES, StreamDecoder,
};

/// Checks one direction's frame type: single decodes re-encode to the bytes they came from, and a
/// stream decoder agrees with them at any read size.
macro_rules! direction_checks {
    ($check:ident, $decode_stream:ident, $frame:ident, $udp_run:ident) => {
        fn $decode_stream(bytes: &[u8], chunk_bytes: usize) {
            let decode_owned = |bytes: &[u8]| {
                $frame::decode(bytes)
                    .map(|decoded| decoded.map(|(frame, length)| (frame.into_owned(), length)))
            };
            let mut decoder = StreamDecoder::default();
            let mut consumed = 0;
            for chunk in bytes.chunks(chunk_bytes) {
                let buffer = decoder.read_buffer();
                if buffer.len() < chunk.len() {
                    return;
                }
                buffer[..chunk.len()].copy_from_slice(chunk);
                decoder.commit(chunk.len());
                while let Ok(Some(frame)) = decoder
                    .next_frame::<$frame<&[u8]>>()
                    .map(|frame| frame.map($frame::into_owned))
                {
                    let encoded = frame.encode();
                    assert!(
                        encoded
                            .as_ref()
                            .is_ok_and(|encoded| encoded.len() <= MAX_FRAME_BYTES)
                    );
                    if let Ok(encoded) = encoded {
                        assert_eq!(
                            decode_owned(&bytes[consumed..]),
                            Ok(Some((frame, encoded.len())))
                        );
                        assert_eq!(
                            bytes.get(consumed..consumed + encoded.len()),
                            Some(encoded.as_slice())
                        );
                        consumed += encoded.len();
                    }
                }
            }
            assert_eq!(
                decoder
                    .next_frame::<$frame<&[u8]>>()
                    .map(|frame| frame.map($frame::into_owned)),
                decode_owned(&bytes[consumed..]).map(|decoded| decoded.map(|(frame, _)| frame))
            );
        }

        fn $check(bytes: &[u8]) {
            if let Ok(Some((frame, length))) = $frame::decode(bytes) {
                assert!(length <= MAX_FRAME_BYTES);
                if let $frame::$udp_run(run) = &frame {
                    assert!(
                        bytes[..length].as_ptr_range().contains(&run.bytes.as_ptr())
                            || run.bytes.is_empty()
                    );
                }
                assert_eq!(
                    frame.into_owned().encode().ok().as_deref(),
                    bytes.get(..length)
                );
            }
            for chunk_bytes in [
                1,
                usize::from(bytes.first().copied().unwrap_or(0)) + 1,
                MAX_FRAME_BYTES,
            ] {
                $decode_stream(bytes, chunk_bytes);
            }
        }
    };
}

direction_checks!(check_guest, decode_guest_stream, GuestFrame, UdpSend);
direction_checks!(check_host, decode_host_stream, HostFrame, UdpDatagram);

fuzz_target!(|bytes: &[u8]| {
    check_guest(bytes);
    check_host(bytes);
});
