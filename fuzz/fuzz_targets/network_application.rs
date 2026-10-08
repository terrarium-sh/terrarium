#![no_main]

use libfuzzer_sys::fuzz_target;
use terra_protocol::application::{Direction, MAX_FRAME_BYTES, Message, StreamDecoder};

fn decode_stream(bytes: &[u8], direction: Direction, chunk_bytes: usize) {
    let mut decoder = StreamDecoder::default();
    let mut consumed = 0;
    for chunk in bytes.chunks(chunk_bytes) {
        if decoder.push(chunk).is_err() {
            return;
        }
        while let Ok(Some(message)) = decoder.next(direction) {
            let encoded = message.encode();
            assert!(
                encoded
                    .as_ref()
                    .is_ok_and(|frame| frame.len() <= MAX_FRAME_BYTES)
            );
            if let Ok(frame) = encoded {
                assert_eq!(
                    Message::decode(&bytes[consumed..], direction),
                    Ok(Some((message, frame.len())))
                );
                assert_eq!(
                    bytes.get(consumed..consumed + frame.len()),
                    Some(frame.as_slice())
                );
                consumed += frame.len();
            }
        }
        assert!(decoder.remaining_capacity() <= MAX_FRAME_BYTES);
    }
    assert_eq!(
        decoder.next(direction),
        Message::decode(&bytes[consumed..], direction)
            .map(|frame| frame.map(|(message, _)| message))
    );
}

fuzz_target!(|bytes: &[u8]| {
    for direction in [Direction::GuestToHost, Direction::HostToGuest] {
        if let Ok(Some((message, length))) = Message::decode(bytes, direction) {
            assert!(length <= MAX_FRAME_BYTES);
            assert_eq!(message.encode().ok().as_deref(), bytes.get(..length));
        }
        for chunk_bytes in [
            1,
            usize::from(bytes.first().copied().unwrap_or(0)) + 1,
            MAX_FRAME_BYTES,
        ] {
            decode_stream(bytes, direction, chunk_bytes);
        }
    }
    let _ = terra_protocol::guest_image::validate_boot_image_extra(Some(bytes));
    let _ = terra_protocol::guest_image::validate_kernel_image_extra(Some(bytes));
});
