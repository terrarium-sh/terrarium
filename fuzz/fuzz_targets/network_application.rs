#![no_main]

use libfuzzer_sys::fuzz_target;
use terra_protocol::application::{
    Frame, GuestFrame, HostFrame, LentFrame, MAX_FRAME_BYTES, StreamDecoder,
};

fn decode_stream<F: Frame + std::fmt::Debug + PartialEq>(bytes: &[u8], chunk_bytes: usize) {
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
            .next_lent_frame::<F>()
            .map(|frame| frame.map(LentFrame::into_owned))
        {
            let encoded = frame.encode();
            assert!(
                encoded
                    .as_ref()
                    .is_ok_and(|encoded| encoded.len() <= MAX_FRAME_BYTES)
            );
            if let Ok(encoded) = encoded {
                assert_eq!(
                    F::decode(&bytes[consumed..]),
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
            .next_lent_frame::<F>()
            .map(|frame| frame.map(LentFrame::into_owned)),
        F::decode(&bytes[consumed..]).map(|decoded| decoded.map(|(frame, _)| frame))
    );
}

fn check_direction<F: Frame + std::fmt::Debug + PartialEq>(bytes: &[u8]) {
    if let Ok(Some((frame, length))) = F::decode(bytes) {
        assert!(length <= MAX_FRAME_BYTES);
        assert_eq!(frame.encode().ok().as_deref(), bytes.get(..length));
    }
    if let Ok(Some((LentFrame::UdpRun(run), length))) = F::decode_lent(bytes) {
        assert!(
            bytes[..length].as_ptr_range().contains(&run.bytes.as_ptr()) || run.bytes.is_empty()
        );
        assert_eq!(
            F::decode(bytes),
            Ok(Some((F::from_udp_run(run.into_owned()), length)))
        );
    }
    for chunk_bytes in [
        1,
        usize::from(bytes.first().copied().unwrap_or(0)) + 1,
        MAX_FRAME_BYTES,
    ] {
        decode_stream::<F>(bytes, chunk_bytes);
    }
}

fuzz_target!(|bytes: &[u8]| {
    check_direction::<GuestFrame>(bytes);
    check_direction::<HostFrame>(bytes);
    let _ = terra_protocol::guest_image::GuestImage::Boot.validate(Some(bytes));
    let _ = terra_protocol::guest_image::GuestImage::Kernel.validate(Some(bytes));
});
