//! Protocol markers for trusted compressed guest artifacts.

#[must_use]
pub fn boot_image_extra() -> [u8; 12] {
    let mut extra = [0; 12];
    extra[..4].copy_from_slice(b"TB\x08\0");
    extra[4] = 2;
    extra[5] = crate::AGENT_PROTOCOL_VERSION;
    extra[6..8].copy_from_slice(b"VS");
    extra[8..10].copy_from_slice(&crate::socket::VERSION.to_le_bytes());
    extra[10..12].copy_from_slice(&crate::vsock::VERSION.to_le_bytes());
    extra
}

pub fn validate_boot_image_extra(extra: Option<&[u8]>) -> std::io::Result<()> {
    if extra != Some(boot_image_extra().as_slice()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "guest boot image protocol marker is missing or incompatible; rebuild the kernel, agent, components, and runtime together",
        ));
    }
    Ok(())
}

#[must_use]
pub fn kernel_image_extra() -> [u8; 12] {
    let mut extra = [0; 12];
    extra[..6].copy_from_slice(b"TK\x08\0VS");
    extra[6..8].copy_from_slice(&crate::socket::VERSION.to_le_bytes());
    extra[8..10].copy_from_slice(&crate::application::VERSION.to_le_bytes());
    extra[10..12].copy_from_slice(&crate::vsock::VERSION.to_le_bytes());
    extra
}

pub fn validate_kernel_image_extra(extra: Option<&[u8]>) -> std::io::Result<()> {
    if extra != Some(kernel_image_extra().as_slice()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "guest kernel protocol marker is missing or incompatible; rebuild the matching kernel, agent, components, and runtime together",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};

    #[test]
    fn marker_pins_current_protocols_and_standard_gzip_subfield_layout() {
        let extra = boot_image_extra();
        assert_eq!(&extra[..5], b"TB\x08\0\x02");
        assert_eq!(extra[5], crate::AGENT_PROTOCOL_VERSION);
        assert_eq!(&extra[6..8], b"VS");
        assert_eq!(&extra[8..10], &crate::socket::VERSION.to_le_bytes());
        assert_eq!(&extra[10..], &crate::vsock::VERSION.to_le_bytes());
        validate_boot_image_extra(Some(&extra)).unwrap();
    }

    #[test]
    fn missing_truncated_extended_or_changed_markers_are_rejected() {
        let extra = boot_image_extra();
        assert!(validate_boot_image_extra(None).is_err());
        for length in 0..extra.len() {
            assert!(validate_boot_image_extra(Some(&extra[..length])).is_err());
        }
        let mut extended = extra.to_vec();
        extended.push(0);
        assert!(validate_boot_image_extra(Some(&extended)).is_err());
        for index in 0..extra.len() {
            let mut changed = extra;
            changed[index] ^= 1;
            let error = validate_boot_image_extra(Some(&changed)).unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
            assert!(error.to_string().contains("rebuild"));
        }
    }

    #[test]
    fn kernel_marker_pins_socket_application_and_vsock_versions() {
        let extra = kernel_image_extra();
        assert_eq!(&extra[..6], b"TK\x08\0VS");
        assert_eq!(&extra[6..8], &crate::socket::VERSION.to_le_bytes());
        assert_eq!(&extra[8..10], &crate::application::VERSION.to_le_bytes());
        assert_eq!(&extra[10..], &crate::vsock::VERSION.to_le_bytes());
        validate_kernel_image_extra(Some(&extra)).unwrap();
        assert!(validate_kernel_image_extra(Some(&boot_image_extra())).is_err());
        assert!(validate_boot_image_extra(Some(&extra)).is_err());
    }

    #[test]
    fn kernel_rejects_missing_truncated_extended_and_changed_markers() {
        let extra = kernel_image_extra();
        assert!(validate_kernel_image_extra(None).is_err());
        for length in 0..extra.len() {
            assert!(validate_kernel_image_extra(Some(&extra[..length])).is_err());
        }
        let mut extended = extra.to_vec();
        extended.push(0);
        assert!(validate_kernel_image_extra(Some(&extended)).is_err());
        for index in 0..extra.len() {
            let mut changed = extra;
            changed[index] ^= 1;
            let error = validate_kernel_image_extra(Some(&changed)).unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
            assert!(error.to_string().contains("rebuild the matching"));
        }
    }

    #[test]
    fn marked_gzip_remains_deterministic_and_decodes_as_an_ordinary_image() {
        for extra in [boot_image_extra(), kernel_image_extra()] {
            let image = b"guest artifact payload";
            let compress = || {
                let mut encoder = flate2::GzBuilder::new()
                    .mtime(0)
                    .extra(extra.to_vec())
                    .write(Vec::new(), flate2::Compression::best());
                encoder.write_all(image).unwrap();
                encoder.finish().unwrap()
            };
            let compressed = compress();
            assert_eq!(compressed, compress());
            let mut decoder = flate2::read::GzDecoder::new(compressed.as_slice());
            let header = decoder.header().unwrap();
            assert_eq!(header.mtime(), 0);
            assert_eq!(header.extra(), Some(extra.as_slice()));
            let mut restored_image = Vec::new();
            decoder.read_to_end(&mut restored_image).unwrap();
            assert_eq!(restored_image, image);
        }
    }
}
