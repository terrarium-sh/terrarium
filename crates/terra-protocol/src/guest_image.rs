//! Protocol markers for trusted compressed guest artifacts.

#[derive(Clone, Copy)]
pub enum GuestImage {
    Boot,
    Kernel,
}

/// Bumps when a marker's layout changes.
const MARKER_FORMAT: u8 = 4;
pub const MARKER_BYTES: usize = 8;

impl GuestImage {
    /// The gzip header subfield naming the agent protocol and kernel ABI an image was built for:
    /// its two-byte ID and length, then the marker format, agent version, and kernel ABI version.
    #[must_use]
    pub fn marker(self) -> [u8; MARKER_BYTES] {
        let (id, agent_version) = match self {
            Self::Boot => (*b"TB", crate::AGENT_PROTOCOL_VERSION),
            // The kernel image carries no agent.
            Self::Kernel => (*b"TK", 0),
        };
        let [abi_low, abi_high] = crate::kernel_abi::VERSION.to_le_bytes();
        [
            id[0],
            id[1],
            4,
            0,
            MARKER_FORMAT,
            agent_version,
            abi_low,
            abi_high,
        ]
    }

    pub fn validate(self, extra: Option<&[u8]>) -> std::io::Result<()> {
        if extra == Some(self.marker().as_slice()) {
            return Ok(());
        }
        let message = match self {
            Self::Boot => {
                "guest boot image protocol marker is missing or incompatible; rebuild the kernel, agent, components, and runtime together"
            }
            Self::Kernel => {
                "guest kernel protocol marker is missing or incompatible; rebuild the matching kernel, agent, components, and runtime together"
            }
        };
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            message,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};

    #[test]
    fn markers_pin_the_agent_protocol_and_kernel_abi_in_a_gzip_subfield() {
        let abi = crate::kernel_abi::VERSION.to_le_bytes();
        let boot = GuestImage::Boot.marker();
        assert_eq!(
            boot[..6],
            [
                b'T',
                b'B',
                4,
                0,
                MARKER_FORMAT,
                crate::AGENT_PROTOCOL_VERSION
            ]
        );
        assert_eq!(boot[6..], abi);
        let kernel = GuestImage::Kernel.marker();
        assert_eq!(kernel[..6], [b'T', b'K', 4, 0, MARKER_FORMAT, 0]);
        assert_eq!(kernel[6..], abi);
        GuestImage::Boot.validate(Some(&boot)).unwrap();
        GuestImage::Kernel.validate(Some(&kernel)).unwrap();
        assert!(GuestImage::Kernel.validate(Some(&boot)).is_err());
        assert!(GuestImage::Boot.validate(Some(&kernel)).is_err());
    }

    #[test]
    fn missing_truncated_extended_or_changed_markers_are_rejected() {
        for (image, rebuild_hint) in [
            (GuestImage::Boot, "rebuild the kernel, agent"),
            (GuestImage::Kernel, "rebuild the matching"),
        ] {
            let extra = image.marker();
            assert!(image.validate(None).is_err());
            for length in 0..extra.len() {
                assert!(image.validate(Some(&extra[..length])).is_err());
            }
            let mut extended = extra.to_vec();
            extended.push(0);
            assert!(image.validate(Some(&extended)).is_err());
            for index in 0..extra.len() {
                let mut changed = extra;
                changed[index] ^= 1;
                let error = image.validate(Some(&changed)).unwrap_err();
                assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
                assert!(error.to_string().contains(rebuild_hint));
            }
        }
    }

    #[test]
    fn marked_gzip_remains_deterministic_and_decodes_as_an_ordinary_image() {
        for extra in [GuestImage::Boot.marker(), GuestImage::Kernel.marker()] {
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
