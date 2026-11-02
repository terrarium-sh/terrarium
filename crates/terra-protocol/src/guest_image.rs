//! Protocol markers for trusted compressed guest artifacts.

#[derive(Clone, Copy)]
pub enum GuestImage {
    Boot,
    Kernel,
}

/// The marker's data after its gzip subfield ID and length: agent version and kernel ABI version.
const MARKER_DATA_BYTES: u8 = 3;
pub(crate) const MARKER_BYTES: usize = 4 + MARKER_DATA_BYTES as usize;

impl GuestImage {
    /// The gzip header subfield naming the agent protocol and kernel ABI an image was built for:
    /// its two-byte ID and length, then the agent version and kernel ABI version.
    #[must_use]
    pub const fn marker(self) -> [u8; MARKER_BYTES] {
        let (id, agent_version) = match self {
            Self::Boot => (*b"TB", crate::AGENT_PROTOCOL_VERSION),
            // The kernel image carries no agent.
            Self::Kernel => (*b"TK", 0),
        };
        let [abi_low, abi_high] = crate::kernel_abi::VERSION.to_le_bytes();
        [
            id[0],
            id[1],
            MARKER_DATA_BYTES,
            0,
            agent_version,
            abi_low,
            abi_high,
        ]
    }

    /// Whether `bytes` is exactly this kind's marker; `const` so an embedded image can be checked
    /// when it is compiled in.
    #[must_use]
    pub(crate) const fn is_marker(self, bytes: &[u8]) -> bool {
        let marker = self.marker();
        if bytes.len() != MARKER_BYTES {
            return false;
        }
        let mut index = 0;
        while index < MARKER_BYTES {
            if bytes[index] != marker[index] {
                return false;
            }
            index += 1;
        }
        true
    }

    pub fn validate(self, extra: Option<&[u8]>) -> std::io::Result<()> {
        if extra.is_some_and(|extra| self.is_marker(extra)) {
            return Ok(());
        }
        let image = match self {
            Self::Boot => "boot image",
            Self::Kernel => "kernel",
        };
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "guest {image} protocol marker is missing or incompatible; rebuild the kernel, agent, components, and runtime together"
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markers_pin_the_agent_protocol_and_kernel_abi_in_a_gzip_subfield() {
        let abi = crate::kernel_abi::VERSION.to_le_bytes();
        let boot = GuestImage::Boot.marker();
        assert_eq!(boot[..5], [b'T', b'B', 3, 0, crate::AGENT_PROTOCOL_VERSION]);
        assert_eq!(boot[5..], abi);
        let kernel = GuestImage::Kernel.marker();
        assert_eq!(kernel[..5], [b'T', b'K', 3, 0, 0]);
        assert_eq!(kernel[5..], abi);
        GuestImage::Boot.validate(Some(&boot)).unwrap();
        GuestImage::Kernel.validate(Some(&kernel)).unwrap();
        assert!(GuestImage::Kernel.validate(Some(&boot)).is_err());
        assert!(GuestImage::Boot.validate(Some(&kernel)).is_err());
    }

    #[test]
    fn missing_truncated_extended_or_changed_markers_are_rejected() {
        for (image, name) in [
            (GuestImage::Boot, "guest boot image"),
            (GuestImage::Kernel, "guest kernel"),
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
                let message = error.to_string();
                assert!(message.starts_with(name), "{message}");
                assert!(message.contains("rebuild the kernel, agent"), "{message}");
            }
        }
    }
}
