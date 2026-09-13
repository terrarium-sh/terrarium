//! Trusted Wasmtime component artifacts shared by VMM backends.

/// Build-embedded AOT artifacts for one exact Wasmtime runtime.
pub struct TrustedArtifacts {
    pub block: &'static [u8],
    pub vsock: &'static [u8],
    pub network: &'static [u8],
    pub fs: &'static [u8],
    pub mem: &'static [u8],
    pub boot: &'static [u8],
    pub mmio: &'static [u8],
}

impl TrustedArtifacts {
    /// # Safety
    ///
    /// All byte slices must be trusted AOT artifacts produced for this exact
    /// Wasmtime build; they must never come from a user or network input.
    #[must_use]
    #[allow(unsafe_code)]
    pub const unsafe fn new(
        block: &'static [u8],
        vsock: &'static [u8],
        network: &'static [u8],
        fs: &'static [u8],
        mem: &'static [u8],
        boot: &'static [u8],
        mmio: &'static [u8],
    ) -> Self {
        Self {
            block,
            vsock,
            network,
            fs,
            mem,
            boot,
            mmio,
        }
    }
}
