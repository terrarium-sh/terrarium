//! Trusted Wasmtime component artifacts shared by VMM backends.

/// Build-embedded AOT artifacts for one exact Wasmtime runtime.
pub struct TrustedArtifacts {
    block: &'static [u8],
    vsock: &'static [u8],
    network: &'static [u8],
    fs: &'static [u8],
    mem: &'static [u8],
    boot: &'static [u8],
    mmio: &'static [u8],
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

    #[must_use]
    pub const fn block(&self) -> &'static [u8] {
        self.block
    }

    #[must_use]
    pub const fn vsock(&self) -> &'static [u8] {
        self.vsock
    }

    #[must_use]
    pub const fn network(&self) -> &'static [u8] {
        self.network
    }

    #[must_use]
    pub const fn fs(&self) -> &'static [u8] {
        self.fs
    }

    #[must_use]
    pub const fn mem(&self) -> &'static [u8] {
        self.mem
    }

    #[must_use]
    pub const fn boot(&self) -> &'static [u8] {
        self.boot
    }

    #[must_use]
    pub const fn mmio(&self) -> &'static [u8] {
        self.mmio
    }
}
