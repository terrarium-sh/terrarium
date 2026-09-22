//! Trusted Wasmtime component artifacts shared by VMM backends.

/// Trusted AOT artifact for one exact Wasmtime runtime.
#[derive(Clone, Copy)]
pub struct TrustedArtifact(&'static [u8]);

#[allow(unsafe_code)]
impl TrustedArtifact {
    /// # Safety
    ///
    /// `bytes` must be trusted AOT output produced for this exact Wasmtime
    /// build; it must never come from a user or network input.
    #[must_use]
    pub const unsafe fn from_trusted_bytes(bytes: &'static [u8]) -> Self {
        Self(bytes)
    }

    pub fn deserialize(
        self,
        engine: &wasmtime::Engine,
    ) -> wasmtime::Result<wasmtime::component::Component> {
        // SAFETY: TrustedArtifact is constructed only from trusted AOT output for this runtime.
        unsafe { wasmtime::component::Component::deserialize(engine, self.0) }
    }
}

/// Build-embedded AOT artifacts for one exact Wasmtime runtime.
pub struct TrustedArtifacts {
    block: TrustedArtifact,
    vsock: TrustedArtifact,
    network: TrustedArtifact,
    fs: TrustedArtifact,
    mem: TrustedArtifact,
    boot: TrustedArtifact,
    vmm: TrustedArtifact,
    mmio: TrustedArtifact,
    interrupt_controller: TrustedArtifact,
}

impl TrustedArtifacts {
    /// # Safety
    ///
    /// All byte slices must be trusted AOT artifacts produced for this exact
    /// Wasmtime build; they must never come from a user or network input.
    #[must_use]
    #[allow(unsafe_code, clippy::too_many_arguments)]
    pub const unsafe fn new(
        block: &'static [u8],
        vsock: &'static [u8],
        network: &'static [u8],
        fs: &'static [u8],
        mem: &'static [u8],
        boot: &'static [u8],
        vmm: &'static [u8],
        mmio: &'static [u8],
        interrupt_controller: &'static [u8],
    ) -> Self {
        Self {
            block: TrustedArtifact(block),
            vsock: TrustedArtifact(vsock),
            network: TrustedArtifact(network),
            fs: TrustedArtifact(fs),
            mem: TrustedArtifact(mem),
            boot: TrustedArtifact(boot),
            vmm: TrustedArtifact(vmm),
            mmio: TrustedArtifact(mmio),
            interrupt_controller: TrustedArtifact(interrupt_controller),
        }
    }

    #[must_use]
    pub const fn block(&self) -> TrustedArtifact {
        self.block
    }

    #[must_use]
    pub const fn vsock(&self) -> TrustedArtifact {
        self.vsock
    }

    #[must_use]
    pub const fn network(&self) -> TrustedArtifact {
        self.network
    }

    #[must_use]
    pub const fn fs(&self) -> TrustedArtifact {
        self.fs
    }

    #[must_use]
    pub const fn mem(&self) -> TrustedArtifact {
        self.mem
    }

    #[must_use]
    pub const fn boot(&self) -> TrustedArtifact {
        self.boot
    }

    #[must_use]
    pub const fn mmio(&self) -> TrustedArtifact {
        self.mmio
    }

    #[must_use]
    pub const fn interrupt_controller(&self) -> TrustedArtifact {
        self.interrupt_controller
    }

    #[must_use]
    pub const fn vmm(&self) -> TrustedArtifact {
        self.vmm
    }
}
