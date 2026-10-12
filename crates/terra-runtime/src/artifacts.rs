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
#[derive(Clone, Copy)]
pub struct TrustedArtifacts {
    pub block: TrustedArtifact,
    pub agent: TrustedArtifact,
    pub vsock_frontend: TrustedArtifact,
    pub fs: TrustedArtifact,
    pub mem: TrustedArtifact,
    pub boot: TrustedArtifact,
    pub vmm: TrustedArtifact,
    pub interrupt_controller: TrustedArtifact,
}
