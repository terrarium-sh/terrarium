//! Trusted Wasmtime component artifacts shared by VMM backends.

use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, PoisonError};
use terra_platform::code_memory::{self, PageAligned};
use wasmtime::component::Component;

/// Trusted AOT artifact for one exact Wasmtime runtime.
#[derive(Clone, Copy)]
pub struct TrustedArtifact(ArtifactBytes);

/// Where an artifact's bytes live, which decides whether its code can run in place.
#[derive(Clone, Copy)]
enum ArtifactBytes {
    OwnPages(&'static PageAligned<[u8]>),
    Anywhere(&'static [u8]),
}

/// Components loaded in place, keyed by the artifact's address; `None` records
/// an artifact that failed to load in place.
static IN_PLACE_COMPONENTS: Mutex<Vec<(usize, Option<InPlaceOwner>)>> = Mutex::new(Vec::new());
static HAS_LOGGED_COPY_FALLBACK: AtomicBool = AtomicBool::new(false);

/// The engine that loaded an artifact in place, and the component it loaded.
type InPlaceOwner = (wasmtime::Engine, Component);

#[allow(unsafe_code)]
impl TrustedArtifact {
    /// # Safety
    ///
    /// `bytes` must be trusted AOT output produced for this exact Wasmtime
    /// build; it must never come from a user or network input.
    #[must_use]
    pub const unsafe fn from_trusted_bytes(bytes: &'static [u8]) -> Self {
        Self(ArtifactBytes::Anywhere(bytes))
    }

    /// # Safety
    ///
    /// As for [`Self::from_trusted_bytes`]; nothing may write `bytes` afterwards.
    #[must_use]
    pub const unsafe fn from_trusted_page_aligned(bytes: &'static PageAligned<[u8]>) -> Self {
        Self(ArtifactBytes::OwnPages(bytes))
    }

    fn bytes(self) -> &'static [u8] {
        match self.0 {
            ArtifactBytes::OwnPages(bytes) => &bytes.0,
            ArtifactBytes::Anywhere(bytes) => bytes,
        }
    }

    /// Deserializes in place, or from a private copy when that cannot be used.
    pub fn deserialize(self, engine: &wasmtime::Engine) -> wasmtime::Result<Component> {
        self.deserialize_in_place(engine).or_else(|error| {
            if !HAS_LOGGED_COPY_FALLBACK.swap(true, Ordering::Relaxed) {
                log::debug!("copying embedded components into private memory: {error:#}");
            }
            // SAFETY: TrustedArtifact is constructed only from trusted AOT output for this runtime.
            unsafe { Component::deserialize(engine, self.bytes()) }
        })
    }

    /// Deserializes without copying, so every process running an embedded
    /// artifact shares its code's page-cache pages. Loads once per process, by
    /// the first engine that asks.
    pub fn deserialize_in_place(self, engine: &wasmtime::Engine) -> wasmtime::Result<Component> {
        let ArtifactBytes::OwnPages(bytes) = self.0 else {
            wasmtime::bail!("the artifact does not sit on pages of its own");
        };
        let address = bytes.0.as_ptr().addr();
        let mut components = IN_PLACE_COMPONENTS
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some((_, loaded)) = components.iter().find(|(loaded, _)| *loaded == address) {
            return match loaded {
                Some((owner, component)) if wasmtime::Engine::same(owner, engine) => {
                    Ok(component.clone())
                }
                // see another_engine_falls_back_to_a_private_copy
                Some(_) => {
                    wasmtime::bail!("the artifact's in-place code belongs to another engine")
                }
                None => wasmtime::bail!("the artifact failed to load in place earlier"),
            };
        }
        let loaded = if address.is_multiple_of(code_memory::page_size()) {
            // SAFETY: the trusted bytes sit on pages of their own that nothing
            // writes, for the life of the process; the cached component keeps
            // its code published, so the pages are never unpublished.
            unsafe { Component::deserialize_raw(engine, NonNull::from(&bytes.0)) }
        } else {
            Err(wasmtime::Error::msg(
                "the artifact's alignment is below the page size",
            ))
        };
        components.push((
            address,
            loaded
                .as_ref()
                .ok()
                .map(|component| (engine.clone(), component.clone())),
        ));
        loaded
    }
}

/// Code page protection for every device-engine code mapping, including the
/// in-place artifacts Wasmtime cannot protect itself.
pub(crate) struct CodeProtection;

#[allow(unsafe_code)]
impl wasmtime::CustomCodeMemory for CodeProtection {
    fn required_alignment(&self) -> usize {
        code_memory::page_size()
    }

    fn publish_executable(&self, ptr: *const u8, len: usize) -> wasmtime::Result<()> {
        if len == 0 {
            return Ok(());
        }
        // SAFETY: Wasmtime hands over a page-aligned text range it has finished
        // writing and never writes again while published.
        unsafe {
            wasmtime_internal_jit_icache_coherence::clear_cache(ptr.cast(), len)?;
            code_memory::protect_executable(ptr, len)?;
        }
        wasmtime_internal_jit_icache_coherence::pipeline_flush_mt()?;
        Ok(())
    }

    /// Leaves the range read-only rather than writable: in-place code is the
    /// executable's own image, and nothing here edits code after publishing it.
    fn unpublish_executable(&self, ptr: *const u8, len: usize) -> wasmtime::Result<()> {
        if len == 0 {
            return Ok(());
        }
        // SAFETY: Wasmtime guarantees no code runs from this range any more.
        unsafe { code_memory::protect_read_only(ptr, len)? };
        Ok(())
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
