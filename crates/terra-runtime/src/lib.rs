//! Native hosting and scoped capabilities for Terra's WASI worlds.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod artifacts;
pub use artifacts::TrustedArtifacts;
pub mod box_runtime;
pub mod component;
pub mod engine;

#[cfg(unix)]
use vm_memory::{Bytes, GuestAddress, GuestMemoryBackend, GuestMemoryMmap};
#[cfg(windows)]
use windows_sys::Win32::System::Memory::{
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc, VirtualFree,
};

pub use terra_limits::MAX_BATCH_GUEST_COPY_BYTES as MAX_BATCH_BYTES;
pub use terra_limits::MAX_SINGLE_GUEST_COPY_BYTES as MAX_SINGLE_BYTES;
/// Interrupts coalesced per window before further signals drop.
pub const MAX_SIGNALS_PER_WINDOW: u32 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryError {
    OutOfRange,
    TooLarge,
    Unmapped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskError {
    OutOfRange,
    ReadOnly,
    TooLarge,
}

#[cfg(windows)]
pub struct WindowsRam {
    address: core::ptr::NonNull<u8>,
    size: usize,
    guest_base: u64,
}

#[cfg(windows)]
// SAFETY: WindowsRam owns stable VirtualAlloc storage; BoundedMemory uses atomic byte accesses.
#[allow(unsafe_code)]
unsafe impl Send for WindowsRam {}

#[cfg(windows)]
// SAFETY: WindowsRam exposes no Rust references into the allocation.
#[allow(unsafe_code)]
unsafe impl Sync for WindowsRam {}

#[cfg(windows)]
impl WindowsRam {
    #[must_use]
    pub fn allocate(size: u64) -> Option<std::sync::Arc<Self>> {
        Self::allocate_at(size, 0)
    }

    #[must_use]
    pub fn allocate_at(size: u64, guest_base: u64) -> Option<std::sync::Arc<Self>> {
        let size = usize::try_from(size).ok()?;
        if size == 0 || guest_base.checked_add(u64::try_from(size).ok()?).is_none() {
            return None;
        }
        #[allow(unsafe_code)]
        let address = unsafe {
            VirtualAlloc(
                core::ptr::null(),
                size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        Some(std::sync::Arc::new(Self {
            address: core::ptr::NonNull::new(address.cast())?,
            size,
            guest_base,
        }))
    }

    #[must_use]
    pub const fn address(&self) -> *mut u8 {
        self.address.as_ptr()
    }

    #[must_use]
    pub const fn size(&self) -> usize {
        self.size
    }

    #[must_use]
    pub const fn guest_base(&self) -> u64 {
        self.guest_base
    }
}

#[cfg(windows)]
impl Drop for WindowsRam {
    fn drop(&mut self) {
        #[allow(unsafe_code)]
        unsafe {
            // SAFETY: WindowsRam owns this VirtualAlloc allocation.
            VirtualFree(self.address.as_ptr().cast(), 0, MEM_RELEASE);
        }
    }
}

/// Synthetic guest RAM shared by the VM worker and each device store.
#[derive(Clone)]
pub struct SyntheticRam {
    #[cfg(unix)]
    mem: std::sync::Arc<GuestMemoryMmap<()>>,
    #[cfg(windows)]
    mem: std::sync::Arc<WindowsRam>,
    size: u64,
}

impl SyntheticRam {
    #[cfg(unix)]
    #[must_use]
    pub fn new(size: u64) -> Option<Self> {
        let size_usize = usize::try_from(size).ok()?;
        if size_usize == 0 {
            return None;
        }
        let mem = GuestMemoryMmap::<()>::from_ranges(&[(GuestAddress(0), size_usize)]).ok()?;
        Some(Self {
            mem: std::sync::Arc::new(mem),
            size,
        })
    }

    #[cfg(windows)]
    #[must_use]
    pub fn new(size: u64) -> Option<Self> {
        let size = usize::try_from(size).ok()?;
        if size == 0 {
            return None;
        }
        Some(Self {
            mem: WindowsRam::allocate(u64::try_from(size).ok()?)?,
            size: u64::try_from(size).ok()?,
        })
    }

    #[cfg(windows)]
    #[must_use]
    pub fn from_windows_ram(mem: std::sync::Arc<WindowsRam>) -> Option<Self> {
        Some(Self {
            size: mem
                .guest_base()
                .checked_add(u64::try_from(mem.size()).ok()?)?,
            mem,
        })
    }

    /// Alias an existing mapping (for example the VM worker's RAM) instead
    /// of allocating. The size is the exclusive guest-address bound.
    #[cfg(unix)]
    #[must_use]
    pub fn from_shared(mem: std::sync::Arc<GuestMemoryMmap<()>>) -> Option<Self> {
        let size = mem.last_addr().0.checked_add(1)?;
        if size == 0 {
            return None;
        }
        Some(Self { mem, size })
    }

    pub(crate) fn mapped_bytes(&self) -> u64 {
        #[cfg(unix)]
        {
            use vm_memory::GuestMemoryRegion;
            self.mem.iter().map(GuestMemoryRegion::len).sum()
        }
        #[cfg(windows)]
        {
            self.mem.size() as u64
        }
    }

    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }
}

/// Bounded guest-memory access. Every range is checked for arithmetic
/// overflow, mapping, and aggregate limits before anything is copied, so a
/// compromised device cannot reach host memory through a crafted offset.
pub struct BoundedMemory<'a> {
    ram: &'a SyntheticRam,
}

impl<'a> BoundedMemory<'a> {
    #[must_use]
    pub fn new(ram: &'a SyntheticRam) -> Self {
        Self { ram }
    }

    fn check_range(&self, offset: u64, len: u64) -> Result<(), MemoryError> {
        if len > MAX_SINGLE_BYTES {
            return Err(MemoryError::TooLarge);
        }
        let end = offset.checked_add(len).ok_or(MemoryError::OutOfRange)?;
        if end > self.ram.size() {
            return Err(MemoryError::OutOfRange);
        }
        #[cfg(windows)]
        if offset < self.ram.mem.guest_base()
            || end
                > self
                    .ram
                    .mem
                    .guest_base()
                    .checked_add(self.ram.mem.size() as u64)
                    .ok_or(MemoryError::OutOfRange)?
        {
            return Err(MemoryError::OutOfRange);
        }
        #[cfg(unix)]
        {
            let len = usize::try_from(len).map_err(|_| MemoryError::TooLarge)?;
            if !self.ram.mem.check_range(GuestAddress(offset), len) {
                return Err(MemoryError::Unmapped);
            }
        }
        Ok(())
    }

    pub fn read(&self, offset: u64, len: u64) -> Result<Vec<u8>, MemoryError> {
        self.check_range(offset, len)?;
        let len_usize = usize::try_from(len).map_err(|_| MemoryError::TooLarge)?;
        let mut buf = vec![0u8; len_usize];
        #[cfg(unix)]
        self.ram
            .mem
            .read_slice(&mut buf, GuestAddress(offset))
            .map_err(|_| MemoryError::Unmapped)?;
        #[cfg(windows)]
        {
            let start = usize::try_from(offset - self.ram.mem.guest_base())
                .map_err(|_| MemoryError::OutOfRange)?;
            let _end = start
                .checked_add(len_usize)
                .ok_or(MemoryError::OutOfRange)?;
            #[allow(unsafe_code)]
            for (index, byte) in buf.iter_mut().enumerate() {
                // SAFETY: check_range proved this offset is within WindowsRam.
                *byte = unsafe {
                    core::sync::atomic::AtomicU8::from_ptr(
                        self.ram.mem.address().add(start + index),
                    )
                    .load(core::sync::atomic::Ordering::Relaxed)
                };
            }
        }
        Ok(buf)
    }

    pub fn write(&self, offset: u64, data: &[u8]) -> Result<(), MemoryError> {
        let len = u64::try_from(data.len()).map_err(|_| MemoryError::TooLarge)?;
        self.check_range(offset, len)?;
        #[cfg(unix)]
        self.ram
            .mem
            .write_slice(data, GuestAddress(offset))
            .map_err(|_| MemoryError::Unmapped)?;
        #[cfg(windows)]
        {
            let start = usize::try_from(offset - self.ram.mem.guest_base())
                .map_err(|_| MemoryError::OutOfRange)?;
            let _end = start
                .checked_add(data.len())
                .ok_or(MemoryError::OutOfRange)?;
            #[allow(unsafe_code)]
            for (index, byte) in data.iter().copied().enumerate() {
                // SAFETY: check_range proved this offset is within WindowsRam.
                unsafe {
                    core::sync::atomic::AtomicU8::from_ptr(
                        self.ram.mem.address().add(start + index),
                    )
                    .store(byte, core::sync::atomic::Ordering::Relaxed);
                };
            }
        }
        Ok(())
    }
}

/// One device's interrupt line. The device cannot name an IRQ; the native
/// side coalesces bursts and drops past the per-window budget.
pub struct Interrupt {
    pending: bool,
    window_count: u32,
    delivered: u64,
    dropped: u64,
}

impl Interrupt {
    #[must_use]
    pub fn new() -> Self {
        Self {
            pending: false,
            window_count: 0,
            delivered: 0,
            dropped: 0,
        }
    }

    pub fn signal(&mut self) -> bool {
        if self.window_count >= MAX_SIGNALS_PER_WINDOW {
            self.dropped += 1;
            return false;
        }
        self.window_count += 1;
        self.pending = true;
        true
    }

    /// Drain one coalesced notification. Returns true when the guest
    /// needs an injection.
    pub fn take(&mut self) -> bool {
        if self.pending {
            self.pending = false;
            self.delivered += 1;
            true
        } else {
            false
        }
    }

    pub fn end_window(&mut self) {
        self.window_count = 0;
    }

    #[must_use]
    pub fn delivered(&self) -> u64 {
        self.delivered
    }

    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped
    }
}

impl Default for Interrupt {
    fn default() -> Self {
        Self::new()
    }
}

/// One disk grant: fixed capacity with the real read-only mode enforced
/// on every mutation path, mirroring the native WASI wrapper.
pub struct BoundedDisk {
    data: Vec<u8>,
    readonly: bool,
}

impl BoundedDisk {
    #[must_use]
    pub fn new(capacity: usize, readonly: bool) -> Self {
        Self {
            data: vec![0u8; capacity],
            readonly,
        }
    }

    #[must_use]
    pub fn from_readonly_bytes(data: Vec<u8>) -> Self {
        Self {
            data,
            readonly: true,
        }
    }

    #[must_use]
    pub fn capacity(&self) -> usize {
        self.data.len()
    }

    pub fn read(&self, offset: usize, len: usize) -> Result<&[u8], DiskError> {
        let end = offset.checked_add(len).ok_or(DiskError::OutOfRange)?;
        let len_u64 = u64::try_from(len).map_err(|_| DiskError::OutOfRange)?;
        if end > self.data.len() || len_u64 > MAX_BATCH_BYTES {
            return Err(DiskError::OutOfRange);
        }
        Ok(&self.data[offset..end])
    }

    pub fn write(&mut self, offset: usize, buf: &[u8]) -> Result<(), DiskError> {
        if self.readonly {
            return Err(DiskError::ReadOnly);
        }
        let len_u64 = u64::try_from(buf.len()).map_err(|_| DiskError::TooLarge)?;
        if len_u64 > MAX_BATCH_BYTES {
            return Err(DiskError::TooLarge);
        }
        let end = offset.checked_add(buf.len()).ok_or(DiskError::OutOfRange)?;
        if end > self.data.len() {
            return Err(DiskError::OutOfRange);
        }
        self.data[offset..end].copy_from_slice(buf);
        Ok(())
    }
}
