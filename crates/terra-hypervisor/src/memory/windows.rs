use windows_sys::Win32::System::Memory::{
    DiscardVirtualMemory, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc,
    VirtualFree,
};
use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};

use super::{DiscardError, MemoryError, MemoryRange};

pub(super) struct Backing(Vec<Allocation>);

struct Allocation {
    address: core::ptr::NonNull<u8>,
    size: usize,
    guest_base: u64,
}

// SAFETY: Backing owns stable VirtualAlloc storage; access uses atomic bytes.
#[allow(unsafe_code)]
unsafe impl Send for Backing {}

// SAFETY: Backing exposes no Rust references into the allocation.
#[allow(unsafe_code)]
unsafe impl Sync for Backing {}

impl Backing {
    pub(super) fn new(sorted_ranges: &[(u64, usize)]) -> Option<Self> {
        sorted_ranges
            .iter()
            .map(|&(guest_base, size)| Allocation::new(guest_base, size))
            .collect::<Option<Vec<_>>>()
            .map(Self)
    }

    pub(super) fn ranges(&self) -> impl Iterator<Item = MemoryRange> + '_ {
        self.0.iter().map(|allocation| MemoryRange {
            addr: allocation.guest_base,
            len: allocation.size as u64,
        })
    }

    pub(super) fn host_ranges(&self) -> impl ExactSizeIterator<Item = (u64, *mut u8, u64)> + '_ {
        self.0.iter().map(|allocation| {
            (
                allocation.guest_base,
                allocation.address.as_ptr(),
                allocation.size as u64,
            )
        })
    }

    /// Whether one allocation holds the whole range; an access spanning two allocations is rejected.
    pub(super) fn contains(&self, addr: u64, len: u64) -> bool {
        self.allocation(addr, len).is_some()
    }

    #[allow(unsafe_code)]
    pub(super) fn read_append(
        &self,
        addr: u64,
        len: usize,
        bytes: &mut Vec<u8>,
    ) -> Result<(), MemoryError> {
        let (allocation, offset) = self.resolve(addr, len as u64)?;
        bytes.reserve(len);
        for index in 0..len {
            // SAFETY: `resolve` confines this byte to the allocation.
            bytes.push(unsafe {
                core::sync::atomic::AtomicU8::from_ptr(
                    allocation.address.as_ptr().add(offset + index),
                )
                .load(core::sync::atomic::Ordering::Relaxed)
            });
        }
        Ok(())
    }

    #[allow(unsafe_code)]
    pub(super) fn write(&self, addr: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        let (allocation, offset) = self.resolve(addr, bytes.len() as u64)?;
        for (index, byte) in bytes.iter().copied().enumerate() {
            // SAFETY: `resolve` confines this byte to the allocation.
            unsafe {
                core::sync::atomic::AtomicU8::from_ptr(
                    allocation.address.as_ptr().add(offset + index),
                )
                .store(byte, core::sync::atomic::Ordering::Relaxed);
            }
        }
        Ok(())
    }

    pub(super) fn host_address_within_region(&self, addr: u64, len: u64) -> Option<*mut u8> {
        let allocation = self.allocation(addr, len)?;
        let offset = usize::try_from(addr.checked_sub(allocation.guest_base)?).ok()?;
        Some(allocation.address.as_ptr().wrapping_add(offset))
    }

    #[allow(unsafe_code)]
    pub(super) fn discard_host_pages(address: *mut u8, len: usize) -> Result<(), DiscardError> {
        // SAFETY: `GuestMemory::discard` confines this full page range to the allocation.
        let result = unsafe { DiscardVirtualMemory(address.cast(), len) };
        (result == 0).ok_or(DiscardError::Io)
    }

    #[allow(unsafe_code)]
    pub(super) fn host_page_bytes() -> usize {
        let mut info = core::mem::MaybeUninit::<SYSTEM_INFO>::zeroed();
        // SAFETY: GetSystemInfo initializes SYSTEM_INFO at this valid pointer.
        unsafe {
            GetSystemInfo(info.as_mut_ptr());
            info.assume_init().dwPageSize as usize
        }
    }

    fn allocation(&self, addr: u64, len: u64) -> Option<&Allocation> {
        let end = addr.checked_add(len)?;
        self.0
            .iter()
            .find(|allocation| addr >= allocation.guest_base && end <= allocation.limit())
    }

    fn resolve(&self, addr: u64, len: u64) -> Result<(&Allocation, usize), MemoryError> {
        let allocation = self.allocation(addr, len).ok_or(MemoryError::Unmapped)?;
        let offset =
            usize::try_from(addr - allocation.guest_base).map_err(|_| MemoryError::OutOfRange)?;
        Ok((allocation, offset))
    }
}

impl Allocation {
    #[allow(unsafe_code)]
    fn new(guest_base: u64, size: usize) -> Option<Self> {
        // SAFETY: VirtualAlloc allocates a new writable mapping or returns null.
        let address = unsafe {
            VirtualAlloc(
                core::ptr::null(),
                size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        Some(Self {
            address: core::ptr::NonNull::new(address.cast())?,
            size,
            guest_base,
        })
    }

    fn limit(&self) -> u64 {
        self.guest_base + self.size as u64
    }
}

impl Drop for Allocation {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: Backing owns this VirtualAlloc allocation.
        unsafe {
            VirtualFree(self.address.as_ptr().cast(), 0, MEM_RELEASE);
        }
    }
}
