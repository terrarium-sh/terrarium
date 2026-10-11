use vm_memory::{
    Bytes, GuestAddress, GuestMemoryBackend, GuestMemoryMmap, GuestMemoryRegion,
    MemoryRegionAddress,
};

use super::{DiscardError, MemoryError, MemoryRange};

pub(super) struct Backing(GuestMemoryMmap<()>);

impl Backing {
    pub(super) fn new(sorted_ranges: &[(u64, usize)]) -> Option<Self> {
        let ranges: Vec<_> = sorted_ranges
            .iter()
            .map(|&(base, size)| (GuestAddress(base), size))
            .collect();
        GuestMemoryMmap::from_ranges(&ranges).ok().map(Self)
    }

    pub(super) fn ranges(&self) -> impl Iterator<Item = MemoryRange> + '_ {
        self.0.iter().map(|region| MemoryRange {
            addr: region.start_addr().0,
            len: region.len(),
        })
    }

    pub(super) fn contains(&self, addr: u64, len: u64) -> bool {
        usize::try_from(len).is_ok_and(|len| self.0.check_range(GuestAddress(addr), len))
    }

    pub(super) fn read_append(
        &self,
        addr: u64,
        len: usize,
        bytes: &mut Vec<u8>,
    ) -> Result<(), MemoryError> {
        self.0
            .write_all_volatile_to(GuestAddress(addr), bytes, len)
            .map_err(|_| MemoryError::Unmapped)
    }

    pub(super) fn write(&self, addr: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        self.0
            .write_slice(bytes, GuestAddress(addr))
            .map_err(|_| MemoryError::Unmapped)
    }

    /// Host address of `addr`, or `None` when `addr..addr + len` leaves the region holding `addr`.
    pub(super) fn host_address_within_region(&self, addr: u64, len: u64) -> Option<*mut u8> {
        let region = self.0.find_region(GuestAddress(addr))?;
        let offset = addr.checked_sub(region.start_addr().0)?;
        if addr.checked_add(len)? > region.last_addr().0.checked_add(1)? {
            return None;
        }
        region.get_host_address(MemoryRegionAddress(offset)).ok()
    }

    #[allow(unsafe_code)]
    pub(super) fn discard_host_pages(address: *mut u8, len: usize) -> Result<(), DiscardError> {
        // SAFETY: `GuestMemory::discard` confines this full page range to the mapping.
        let result = unsafe {
            libc::madvise(
                address.cast(),
                len,
                #[cfg(target_os = "macos")]
                libc::MADV_ZERO,
                #[cfg(not(target_os = "macos"))]
                libc::MADV_DONTNEED,
            )
        };
        #[cfg(target_os = "macos")]
        if result != 0
            && matches!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ENOTSUP | libc::EINVAL)
            )
        {
            return Err(DiscardError::Unsupported);
        }
        (result == 0).ok_or(DiscardError::Io)
    }

    pub(super) fn host_page_bytes() -> usize {
        rustix::param::page_size()
    }
}
