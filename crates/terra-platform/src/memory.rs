//! Native guest RAM allocation and access.

use std::sync::Arc;

#[cfg(unix)]
use vm_memory::{
    Bytes, GuestAddress, GuestMemoryBackend, GuestMemoryMmap, GuestMemoryRegion,
    MemoryRegionAddress,
};
#[cfg(windows)]
use windows_sys::Win32::System::Memory::{
    DiscardVirtualMemory, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc,
    VirtualFree,
};
#[cfg(windows)]
use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryRange {
    pub addr: u64,
    pub len: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryError {
    OutOfRange,
    Unmapped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscardError {
    Invalid,
    Unsupported,
    Io,
}

/// Native RAM mappings shared by the VM and its runtime devices.
#[derive(Clone)]
pub struct GuestMemory {
    #[cfg(unix)]
    memory: Arc<GuestMemoryMmap<()>>,
    #[cfg(windows)]
    memory: Arc<WindowsMemory>,
    limit: u64,
}

impl GuestMemory {
    #[must_use]
    pub fn allocate(size: u64) -> Option<Self> {
        Self::allocate_at(0, size)
    }

    #[must_use]
    pub fn allocate_at(guest_base: u64, size: u64) -> Option<Self> {
        let size = usize::try_from(size).ok()?;
        if size == 0 {
            return None;
        }
        #[cfg(unix)]
        let memory =
            Arc::new(GuestMemoryMmap::from_ranges(&[(GuestAddress(guest_base), size)]).ok()?);
        #[cfg(windows)]
        let memory = WindowsMemory::allocate(guest_base, size)?;
        let limit = guest_base.checked_add(u64::try_from(size).ok()?)?;
        Some(Self { memory, limit })
    }

    /// Allocates the supplied guest-physical mappings.
    #[must_use]
    pub fn from_ranges(ranges: &[(u64, usize)]) -> Option<Self> {
        #[cfg(unix)]
        {
            let ranges: Vec<_> = ranges
                .iter()
                .map(|&(base, size)| (GuestAddress(base), size))
                .collect();
            let limit = ranges
                .iter()
                .map(|(base, size)| base.0.checked_add(u64::try_from(*size).ok()?))
                .collect::<Option<Vec<_>>>()?
                .into_iter()
                .max()?;
            Some(Self {
                memory: Arc::new(GuestMemoryMmap::from_ranges(&ranges).ok()?),
                limit,
            })
        }
        #[cfg(windows)]
        {
            let &[(base, size)] = ranges else {
                return None;
            };
            Self::allocate_at(base, u64::try_from(size).ok()?)
        }
    }

    #[must_use]
    pub fn guest_base(&self) -> u64 {
        #[cfg(unix)]
        {
            self.memory
                .iter()
                .next()
                .map_or(0, |region| region.start_addr().0)
        }
        #[cfg(windows)]
        {
            self.memory.guest_base
        }
    }

    /// Returns the exclusive upper guest address bound.
    #[must_use]
    pub const fn limit(&self) -> u64 {
        self.limit
    }

    #[must_use]
    pub fn mapped_bytes(&self) -> u64 {
        #[cfg(unix)]
        {
            self.memory.iter().map(GuestMemoryRegion::len).sum()
        }
        #[cfg(windows)]
        {
            self.memory.size as u64
        }
    }

    #[must_use]
    pub fn contains_range(&self, addr: u64, len: u64) -> bool {
        let Some(end) = addr.checked_add(len) else {
            return false;
        };
        if end > self.limit {
            return false;
        }
        #[cfg(unix)]
        {
            let Ok(len) = usize::try_from(len) else {
                return false;
            };
            self.memory.check_range(GuestAddress(addr), len)
        }
        #[cfg(windows)]
        {
            addr >= self.memory.guest_base
        }
    }

    #[allow(unsafe_code)]
    pub fn read(&self, addr: u64, len: usize) -> Result<Vec<u8>, MemoryError> {
        let len_u64 = u64::try_from(len).map_err(|_| MemoryError::OutOfRange)?;
        self.check_range(addr, len_u64)?;
        let mut bytes = vec![0; len];
        #[cfg(unix)]
        self.memory
            .read_slice(&mut bytes, GuestAddress(addr))
            .map_err(|_| MemoryError::Unmapped)?;
        #[cfg(windows)]
        for (offset, byte) in bytes.iter_mut().enumerate() {
            // SAFETY: `check_range` confines this byte to the allocation.
            *byte = unsafe {
                core::sync::atomic::AtomicU8::from_ptr(
                    self.memory
                        .address
                        .as_ptr()
                        .add(self.offset(addr)? + offset),
                )
                .load(core::sync::atomic::Ordering::Relaxed)
            };
        }
        Ok(bytes)
    }

    #[allow(unsafe_code)]
    pub fn write(&self, addr: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        self.check_range(
            addr,
            u64::try_from(bytes.len()).map_err(|_| MemoryError::OutOfRange)?,
        )?;
        #[cfg(unix)]
        self.memory
            .write_slice(bytes, GuestAddress(addr))
            .map_err(|_| MemoryError::Unmapped)?;
        #[cfg(windows)]
        for (offset, byte) in bytes.iter().copied().enumerate() {
            // SAFETY: `check_range` confines this byte to the allocation.
            unsafe {
                core::sync::atomic::AtomicU8::from_ptr(
                    self.memory
                        .address
                        .as_ptr()
                        .add(self.offset(addr)? + offset),
                )
                .store(byte, core::sync::atomic::Ordering::Relaxed);
            }
        }
        Ok(())
    }

    /// Discards complete host pages after validating the full batch.
    pub fn discard(&self, ranges: &[MemoryRange]) -> Result<(), DiscardError> {
        let ranges = ranges
            .iter()
            .map(|&range| self.discard_host_range(range))
            .collect::<Result<Vec<_>, _>>()?;
        for (address, len) in ranges {
            Self::discard_host_pages(address, len)?;
        }
        Ok(())
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "windows",
        all(target_os = "macos", target_arch = "aarch64")
    ))]
    pub(crate) fn host_address(&self, addr: u64) -> Option<*mut u8> {
        #[cfg(unix)]
        {
            self.memory.get_host_address(GuestAddress(addr)).ok()
        }
        #[cfg(windows)]
        {
            self.offset(addr)
                .ok()
                .map(|offset| self.memory.address.as_ptr().wrapping_add(offset))
        }
    }

    fn check_range(&self, addr: u64, len: u64) -> Result<(), MemoryError> {
        if self.contains_range(addr, len) {
            Ok(())
        } else if addr < self.guest_base()
            || addr.checked_add(len).is_none_or(|end| end > self.limit)
        {
            Err(MemoryError::OutOfRange)
        } else {
            Err(MemoryError::Unmapped)
        }
    }

    #[cfg(windows)]
    fn offset(&self, addr: u64) -> Result<usize, MemoryError> {
        usize::try_from(
            addr.checked_sub(self.memory.guest_base)
                .ok_or(MemoryError::OutOfRange)?,
        )
        .map_err(|_| MemoryError::OutOfRange)
    }

    fn discard_host_range(&self, range: MemoryRange) -> Result<(*mut u8, usize), DiscardError> {
        if range.len == 0 || !self.contains_range(range.addr, range.len) {
            return Err(DiscardError::Invalid);
        }
        let length = usize::try_from(range.len).map_err(|_| DiscardError::Invalid)?;
        #[cfg(unix)]
        let address = {
            let region = self
                .memory
                .find_region(GuestAddress(range.addr))
                .ok_or(DiscardError::Invalid)?;
            let offset = range
                .addr
                .checked_sub(region.start_addr().0)
                .ok_or(DiscardError::Invalid)?;
            if range
                .addr
                .checked_add(range.len)
                .ok_or(DiscardError::Invalid)?
                > region
                    .last_addr()
                    .0
                    .checked_add(1)
                    .ok_or(DiscardError::Invalid)?
            {
                return Err(DiscardError::Invalid);
            }
            region
                .get_host_address(MemoryRegionAddress(offset))
                .map_err(|_| DiscardError::Invalid)?
        };
        #[cfg(windows)]
        let address = self
            .memory
            .address
            .as_ptr()
            .wrapping_add(self.offset(range.addr).map_err(|_| DiscardError::Invalid)?);
        full_host_pages(address as usize, length, host_page_bytes())
            .map(|(address, length)| (address as *mut u8, length))
            .ok_or(DiscardError::Invalid)
    }

    #[allow(unsafe_code)]
    fn discard_host_pages(address: *mut u8, len: usize) -> Result<(), DiscardError> {
        #[cfg(windows)]
        {
            // SAFETY: `discard_host_range` confines this full page range to the allocation.
            let result = unsafe { DiscardVirtualMemory(address.cast(), len) };
            (result == 0).then_some(()).ok_or(DiscardError::Io)
        }
        #[cfg(unix)]
        {
            // SAFETY: `discard_host_range` confines this full page range to the mapping.
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
            (result == 0).then_some(()).ok_or(DiscardError::Io)
        }
    }
}

#[cfg(windows)]
struct WindowsMemory {
    address: core::ptr::NonNull<u8>,
    size: usize,
    guest_base: u64,
}

#[cfg(windows)]
// SAFETY: WindowsMemory owns stable VirtualAlloc storage; access uses atomic bytes.
#[allow(unsafe_code)]
unsafe impl Send for WindowsMemory {}

#[cfg(windows)]
// SAFETY: WindowsMemory exposes no Rust references into the allocation.
#[allow(unsafe_code)]
unsafe impl Sync for WindowsMemory {}

#[cfg(windows)]
impl WindowsMemory {
    #[allow(unsafe_code)]
    fn allocate(guest_base: u64, size: usize) -> Option<Arc<Self>> {
        guest_base.checked_add(u64::try_from(size).ok()?)?;
        // SAFETY: VirtualAlloc allocates a new writable mapping or returns null.
        let address = unsafe {
            VirtualAlloc(
                core::ptr::null(),
                size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        Some(Arc::new(Self {
            address: core::ptr::NonNull::new(address.cast())?,
            size,
            guest_base,
        }))
    }
}

#[cfg(windows)]
impl Drop for WindowsMemory {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: WindowsMemory owns this VirtualAlloc allocation.
        unsafe {
            VirtualFree(self.address.as_ptr().cast(), 0, MEM_RELEASE);
        }
    }
}

fn full_host_pages(address: usize, len: usize, page: usize) -> Option<(usize, usize)> {
    if page == 0 {
        return None;
    }
    let end = address.checked_add(len)?;
    let start = address.checked_add(page.checked_sub(1)?)? / page * page;
    let end = end / page * page;
    (end > start).then(|| (start, end - start))
}

#[allow(unsafe_code)]
fn host_page_bytes() -> usize {
    #[cfg(unix)]
    {
        rustix::param::page_size()
    }
    #[cfg(windows)]
    {
        let mut info = core::mem::MaybeUninit::<SYSTEM_INFO>::zeroed();
        // SAFETY: GetSystemInfo initializes SYSTEM_INFO at this valid pointer.
        unsafe {
            GetSystemInfo(info.as_mut_ptr());
            info.assume_init().dwPageSize as usize
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aliases_share_one_mapping() {
        let first = GuestMemory::allocate_at(0x1000, 0x4000).expect("RAM");
        let second = first.clone();
        first.write(0x1200, b"shared").expect("write");
        assert_eq!(second.read(0x1200, 6).expect("read"), b"shared");
    }

    #[test]
    fn nonzero_base_rejects_addresses_before_the_mapping() {
        let memory = GuestMemory::allocate_at(0x1000, 0x1000).expect("RAM");
        assert!(!memory.contains_range(0, 1));
        assert_eq!(memory.read(0, 1), Err(MemoryError::OutOfRange));
        assert_eq!(memory.read(0x2000, 1), Err(MemoryError::OutOfRange));
    }

    #[cfg(unix)]
    #[test]
    fn holes_reject_crossing_access() {
        let memory = GuestMemory::from_ranges(&[(0, 0x1000), (0x2000, 0x1000)]).expect("RAM");
        memory.write(0xff0, &[0x42; 16]).expect("write");
        assert_eq!(memory.write(0xff0, &[0x99; 32]), Err(MemoryError::Unmapped));
        assert_eq!(memory.read(0xff0, 16).expect("read"), vec![0x42; 16]);
    }

    #[test]
    fn invalid_batch_does_not_discard_an_earlier_page() {
        let page = host_page_bytes();
        let memory = GuestMemory::allocate((page * 2) as u64).expect("RAM");
        memory.write(0, &[0x5a; 64]).expect("write");
        assert_eq!(
            memory.discard(&[
                MemoryRange {
                    addr: 0,
                    len: page as u64
                },
                MemoryRange {
                    addr: page as u64,
                    len: 0
                },
            ]),
            Err(DiscardError::Invalid)
        );
        assert_eq!(memory.read(0, 64).expect("read"), vec![0x5a; 64]);
    }

    #[test]
    fn discard_keeps_only_complete_host_pages() {
        assert_eq!(full_host_pages(0x1000, 0x1000, 0x4000), None);
        assert_eq!(
            full_host_pages(0x1000, 0x8000, 0x4000),
            Some((0x4000, 0x4000))
        );
        assert_eq!(
            full_host_pages(0x4000, 0x8000, 0x4000),
            Some((0x4000, 0x8000))
        );
    }

    #[test]
    fn sub_host_page_discard_is_rejected_without_modifying_memory() {
        let page = host_page_bytes();
        if page <= 4096 {
            return;
        }
        let memory = GuestMemory::allocate((page * 2) as u64).expect("RAM");
        memory.write(0, &[0x5a; 4096]).expect("write");
        assert_eq!(
            memory.discard(&[MemoryRange { addr: 0, len: 4096 }]),
            Err(DiscardError::Invalid)
        );
        assert_eq!(memory.read(0, 4096).expect("read"), vec![0x5a; 4096]);
    }

    #[cfg(unix)]
    #[test]
    fn discard_zeroes_shared_memory() {
        let page = host_page_bytes();
        let memory = GuestMemory::allocate((page * 2) as u64).expect("RAM");
        let shared = memory.clone();
        memory.write(page as u64, &vec![0x5a; page]).expect("write");
        let result = memory.discard(&[MemoryRange {
            addr: page as u64,
            len: page as u64,
        }]);
        #[cfg(target_os = "macos")]
        if result == Err(DiscardError::Unsupported) {
            return;
        }
        result.expect("discard");
        assert_eq!(shared.read(page as u64, page).expect("read"), vec![0; page]);
    }

    #[test]
    fn discard_does_not_touch_another_mapping() {
        let page = host_page_bytes();
        let first = GuestMemory::allocate((page * 2) as u64).expect("first RAM");
        let second = GuestMemory::allocate(page as u64).expect("second RAM");
        first.write(0, &[0x5a; 64]).expect("write first");
        second.write(0, &[0xa5; 64]).expect("write second");
        let result = first.discard(&[MemoryRange {
            addr: 0,
            len: (page * 2) as u64,
        }]);
        #[cfg(target_os = "macos")]
        if result == Err(DiscardError::Unsupported) {
            return;
        }
        result.expect("discard");
        assert_eq!(second.read(0, 64).expect("read second"), vec![0xa5; 64]);
    }

    #[cfg(unix)]
    #[test]
    fn discard_rejects_a_range_that_crosses_a_hole() {
        let memory = GuestMemory::from_ranges(&[(0, 4096), (8192, 4096)]).expect("RAM");
        memory.write(0, &[0x5a; 4096]).expect("write");
        assert_eq!(
            memory.discard(&[MemoryRange { addr: 0, len: 8192 }]),
            Err(DiscardError::Invalid)
        );
        assert_eq!(memory.read(0, 4096).expect("read"), vec![0x5a; 4096]);
    }
}
