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

    /// Allocates x86 RAM below and above the MMIO hole.
    #[must_use]
    pub fn allocate_x86_ram(total: u64) -> Option<Self> {
        let ranges = terra_limits::x86_ram_layout(total)?
            .regions()
            .map(|region| Some((region.base, usize::try_from(region.size).ok()?)))
            .collect::<Option<Vec<_>>>()?;
        Self::from_ranges(&ranges)
    }

    #[must_use]
    pub fn allocate_arm_ram(total: u64) -> Option<Self> {
        let region = terra_limits::arm_ram_layout(total)?.regions().next()?;
        Self::allocate_at(region.base, region.size)
    }

    /// Allocates the supplied guest-physical mappings.
    #[must_use]
    pub fn from_ranges(ranges: &[(u64, usize)]) -> Option<Self> {
        let mut ranges = ranges.to_vec();
        ranges.sort_unstable_by_key(|(base, _)| *base);
        if ranges.is_empty()
            || ranges
                .iter()
                .any(|&(base, size)| size == 0 || range_end(base, size).is_none())
            || ranges.windows(2).any(|ranges| {
                range_end(ranges[0].0, ranges[0].1).is_none_or(|end| end > ranges[1].0)
            })
        {
            return None;
        }
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
            let memory = WindowsMemory::allocate_ranges(&ranges)?;
            let limit = memory.ranges.iter().map(WindowsMemoryRange::limit).max()?;
            Some(Self {
                memory: Arc::new(memory),
                limit,
            })
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
            self.memory
                .ranges
                .first()
                .map_or(0, |range| range.guest_base)
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
            self.memory.mapped_bytes
        }
    }

    /// Returns the guest-physical RAM ranges in ascending address order.
    #[must_use]
    pub fn ranges(&self) -> Vec<MemoryRange> {
        #[cfg(unix)]
        {
            self.memory
                .iter()
                .map(|range| MemoryRange {
                    addr: range.start_addr().0,
                    len: range.len(),
                })
                .collect()
        }
        #[cfg(windows)]
        {
            self.memory
                .ranges
                .iter()
                .map(|range| MemoryRange {
                    addr: range.guest_base,
                    len: range.size as u64,
                })
                .collect()
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
            self.memory.range(addr, len).is_some()
        }
    }

    #[allow(unsafe_code)]
    pub fn read(&self, addr: u64, len: usize) -> Result<Vec<u8>, MemoryError> {
        let len_u64 = u64::try_from(len).map_err(|_| MemoryError::OutOfRange)?;
        #[cfg(unix)]
        self.check_range(addr, len_u64)?;
        #[cfg(windows)]
        let (range, range_offset) = self.resolve_range(addr, len_u64)?;
        let mut bytes = vec![0; len];
        #[cfg(unix)]
        self.memory
            .read_slice(&mut bytes, GuestAddress(addr))
            .map_err(|_| MemoryError::Unmapped)?;
        #[cfg(windows)]
        for (offset, byte) in bytes.iter_mut().enumerate() {
            // SAFETY: `resolve_range` confines this byte to the allocation.
            *byte = unsafe {
                core::sync::atomic::AtomicU8::from_ptr(
                    range.address.as_ptr().add(range_offset + offset),
                )
                .load(core::sync::atomic::Ordering::Relaxed)
            };
        }
        Ok(bytes)
    }

    #[allow(unsafe_code)]
    pub fn write(&self, addr: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        let len = u64::try_from(bytes.len()).map_err(|_| MemoryError::OutOfRange)?;
        #[cfg(unix)]
        self.check_range(addr, len)?;
        #[cfg(windows)]
        let (range, range_offset) = self.resolve_range(addr, len)?;
        #[cfg(unix)]
        self.memory
            .write_slice(bytes, GuestAddress(addr))
            .map_err(|_| MemoryError::Unmapped)?;
        #[cfg(windows)]
        for (offset, byte) in bytes.iter().copied().enumerate() {
            // SAFETY: `resolve_range` confines this byte to the allocation.
            unsafe {
                core::sync::atomic::AtomicU8::from_ptr(
                    range.address.as_ptr().add(range_offset + offset),
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
            self.memory.range(addr, 1).and_then(|range| {
                usize::try_from(addr.checked_sub(range.guest_base)?)
                    .ok()
                    .map(|offset| range.address.as_ptr().wrapping_add(offset))
            })
        }
    }

    #[cfg(unix)]
    fn check_range(&self, addr: u64, len: u64) -> Result<(), MemoryError> {
        if self.contains_range(addr, len) {
            Ok(())
        } else {
            Err(self.range_error(addr, len))
        }
    }

    #[cfg(windows)]
    fn resolve_range(
        &self,
        addr: u64,
        len: u64,
    ) -> Result<(&WindowsMemoryRange, usize), MemoryError> {
        let range = self
            .memory
            .range(addr, len)
            .ok_or_else(|| self.range_error(addr, len))?;
        let offset =
            usize::try_from(addr - range.guest_base).map_err(|_| MemoryError::OutOfRange)?;
        Ok((range, offset))
    }

    fn range_error(&self, addr: u64, len: u64) -> MemoryError {
        if addr < self.guest_base() || addr.checked_add(len).is_none_or(|end| end > self.limit) {
            MemoryError::OutOfRange
        } else {
            MemoryError::Unmapped
        }
    }

    #[cfg(windows)]
    pub(crate) fn host_ranges(&self) -> impl ExactSizeIterator<Item = (u64, *mut u8, u64)> + '_ {
        self.memory
            .ranges
            .iter()
            .map(|range| (range.guest_base, range.address.as_ptr(), range.size as u64))
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
        let address = self.host_address(range.addr).ok_or(DiscardError::Invalid)?;
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

fn range_end(base: u64, size: usize) -> Option<u64> {
    base.checked_add(u64::try_from(size).ok()?)
}

#[cfg(windows)]
struct WindowsMemory {
    ranges: Vec<WindowsMemoryRange>,
    mapped_bytes: u64,
}

#[cfg(windows)]
struct WindowsMemoryRange {
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
        Some(Arc::new(Self {
            ranges: vec![WindowsMemoryRange::allocate(guest_base, size)?],
            mapped_bytes: size as u64,
        }))
    }

    fn allocate_ranges(ranges: &[(u64, usize)]) -> Option<Self> {
        let ranges = ranges
            .iter()
            .copied()
            .map(|(guest_base, size)| WindowsMemoryRange::allocate(guest_base, size))
            .collect::<Option<Vec<_>>>()?;
        let mapped_bytes = ranges
            .iter()
            .try_fold(0_u64, |total, range| total.checked_add(range.size as u64))?;
        Some(Self {
            ranges,
            mapped_bytes,
        })
    }

    fn range(&self, addr: u64, len: u64) -> Option<&WindowsMemoryRange> {
        let end = addr.checked_add(len)?;
        self.ranges
            .iter()
            .find(|range| addr >= range.guest_base && end <= range.limit())
    }
}

#[cfg(windows)]
impl WindowsMemoryRange {
    #[allow(unsafe_code)]
    fn allocate(guest_base: u64, size: usize) -> Option<Self> {
        if size == 0 {
            return None;
        }
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

#[cfg(windows)]
impl Drop for WindowsMemoryRange {
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

    #[test]
    fn ranges_reject_empty_overlapping_and_overflowing_mappings() {
        assert!(GuestMemory::from_ranges(&[]).is_none());
        assert!(GuestMemory::from_ranges(&[(0, 0)]).is_none());
        assert!(GuestMemory::from_ranges(&[(0, 4096), (2048, 4096)]).is_none());
        assert!(GuestMemory::from_ranges(&[(u64::MAX - 1024, 4096)]).is_none());
    }

    #[test]
    fn ranges_are_sorted_and_reported() {
        let memory = GuestMemory::from_ranges(&[(0x2000, 0x1000), (0, 0x1000)]).expect("RAM");
        assert_eq!(
            memory.ranges(),
            [
                MemoryRange {
                    addr: 0,
                    len: 0x1000,
                },
                MemoryRange {
                    addr: 0x2000,
                    len: 0x1000,
                },
            ]
        );
    }

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
