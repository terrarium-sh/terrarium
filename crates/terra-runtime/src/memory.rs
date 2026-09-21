//! Guest RAM allocation, bounded access, and native page reclamation.

use crate::MAX_SINGLE_BYTES;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::WindowsRam;

#[cfg(unix)]
use vm_memory::{
    Bytes, GuestAddress, GuestMemoryBackend, GuestMemoryMmap, GuestMemoryRegion,
    MemoryRegionAddress,
};
#[cfg(windows)]
use windows_sys::Win32::System::Memory::DiscardVirtualMemory;

#[cfg(windows)]
use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryError {
    OutOfRange,
    TooLarge,
    Unmapped,
}

/// Guest RAM shared by the VM worker and each device store.
#[derive(Clone)]
pub struct GuestRam {
    #[cfg(unix)]
    mem: std::sync::Arc<GuestMemoryMmap<()>>,
    #[cfg(windows)]
    mem: std::sync::Arc<WindowsRam>,
    size: u64,
}

impl GuestRam {
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
    ram: &'a GuestRam,
}

impl<'a> BoundedMemory<'a> {
    #[must_use]
    pub fn new(ram: &'a GuestRam) -> Self {
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

const PAGE_BYTES: u64 = 4096;
const MAX_RANGES: usize = 32;
const MAX_DISCARD_BYTES: u64 = 128 << 20;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReclaimRange {
    pub addr: u64,
    pub len: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReclaimError {
    Invalid,
    Unsupported,
    TooLarge,
    Io,
}

impl GuestRam {
    pub fn discard(&self, ranges: &[ReclaimRange]) -> Result<(), ReclaimError> {
        validate_ranges(self, ranges)?;
        for &range in ranges {
            discard_range(self, range)?;
        }
        Ok(())
    }
}

fn validate_ranges(ram: &GuestRam, ranges: &[ReclaimRange]) -> Result<(), ReclaimError> {
    if ranges.len() > MAX_RANGES {
        return Err(ReclaimError::TooLarge);
    }

    let mut total: u64 = 0;
    for &range in ranges {
        if range.len == 0 || range.addr % PAGE_BYTES != 0 || range.len % PAGE_BYTES != 0 {
            return Err(ReclaimError::Invalid);
        }
        total = total.checked_add(range.len).ok_or(ReclaimError::TooLarge)?;
        if total > MAX_DISCARD_BYTES {
            return Err(ReclaimError::TooLarge);
        }

        let end = range
            .addr
            .checked_add(range.len)
            .ok_or(ReclaimError::Invalid)?;
        if end > ram.size() {
            return Err(ReclaimError::Invalid);
        }
        #[cfg(unix)]
        {
            let length = usize::try_from(range.len).map_err(|_| ReclaimError::TooLarge)?;
            if !ram.mem.check_range(GuestAddress(range.addr), length) {
                return Err(ReclaimError::Invalid);
            }
            let region = ram
                .mem
                .find_region(GuestAddress(range.addr))
                .ok_or(ReclaimError::Invalid)?;
            let offset = range.addr - region.start_addr().0;
            let address = region
                .get_host_address(MemoryRegionAddress(offset))
                .map_err(|_| ReclaimError::Invalid)?;
            if full_host_pages(address as usize, length, host_page_bytes()).is_none() {
                return Err(ReclaimError::Invalid);
            }
            if end
                > region
                    .last_addr()
                    .0
                    .checked_add(1)
                    .ok_or(ReclaimError::Invalid)?
            {
                return Err(ReclaimError::Invalid);
            }
        }
        #[cfg(windows)]
        if range.addr < ram.mem.guest_base() {
            return Err(ReclaimError::Invalid);
        }
    }
    Ok(())
}

fn discard_range(ram: &GuestRam, range: ReclaimRange) -> Result<(), ReclaimError> {
    #[cfg(windows)]
    {
        let offset = usize::try_from(range.addr - ram.mem.guest_base())
            .map_err(|_| ReclaimError::TooLarge)?;
        let length = usize::try_from(range.len).map_err(|_| ReclaimError::TooLarge)?;
        let Some((address, length)) = full_host_pages(
            ram.mem.address().wrapping_add(offset) as usize,
            length,
            host_page_bytes(),
        ) else {
            return Err(ReclaimError::Invalid);
        };
        #[allow(unsafe_code)]
        // SAFETY: validation confines this full host-page range to WindowsRam.
        let result = unsafe { DiscardVirtualMemory(address as *mut _, length) };
        if result != 0 {
            return Err(ReclaimError::Io);
        }
        Ok(())
    }
    #[cfg(unix)]
    {
        let region = ram
            .mem
            .find_region(GuestAddress(range.addr))
            .ok_or(ReclaimError::Invalid)?;
        let offset = range
            .addr
            .checked_sub(region.start_addr().0)
            .ok_or(ReclaimError::Invalid)?;
        let offset = usize::try_from(offset).map_err(|_| ReclaimError::TooLarge)?;
        let length = usize::try_from(range.len).map_err(|_| ReclaimError::TooLarge)?;
        let address = region
            .get_host_address(MemoryRegionAddress(offset as u64))
            .map_err(|_| ReclaimError::Invalid)?;
        let Some((address, length)) = full_host_pages(address as usize, length, host_page_bytes())
        else {
            return Err(ReclaimError::Invalid);
        };
        // SAFETY: validation proves the page-aligned range remains in this mapped RAM region.
        #[allow(unsafe_code)]
        let result = unsafe {
            libc::madvise(
                address as *mut _,
                length,
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
            return Err(ReclaimError::Unsupported);
        }
        (result == 0).then_some(()).ok_or(ReclaimError::Io)
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

fn host_page_bytes() -> usize {
    #[cfg(unix)]
    {
        rustix::param::page_size()
    }
    #[cfg(windows)]
    {
        let mut info = core::mem::MaybeUninit::<SYSTEM_INFO>::zeroed();
        #[allow(unsafe_code)]
        unsafe {
            // SAFETY: GetSystemInfo initializes SYSTEM_INFO at this valid pointer.
            GetSystemInfo(info.as_mut_ptr());
            info.assume_init().dwPageSize as usize
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legal_reclaim_batches_are_not_limited_by_a_worker_lifetime_total() {
        let ram = GuestRam::new(256 << 20).unwrap();

        let result = ram.discard(&[ReclaimRange {
            addr: 0,
            len: MAX_DISCARD_BYTES,
        }]);
        #[cfg(target_os = "macos")]
        if result == Err(ReclaimError::Unsupported) {
            return;
        }
        result.unwrap();
        ram.discard(&[ReclaimRange {
            addr: MAX_DISCARD_BYTES,
            len: MAX_DISCARD_BYTES,
        }])
        .unwrap();
    }

    #[test]
    fn sub_host_page_reclaim_is_rejected_without_modifying_memory() {
        let page = host_page_bytes();
        let guest_page = usize::try_from(PAGE_BYTES).unwrap();
        if page <= guest_page {
            return;
        }
        let ram = GuestRam::new((page * 2) as u64).expect("RAM");
        BoundedMemory::new(&ram)
            .write(0, &vec![0x5a; guest_page])
            .expect("write RAM");
        assert_eq!(
            ram.discard(&[ReclaimRange {
                addr: 0,
                len: PAGE_BYTES
            }]),
            Err(ReclaimError::Invalid)
        );
        assert_eq!(
            BoundedMemory::new(&ram)
                .read(0, PAGE_BYTES)
                .expect("read RAM"),
            vec![0x5a; guest_page]
        );
    }

    #[cfg(unix)]
    #[test]
    fn discard_zeroes_this_vm_page() {
        let page = host_page_bytes();
        let ram = GuestRam::new((page * 2) as u64).expect("RAM");
        BoundedMemory::new(&ram)
            .write(page as u64, &vec![0x5a; page])
            .expect("write RAM");
        let shared_ram = ram.clone();
        let result = ram.discard(&[ReclaimRange {
            addr: page as u64,
            len: page as u64,
        }]);
        #[cfg(target_os = "macos")]
        if result == Err(ReclaimError::Unsupported) {
            assert_eq!(
                BoundedMemory::new(&ram)
                    .read(page as u64, page as u64)
                    .expect("read RAM"),
                vec![0x5a; page]
            );
            return;
        }
        result.expect("discard page");
        assert_eq!(
            BoundedMemory::new(&ram)
                .read(page as u64, page as u64)
                .expect("read RAM"),
            vec![0; page]
        );
        assert_eq!(
            BoundedMemory::new(&shared_ram)
                .read(page as u64, page as u64)
                .expect("shared RAM"),
            vec![0; page]
        );
    }

    #[test]
    fn invalid_batch_does_not_discard_an_earlier_page() {
        let ram = GuestRam::new(16 * 1024).expect("RAM");
        BoundedMemory::new(&ram)
            .write(0, &[0x5a; 4096])
            .expect("write RAM");
        assert_eq!(
            ram.discard(&[
                ReclaimRange { addr: 0, len: 4096 },
                ReclaimRange {
                    addr: 15 * 1024,
                    len: 4096,
                },
            ]),
            Err(ReclaimError::Invalid)
        );
        assert_eq!(
            BoundedMemory::new(&ram).read(0, 4096).expect("read RAM"),
            vec![0x5a; 4096]
        );
    }

    #[test]
    fn reject_unaligned_overflow_and_too_many_ranges() {
        let ram = GuestRam::new(16 * 1024).expect("RAM");
        assert_eq!(
            ram.discard(&[ReclaimRange { addr: 1, len: 4096 }]),
            Err(ReclaimError::Invalid)
        );
        assert_eq!(
            ram.discard(&[ReclaimRange {
                addr: u64::MAX - 4095,
                len: 4096,
            }]),
            Err(ReclaimError::Invalid)
        );
        assert_eq!(
            ram.discard(&vec![ReclaimRange { addr: 0, len: 4096 }; MAX_RANGES + 1]),
            Err(ReclaimError::TooLarge)
        );
    }

    #[cfg(unix)]
    #[test]
    fn reject_ranges_that_cross_a_guest_ram_hole() {
        use std::sync::Arc;
        use vm_memory::{GuestAddress, GuestMemoryMmap};

        let mapping = Arc::new(
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 4096), (GuestAddress(8192), 4096)])
                .expect("RAM with a hole"),
        );
        let ram = GuestRam::from_shared(mapping).expect("RAM alias");

        BoundedMemory::new(&ram)
            .write(0, &[0x5a; 4096])
            .expect("write first region");
        assert_eq!(
            ram.discard(&[ReclaimRange { addr: 0, len: 8192 }]),
            Err(ReclaimError::Invalid)
        );
        assert_eq!(
            BoundedMemory::new(&ram)
                .read(0, 4096)
                .expect("read first region"),
            vec![0x5a; 4096]
        );
    }

    #[test]
    fn discard_does_not_touch_another_mapping() {
        let first_ram = GuestRam::new(64 * 1024).expect("RAM");

        let second_ram = GuestRam::new(16 * 1024).expect("RAM");
        BoundedMemory::new(&first_ram)
            .write(0, &[0x5a; 4096])
            .expect("write first RAM");
        BoundedMemory::new(&second_ram)
            .write(0, &[0xa5; 4096])
            .expect("write second RAM");
        let result = first_ram.discard(&[ReclaimRange {
            addr: 0,
            len: 64 * 1024,
        }]);
        assert!(
            result.is_ok()
                || (cfg!(target_os = "macos") && result == Err(ReclaimError::Unsupported))
        );
        assert_eq!(
            BoundedMemory::new(&second_ram)
                .read(0, 4096)
                .expect("read second RAM"),
            vec![0xa5; 4096]
        );
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
}
