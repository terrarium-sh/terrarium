//! Native guest RAM allocation and access.

use std::sync::Arc;
#[cfg(target_os = "macos")]
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
use unix::Backing;
#[cfg(windows)]
use windows::Backing;

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
    backing: Arc<Backing>,
    limit: u64,
    #[cfg(target_os = "macos")]
    is_hypervisor_mapped: Arc<AtomicBool>,
}

impl GuestMemory {
    #[must_use]
    pub fn from_layout(layout: terra_limits::RamLayout) -> Option<Self> {
        let ranges = layout
            .regions()
            .map(|region| Some((region.base, usize::try_from(region.size).ok()?)))
            .collect::<Option<Vec<_>>>()?;
        Self::from_ranges(&ranges)
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
        let &(last_base, last_size) = ranges.last()?;
        Some(Self {
            backing: Arc::new(Backing::new(&ranges)?),
            limit: range_end(last_base, last_size)?,
            #[cfg(target_os = "macos")]
            is_hypervisor_mapped: Arc::new(AtomicBool::new(false)),
        })
    }

    #[must_use]
    pub fn guest_base(&self) -> u64 {
        self.backing.ranges().next().map_or(0, |range| range.addr)
    }

    /// Returns the exclusive upper guest address bound.
    #[must_use]
    pub const fn limit(&self) -> u64 {
        self.limit
    }

    #[must_use]
    pub fn mapped_bytes(&self) -> u64 {
        self.backing.ranges().map(|range| range.len).sum()
    }

    /// Returns the guest-physical RAM ranges in ascending address order.
    #[must_use]
    pub fn ranges(&self) -> Vec<MemoryRange> {
        self.backing.ranges().collect()
    }

    #[must_use]
    pub fn contains_range(&self, addr: u64, len: u64) -> bool {
        addr.checked_add(len).is_some_and(|end| end <= self.limit)
            && self.backing.contains(addr, len)
    }

    pub fn validate_range(&self, addr: u64, len: u64) -> Result<(), MemoryError> {
        if self.contains_range(addr, len) {
            Ok(())
        } else {
            Err(self.range_error(addr, len))
        }
    }

    pub fn read(&self, addr: u64, len: usize) -> Result<Vec<u8>, MemoryError> {
        self.validate_range(
            addr,
            u64::try_from(len).map_err(|_| MemoryError::OutOfRange)?,
        )?;
        let mut bytes = Vec::with_capacity(len);
        self.backing.read_append(addr, len, &mut bytes)?;
        Ok(bytes)
    }

    pub fn read_append(
        &self,
        addr: u64,
        len: usize,
        bytes: &mut Vec<u8>,
    ) -> Result<(), MemoryError> {
        self.validate_range(
            addr,
            u64::try_from(len).map_err(|_| MemoryError::OutOfRange)?,
        )?;
        self.backing.read_append(addr, len, bytes)
    }

    pub fn write(&self, addr: u64, bytes: &[u8]) -> Result<(), MemoryError> {
        self.validate_range(
            addr,
            u64::try_from(bytes.len()).map_err(|_| MemoryError::OutOfRange)?,
        )?;
        self.backing.write(addr, bytes)
    }

    /// Discards complete host pages after validating the full batch. The guest
    /// must not touch the ranges until this returns: on macOS they leave the VM.
    #[cfg_attr(target_os = "macos", allow(unsafe_code))]
    pub fn discard(&self, ranges: &[MemoryRange]) -> Result<(), DiscardError> {
        let ranges = ranges
            .iter()
            .map(|&range| self.discard_host_range(range))
            .collect::<Result<Vec<_>, _>>()?;
        for (guest_address, host_address, len) in ranges {
            // Discarded pages that Hypervisor.framework still maps stay charged to this process.
            #[cfg(target_os = "macos")]
            if self.is_hypervisor_mapped.load(Ordering::Relaxed) {
                crate::hvf::unmap_guest_ram(guest_address, len).map_err(|_| DiscardError::Io)?;
                let discarded = Backing::discard_host_pages(host_address, len);
                // SAFETY: `discard_host_range` keeps this range inside the VM's own RAM at its
                // own guest address, and the VM's machine holds that RAM until it is destroyed.
                if let Err(error) =
                    unsafe { crate::hvf::map_guest_ram(host_address, guest_address, len) }
                {
                    // The guest would read zeros and lose writes in the hole, so the VM stops.
                    log::error!(
                        "guest RAM {guest_address:#x}+{len:#x} could not be remapped after a discard: {error}"
                    );
                    std::process::abort();
                }
                discarded?;
                continue;
            }
            #[cfg(not(target_os = "macos"))]
            let _ = guest_address;
            Backing::discard_host_pages(host_address, len)?;
        }
        Ok(())
    }

    /// Routes later discards through the Hypervisor.framework VM's mapping.
    #[cfg(target_os = "macos")]
    pub(crate) fn mark_hypervisor_mapped(&self) {
        self.is_hypervisor_mapped.store(true, Ordering::Relaxed);
    }

    #[cfg(unix)]
    pub(crate) fn host_address(&self, addr: u64) -> Option<*mut u8> {
        self.backing.host_address_within_region(addr, 1)
    }

    #[cfg(windows)]
    pub(crate) fn host_ranges(&self) -> impl ExactSizeIterator<Item = (u64, *mut u8, u64)> + '_ {
        self.backing.host_ranges()
    }

    fn range_error(&self, addr: u64, len: u64) -> MemoryError {
        if addr < self.guest_base() || addr.checked_add(len).is_none_or(|end| end > self.limit) {
            MemoryError::OutOfRange
        } else {
            MemoryError::Unmapped
        }
    }

    /// The guest address, host address and length of the complete host pages in `range`.
    fn discard_host_range(
        &self,
        range: MemoryRange,
    ) -> Result<(u64, *mut u8, usize), DiscardError> {
        if range.len == 0 || !self.contains_range(range.addr, range.len) {
            return Err(DiscardError::Invalid);
        }
        let length = usize::try_from(range.len).map_err(|_| DiscardError::Invalid)?;
        let address = self
            .backing
            .host_address_within_region(range.addr, range.len)
            .ok_or(DiscardError::Invalid)?;
        let (start, length) = full_host_pages(address as usize, length, Backing::host_page_bytes())
            .ok_or(DiscardError::Invalid)?;
        let skipped = u64::try_from(start - address as usize).map_err(|_| DiscardError::Invalid)?;
        Ok((range.addr + skipped, start as *mut u8, length))
    }
}

fn range_end(base: u64, size: usize) -> Option<u64> {
    base.checked_add(u64::try_from(size).ok()?)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aliases_share_one_mapping() {
        let first = GuestMemory::from_ranges(&[(0x1000, 0x4000)]).expect("RAM");
        let second = first.clone();
        first.write(0x1200, b"shared").expect("write");
        assert_eq!(second.read(0x1200, 6).expect("read"), b"shared");
    }

    #[test]
    fn nonzero_base_rejects_addresses_before_the_mapping() {
        let memory = GuestMemory::from_ranges(&[(0x1000, 0x1000)]).expect("RAM");
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
        let page = Backing::host_page_bytes();
        let memory = GuestMemory::from_ranges(&[(0, page * 2)]).expect("RAM");
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

    /// The macOS discard unmaps the guest range of exactly the host pages it
    /// discards, so the guest address must round up with the host address.
    #[cfg(unix)]
    #[test]
    fn discard_range_keeps_guest_and_host_pages_aligned() {
        let page = Backing::host_page_bytes();
        let base = (page * 4) as u64;
        let memory = GuestMemory::from_ranges(&[(base, page * 4)]).expect("RAM");
        let host_base = memory.host_address(base).expect("host address") as usize;
        let (guest, host, len) = memory
            .discard_host_range(MemoryRange {
                addr: base + 1,
                len: (page * 3) as u64,
            })
            .expect("range");
        assert_eq!(guest, base + page as u64);
        assert_eq!(host as usize, host_base + page);
        assert_eq!(len, page * 2);
    }

    #[test]
    fn sub_host_page_discard_is_rejected_without_modifying_memory() {
        let page = Backing::host_page_bytes();
        if page <= 4096 {
            return;
        }
        let memory = GuestMemory::from_ranges(&[(0, page * 2)]).expect("RAM");
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
        let page = Backing::host_page_bytes();
        let memory = GuestMemory::from_ranges(&[(0, page * 2)]).expect("RAM");
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
        let page = Backing::host_page_bytes();
        let first = GuestMemory::from_ranges(&[(0, page * 2)]).expect("first RAM");
        let second = GuestMemory::from_ranges(&[(0, page)]).expect("second RAM");
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
