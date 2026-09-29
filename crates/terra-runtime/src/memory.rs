//! Guest-memory policy and bounded access.

use terra_platform::memory::{
    DiscardError, GuestMemory, MemoryError as PlatformMemoryError, MemoryRange,
};

use crate::MAX_SINGLE_BYTES;
use terra_limits::{MAX_BATCH_GUEST_COPY_BYTES, MAX_BATCH_GUEST_COPY_RANGES};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryError {
    OutOfRange,
    TooLarge,
    Unmapped,
}

/// Guest RAM shared by the VM worker and each device store.
#[derive(Clone)]
pub struct GuestRam(GuestMemory);

impl GuestRam {
    #[must_use]
    pub fn new(size: u64) -> Option<Self> {
        GuestMemory::allocate(size).map(Self)
    }

    #[must_use]
    pub fn from_memory(memory: GuestMemory) -> Self {
        Self(memory)
    }

    #[must_use]
    pub const fn memory(&self) -> &GuestMemory {
        &self.0
    }

    #[must_use]
    pub fn mapped_bytes(&self) -> u64 {
        self.0.mapped_bytes()
    }

    #[must_use]
    pub const fn address_limit(&self) -> u64 {
        self.0.limit()
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
    pub const fn new(ram: &'a GuestRam) -> Self {
        Self { ram }
    }

    fn copy_len(len: u64) -> Result<usize, MemoryError> {
        if len > MAX_SINGLE_BYTES {
            return Err(MemoryError::TooLarge);
        }
        usize::try_from(len).map_err(|_| MemoryError::TooLarge)
    }

    pub fn read(&self, offset: u64, len: u64) -> Result<Vec<u8>, MemoryError> {
        let len = Self::copy_len(len)?;
        self.ram
            .memory()
            .read(offset, len)
            .map_err(map_memory_error)
    }

    pub fn read_ranges(&self, ranges: &[MemoryRange]) -> Result<Vec<u8>, MemoryError> {
        if ranges.len() > MAX_BATCH_GUEST_COPY_RANGES {
            return Err(MemoryError::TooLarge);
        }
        let mut total = 0_u64;
        for range in ranges {
            Self::copy_len(range.len)?;
            total = total.checked_add(range.len).ok_or(MemoryError::TooLarge)?;
            if total > MAX_BATCH_GUEST_COPY_BYTES {
                return Err(MemoryError::TooLarge);
            }
            self.ram
                .memory()
                .validate_range(range.addr, range.len)
                .map_err(map_memory_error)?;
        }
        let mut bytes = vec![0; usize::try_from(total).map_err(|_| MemoryError::TooLarge)?];
        let mut start = 0;
        for range in ranges {
            let end = start + Self::copy_len(range.len)?;
            self.ram
                .memory()
                .read_into(range.addr, &mut bytes[start..end])
                .map_err(map_memory_error)?;
            start = end;
        }
        Ok(bytes)
    }

    pub fn write(&self, offset: u64, data: &[u8]) -> Result<(), MemoryError> {
        Self::copy_len(u64::try_from(data.len()).map_err(|_| MemoryError::TooLarge)?)?;
        self.ram
            .memory()
            .write(offset, data)
            .map_err(map_memory_error)
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
        let ranges = ranges
            .iter()
            .map(|range| MemoryRange {
                addr: range.addr,
                len: range.len,
            })
            .collect::<Vec<_>>();
        self.memory().discard(&ranges).map_err(map_discard_error)
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
        if !ram.memory().contains_range(range.addr, range.len) {
            return Err(ReclaimError::Invalid);
        }
    }
    Ok(())
}

const fn map_memory_error(error: PlatformMemoryError) -> MemoryError {
    match error {
        PlatformMemoryError::OutOfRange => MemoryError::OutOfRange,
        PlatformMemoryError::Unmapped => MemoryError::Unmapped,
    }
}

const fn map_discard_error(error: DiscardError) -> ReclaimError {
    match error {
        DiscardError::Invalid => ReclaimError::Invalid,
        DiscardError::Unsupported => ReclaimError::Unsupported,
        DiscardError::Io => ReclaimError::Io,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_guest_policy_violations_before_native_discard() {
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

    #[test]
    fn discard_limit_applies_to_each_batch() {
        let ram = GuestRam::new(256 << 20).expect("RAM");
        let result = ram.discard(&[ReclaimRange {
            addr: 0,
            len: MAX_DISCARD_BYTES,
        }]);
        #[cfg(target_os = "macos")]
        if result == Err(ReclaimError::Unsupported) {
            return;
        }
        result.expect("first discard");
        ram.discard(&[ReclaimRange {
            addr: MAX_DISCARD_BYTES,
            len: MAX_DISCARD_BYTES,
        }])
        .expect("second discard");
    }

    /// A batched read copies ranges in order and rejects an invalid later range before copying.
    #[test]
    fn read_ranges_validate_whole_bounded_batch() {
        let ram = GuestRam::from_memory(
            GuestMemory::from_ranges(&[(0, 4096), (8192, 4096)]).expect("RAM"),
        );
        let memory = BoundedMemory::new(&ram);
        memory.write(0, b"first").unwrap();
        memory.write(8192, b"second").unwrap();
        assert_eq!(
            memory
                .read_ranges(&[
                    MemoryRange { addr: 0, len: 5 },
                    MemoryRange { addr: 8192, len: 6 },
                ])
                .unwrap(),
            b"firstsecond"
        );
        assert_eq!(
            memory.read_ranges(&[
                MemoryRange { addr: 0, len: 5 },
                MemoryRange { addr: 4096, len: 1 },
            ]),
            Err(MemoryError::Unmapped)
        );
        assert_eq!(
            memory.read_ranges(&[MemoryRange {
                addr: 0,
                len: MAX_SINGLE_BYTES + 1
            }]),
            Err(MemoryError::TooLarge)
        );
        assert_eq!(
            memory.read_ranges(&vec![MemoryRange { addr: 0, len: 1 }; 33]),
            Err(MemoryError::TooLarge)
        );
        assert_eq!(
            memory.read_ranges(&[
                MemoryRange { addr: 0, len: 1 },
                MemoryRange {
                    addr: u64::MAX,
                    len: 1,
                },
            ]),
            Err(MemoryError::OutOfRange)
        );
    }

    #[test]
    fn read_ranges_enforces_aggregate_limit() {
        let ram = GuestRam::new(128 * 1024).expect("RAM");
        let memory = BoundedMemory::new(&ram);
        let full = vec![
            MemoryRange {
                addr: 0,
                len: MAX_SINGLE_BYTES,
            };
            4
        ];
        assert_eq!(memory.read_ranges(&full).unwrap().len(), 64 * 1024);
        let mut oversized = full;
        oversized.push(MemoryRange { addr: 0, len: 1 });
        assert_eq!(memory.read_ranges(&oversized), Err(MemoryError::TooLarge));
    }
}
