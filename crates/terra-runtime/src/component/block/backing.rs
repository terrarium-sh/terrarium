//! Host disk capabilities for the Wasm block device.

use crate::component::AccessMode;
use terra_protocol::packed_image::{ChunkCache, PackedImage};

/// In-memory disk for tests: fixed capacity with the real read-only mode
/// enforced on every mutation path.
#[cfg(any(test, feature = "test-support"))]
pub struct BoundedDisk {
    data: Vec<u8>,
    access: AccessMode,
}

#[cfg(any(test, feature = "test-support"))]
impl BoundedDisk {
    #[must_use]
    pub fn new(capacity: usize, access: AccessMode) -> Self {
        Self {
            data: vec![0u8; capacity],
            access,
        }
    }

    fn range(&self, offset: u64, len: usize) -> Result<std::ops::Range<usize>, BackingError> {
        let offset = usize::try_from(offset).map_err(|_| BackingError::OutOfRange)?;
        let end = offset.checked_add(len).ok_or(BackingError::OutOfRange)?;
        if end > self.data.len() {
            return Err(BackingError::OutOfRange);
        }
        Ok(offset..end)
    }
}

/// Host storage operations exposed to the block component.
pub trait BlockBacking {
    fn capacity(&self) -> u64;
    fn access(&self) -> AccessMode;
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), BackingError>;
    fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<(), BackingError>;
    fn discard(&mut self, offset: u64, len: u64) -> Result<(), BackingError>;
    fn sync(&self) -> Result<(), BackingError>;
}

/// The one disk grant bound to a component instance. Capacity and
/// read-only enforcement live in these native methods on every path;
/// a check inside the component never constrains it after compromise.
pub enum DiskGrant {
    #[cfg(any(test, feature = "test-support"))]
    Mem(BoundedDisk),
    File(FileDisk),
    Packed(PackedDisk),
}

impl BlockBacking for DiskGrant {
    fn capacity(&self) -> u64 {
        match self {
            #[cfg(any(test, feature = "test-support"))]
            Self::Mem(disk) => BlockBacking::capacity(disk),
            Self::File(disk) => BlockBacking::capacity(disk),
            Self::Packed(disk) => BlockBacking::capacity(disk),
        }
    }

    fn access(&self) -> AccessMode {
        match self {
            #[cfg(any(test, feature = "test-support"))]
            Self::Mem(disk) => disk.access(),
            Self::File(disk) => disk.access(),
            Self::Packed(disk) => disk.access(),
        }
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), BackingError> {
        match self {
            #[cfg(any(test, feature = "test-support"))]
            Self::Mem(disk) => BlockBacking::read_at(disk, offset, buf),
            Self::File(disk) => BlockBacking::read_at(disk, offset, buf),
            Self::Packed(disk) => BlockBacking::read_at(disk, offset, buf),
        }
    }

    fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<(), BackingError> {
        match self {
            #[cfg(any(test, feature = "test-support"))]
            Self::Mem(disk) => BlockBacking::write_at(disk, offset, buf),
            Self::File(disk) => BlockBacking::write_at(disk, offset, buf),
            Self::Packed(disk) => BlockBacking::write_at(disk, offset, buf),
        }
    }

    fn discard(&mut self, offset: u64, len: u64) -> Result<(), BackingError> {
        match self {
            #[cfg(any(test, feature = "test-support"))]
            Self::Mem(disk) => BlockBacking::discard(disk, offset, len),
            Self::File(disk) => BlockBacking::discard(disk, offset, len),
            Self::Packed(disk) => BlockBacking::discard(disk, offset, len),
        }
    }

    fn sync(&self) -> Result<(), BackingError> {
        match self {
            #[cfg(any(test, feature = "test-support"))]
            Self::Mem(disk) => BlockBacking::sync(disk),
            Self::File(disk) => BlockBacking::sync(disk),
            Self::Packed(disk) => BlockBacking::sync(disk),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackingError {
    OutOfRange,
    ReadOnly,
    Io,
}

#[cfg(any(test, feature = "test-support"))]
impl BlockBacking for BoundedDisk {
    fn capacity(&self) -> u64 {
        u64::try_from(self.data.len()).unwrap_or(u64::MAX)
    }

    fn access(&self) -> AccessMode {
        self.access
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), BackingError> {
        buf.copy_from_slice(&self.data[self.range(offset, buf.len())?]);
        Ok(())
    }

    fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<(), BackingError> {
        if self.access.is_read_only() {
            return Err(BackingError::ReadOnly);
        }
        let range = self.range(offset, buf.len())?;
        self.data[range].copy_from_slice(buf);
        Ok(())
    }

    fn discard(&mut self, offset: u64, len: u64) -> Result<(), BackingError> {
        if self.access.is_read_only() {
            return Err(BackingError::ReadOnly);
        }
        let len = usize::try_from(len).map_err(|_| BackingError::OutOfRange)?;
        let range = self.range(offset, len)?;
        self.data[range].fill(0);
        Ok(())
    }

    fn sync(&self) -> Result<(), BackingError> {
        Ok(())
    }
}

/// Read-only disk decoded chunk by chunk from a packed image; one decoded
/// chunk stays cached.
pub struct PackedDisk {
    image: PackedImage<'static>,
    cache: std::sync::Mutex<ChunkCache>,
}

impl PackedDisk {
    #[must_use]
    pub fn new(image: PackedImage<'static>) -> Self {
        let cache = std::sync::Mutex::new(ChunkCache::new(&image));
        Self { image, cache }
    }
}

fn check_range(capacity: u64, offset: u64, len: u64) -> Result<(), BackingError> {
    let end = offset.checked_add(len).ok_or(BackingError::OutOfRange)?;
    if end > capacity {
        return Err(BackingError::OutOfRange);
    }
    Ok(())
}

impl BlockBacking for PackedDisk {
    fn capacity(&self) -> u64 {
        self.image.image_bytes()
    }

    fn access(&self) -> AccessMode {
        AccessMode::ReadOnly
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), BackingError> {
        check_range(self.capacity(), offset, buf.len() as u64)?;
        let mut cache = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.image
            .read_at(offset, buf, &mut cache)
            .map_err(|_| BackingError::Io)
    }

    fn write_at(&mut self, _offset: u64, _buf: &[u8]) -> Result<(), BackingError> {
        Err(BackingError::ReadOnly)
    }

    fn discard(&mut self, _offset: u64, _len: u64) -> Result<(), BackingError> {
        Err(BackingError::ReadOnly)
    }

    fn sync(&self) -> Result<(), BackingError> {
        Ok(())
    }
}

/// File-backed grant: the image opened with its real read-only or
/// read-write mode, capacity fixed at the pre-grown length. There is
/// no resize or truncate path, so a compromised component cannot grow
/// the image through this handle; writes are positional loops that
/// either complete fully or report `Io`.
pub struct FileDisk {
    file: std::fs::File,
    capacity: u64,
    access: AccessMode,
}

impl FileDisk {
    pub fn open(path: &std::path::Path, access: AccessMode) -> std::io::Result<Self> {
        let file = terra_platform::filesystem::disk::open_disk(path, access.is_read_only())?;
        let capacity = file.metadata()?.len();
        Ok(Self {
            file,
            capacity,
            access,
        })
    }
}

impl BlockBacking for FileDisk {
    fn capacity(&self) -> u64 {
        self.capacity
    }

    fn access(&self) -> AccessMode {
        self.access
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), BackingError> {
        check_range(self.capacity, offset, buf.len() as u64)?;
        terra_platform::filesystem::disk::read_exact_at(&self.file, offset, buf)
            .map_err(|_| BackingError::Io)
    }

    fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<(), BackingError> {
        if self.access.is_read_only() {
            return Err(BackingError::ReadOnly);
        }
        check_range(self.capacity, offset, buf.len() as u64)?;
        terra_platform::filesystem::disk::write_all_at(&self.file, offset, buf)
            .map_err(|_| BackingError::Io)
    }

    fn discard(&mut self, offset: u64, len: u64) -> Result<(), BackingError> {
        if self.access.is_read_only() {
            return Err(BackingError::ReadOnly);
        }
        check_range(self.capacity, offset, len)?;
        terra_platform::filesystem::disk::discard(&self.file, offset, len)
            .map_err(|_| BackingError::Io)
    }

    fn sync(&self) -> Result<(), BackingError> {
        self.file.sync_all().map_err(|_| BackingError::Io)
    }
}

#[cfg(test)]
mod file_tests {
    use super::{BackingError, BlockBacking, FileDisk};
    use crate::component::AccessMode;

    fn backing_file() -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().unwrap();
        file.as_file().set_len(4096).unwrap();
        file
    }

    #[test]
    fn file_round_trip_persists_across_reopen() {
        let file = backing_file();
        {
            let mut disk = FileDisk::open(file.path(), AccessMode::ReadWrite).unwrap();
            disk.write_at(1536, &[0xAB; 512]).unwrap();
            disk.sync().unwrap();
        }
        let disk = FileDisk::open(file.path(), AccessMode::ReadOnly).unwrap();
        let mut bytes = [0; 512];
        disk.read_at(1536, &mut bytes).unwrap();
        assert_eq!(bytes, [0xAB; 512]);
    }

    #[test]
    fn file_bounds_reject_past_end_and_overflow_without_extending_the_image() {
        let file = backing_file();
        let mut disk = FileDisk::open(file.path(), AccessMode::ReadWrite).unwrap();
        assert_eq!(disk.capacity(), 4096);
        for offset in [4096, u64::MAX] {
            assert_eq!(
                disk.read_at(offset, &mut [0]),
                Err(BackingError::OutOfRange)
            );
            assert_eq!(disk.write_at(offset, &[1]), Err(BackingError::OutOfRange));
            assert_eq!(disk.discard(offset, 1), Err(BackingError::OutOfRange));
        }
        assert_eq!(file.as_file().metadata().unwrap().len(), 4096);
        file.as_file().set_len(8192).unwrap();
        assert_eq!(disk.capacity(), 4096);
        assert_eq!(disk.write_at(4096, &[1]), Err(BackingError::OutOfRange));
    }

    #[test]
    fn file_readonly_rejects_writes_and_discard() {
        let file = backing_file();
        let mut disk = FileDisk::open(file.path(), AccessMode::ReadOnly).unwrap();
        assert_eq!(disk.write_at(0, &[1]), Err(BackingError::ReadOnly));
        assert_eq!(disk.discard(0, 512), Err(BackingError::ReadOnly));
        let mut bytes = [1; 512];
        disk.read_at(0, &mut bytes).unwrap();
        assert_eq!(bytes, [0; 512]);
    }
}

#[cfg(test)]
mod packed_tests {
    use super::{BackingError, BlockBacking, PackedDisk};
    use crate::component::AccessMode;
    use terra_protocol::guest_image::GuestImage;
    use terra_protocol::packed_image::{
        PackedImage, chunk_bytes, compress_fast, pack, pack_fast_leaked,
    };

    const CHUNK: usize = chunk_bytes(GuestImage::Boot) as usize;

    fn contents() -> Vec<u8> {
        (0..2 * CHUNK + 100)
            .map(|index| u8::try_from((index * 13 + index / 97) % 256).unwrap())
            .collect()
    }

    fn disk() -> PackedDisk {
        PackedDisk::new(pack_fast_leaked(&contents(), GuestImage::Boot).unwrap())
    }

    /// A disk whose chunks listed by `is_corrupt` decode to bytes that fail their CRC.
    fn disk_with_corrupt_chunks(is_corrupt: impl Fn(usize) -> bool) -> PackedDisk {
        let mut index = 0;
        let packed = pack(&contents(), GuestImage::Boot, |chunk| {
            let mut bytes = chunk.to_vec();
            if is_corrupt(index) {
                bytes[0] ^= 1;
            }
            index += 1;
            compress_fast(&bytes)
        })
        .unwrap();
        PackedDisk::new(PackedImage::parse(packed.leak(), GuestImage::Boot).unwrap())
    }

    /// Reads inside one chunk, across chunk boundaries and ending exactly at
    /// capacity all return the original bytes.
    #[test]
    fn reads_match_the_image_across_chunks_and_at_the_end() {
        let image = contents();
        let disk = disk();
        assert_eq!(disk.capacity(), image.len() as u64);
        assert_eq!(disk.access(), AccessMode::ReadOnly);
        for (offset, len) in [
            (0, 512),
            (CHUNK - 10, 20),
            (CHUNK - 10, CHUNK + 20),
            (3, image.len() - 3),
            (image.len() - 7, 7),
            (image.len(), 0),
        ] {
            let mut bytes = vec![0; len];
            disk.read_at(offset as u64, &mut bytes).unwrap();
            assert_eq!(bytes, image[offset..offset + len], "{offset}+{len}");
        }
    }

    /// Guest-chosen offsets and lengths past capacity, or that overflow, are
    /// refused before any chunk is decoded: on a disk where every chunk is
    /// corrupt, a decode would have reported `Io` instead.
    #[test]
    fn out_of_range_reads_are_refused() {
        let disk = disk_with_corrupt_chunks(|_| true);
        let capacity = disk.capacity();
        let mut bytes = [0; 8];
        for offset in [capacity - 7, capacity, u64::MAX - 3, u64::MAX] {
            assert_eq!(
                disk.read_at(offset, &mut bytes),
                Err(BackingError::OutOfRange)
            );
        }
    }

    /// The disk is read-only on every mutation path.
    #[test]
    fn writes_and_discards_are_refused() {
        let mut disk = disk();
        assert_eq!(disk.write_at(0, &[1]), Err(BackingError::ReadOnly));
        assert_eq!(disk.discard(0, 1), Err(BackingError::ReadOnly));
        assert_eq!(disk.sync(), Ok(()));
    }

    /// A chunk that fails its checksum surfaces as an I/O error, and the failed
    /// decode, which overwrote the cache buffer, never serves the previously
    /// cached chunk's bytes as that chunk again.
    #[test]
    fn a_corrupt_chunk_is_an_io_error_and_leaves_no_stale_cache() {
        let image = contents();
        let disk = disk_with_corrupt_chunks(|index| index == 0);
        let mut bytes = [0; 16];
        disk.read_at(CHUNK as u64, &mut bytes).unwrap();
        assert_eq!(disk.read_at(0, &mut bytes), Err(BackingError::Io));
        disk.read_at(CHUNK as u64, &mut bytes).unwrap();
        assert_eq!(bytes, image[CHUNK..CHUNK + 16]);
    }
}
