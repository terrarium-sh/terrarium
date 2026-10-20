//! Chunked LZ4 container for the embedded guest kernel and boot disk.

use crate::guest_image::GuestImage;
use std::io;
use std::ops::Range;

const MAGIC: [u8; 8] = *b"TERRALZ\x01";
const KERNEL_CHUNK_BYTES: u32 = 1024 * 1024;
const BOOT_CHUNK_BYTES: u32 = 64 * 1024;

const MAGIC_RANGE: Range<usize> = 0..8;
const MARKER_RANGE: Range<usize> = 8..20;
const CHUNK_BYTES_RANGE: Range<usize> = 20..24;
const IMAGE_BYTES_RANGE: Range<usize> = 24..32;
const CHUNK_COUNT_RANGE: Range<usize> = 32..36;
const HEADER_BYTES: usize = 36;
const TABLE_ENTRY_BYTES: usize = 8;
const ENTRY_CRC_AT: usize = 4;

#[must_use]
pub const fn chunk_bytes(kind: GuestImage) -> u32 {
    match kind {
        GuestImage::Kernel => KERNEL_CHUNK_BYTES,
        GuestImage::Boot => BOOT_CHUNK_BYTES,
    }
}

fn invalid_data_error(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_owned())
}

fn le_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(std::array::from_fn(|index| bytes[index]))
}

fn le_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(std::array::from_fn(|index| bytes[index]))
}

#[derive(Clone, Copy)]
struct Chunk {
    payload_start: usize,
    compressed_bytes: usize,
    crc32: u32,
}

/// A parsed container whose chunks are decoded on demand.
#[derive(Clone)]
pub struct PackedImage<'a> {
    image_bytes: u64,
    chunk_bytes: usize,
    chunks: Vec<Chunk>,
    payload: &'a [u8],
}

/// The one decoded chunk that [`PackedImage::read_at`] keeps between reads.
pub struct ChunkCache {
    index: Option<usize>,
    bytes: Vec<u8>,
}

impl ChunkCache {
    #[must_use]
    pub fn new(image: &PackedImage<'_>) -> Self {
        Self {
            index: None,
            bytes: vec![0; image.chunk_bytes],
        }
    }
}

impl<'a> PackedImage<'a> {
    /// Validates the whole layout without decompressing anything.
    pub fn parse(bytes: &'a [u8], kind: GuestImage) -> io::Result<Self> {
        let header = bytes
            .get(..HEADER_BYTES)
            .ok_or_else(|| invalid_data_error("packed image header is truncated"))?;
        if header[MAGIC_RANGE] != MAGIC {
            return Err(invalid_data_error(
                "guest image is not a packed image of this container version",
            ));
        }
        kind.validate(Some(&header[MARKER_RANGE]))?;
        let expected_chunk_bytes = chunk_bytes(kind);
        if le_u32(&header[CHUNK_BYTES_RANGE]) != expected_chunk_bytes {
            return Err(invalid_data_error(
                "packed image chunk size does not match its kind",
            ));
        }
        let image_bytes = le_u64(&header[IMAGE_BYTES_RANGE]);
        if image_bytes == 0 {
            return Err(invalid_data_error("packed image is empty"));
        }
        let chunk_count = le_u32(&header[CHUNK_COUNT_RANGE]);
        if u64::from(chunk_count) != image_bytes.div_ceil(u64::from(expected_chunk_bytes)) {
            return Err(invalid_data_error(
                "packed image chunk count does not match its length",
            ));
        }
        let chunk_bytes = expected_chunk_bytes as usize;
        let table_end = (chunk_count as usize)
            .checked_mul(TABLE_ENTRY_BYTES)
            .and_then(|table| table.checked_add(HEADER_BYTES))
            .ok_or_else(|| invalid_data_error("packed image chunk table overflows"))?;
        let table = bytes
            .get(HEADER_BYTES..table_end)
            .ok_or_else(|| invalid_data_error("packed image chunk table is truncated"))?;
        let max_compressed = lz4_flex::block::get_maximum_output_size(chunk_bytes);
        let (entries, _) = table.as_chunks::<TABLE_ENTRY_BYTES>();
        let mut chunks = Vec::with_capacity(entries.len());
        let mut payload_bytes = 0usize;
        for entry in entries {
            let compressed_bytes = le_u32(&entry[..ENTRY_CRC_AT]) as usize;
            if compressed_bytes == 0 || compressed_bytes > max_compressed {
                return Err(invalid_data_error(
                    "packed image chunk has an invalid compressed size",
                ));
            }
            chunks.push(Chunk {
                payload_start: payload_bytes,
                compressed_bytes,
                crc32: le_u32(&entry[ENTRY_CRC_AT..]),
            });
            payload_bytes = payload_bytes
                .checked_add(compressed_bytes)
                .ok_or_else(|| invalid_data_error("packed image payload size overflows"))?;
        }
        let payload = &bytes[table_end..];
        if payload.len() != payload_bytes {
            return Err(invalid_data_error(
                "packed image payload length does not match its chunk table",
            ));
        }
        Ok(Self {
            image_bytes,
            chunk_bytes,
            chunks,
            payload,
        })
    }

    #[must_use]
    pub fn image_bytes(&self) -> u64 {
        self.image_bytes
    }

    /// The decoded size of chunk `index`; only the last chunk can be short.
    fn chunk_len(&self, index: usize) -> usize {
        let remaining = self.image_bytes - (index as u64) * (self.chunk_bytes as u64);
        usize::try_from(remaining).map_or(self.chunk_bytes, |remaining| {
            remaining.min(self.chunk_bytes)
        })
    }

    fn decode_chunk(&self, index: usize, out: &mut [u8]) -> io::Result<()> {
        let chunk = self.chunks[index];
        let block =
            &self.payload[chunk.payload_start..chunk.payload_start + chunk.compressed_bytes];
        let decoded = lz4_flex::block::decompress_into(block, out)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if decoded != out.len() {
            return Err(invalid_data_error(
                "packed image chunk decodes to the wrong length",
            ));
        }
        if crc32fast::hash(out) != chunk.crc32 {
            return Err(invalid_data_error("packed image chunk fails its checksum"));
        }
        Ok(())
    }

    /// Fills `buf` from `offset`, decoding only the chunks `cache` does not hold.
    /// `cache` must come from [`ChunkCache::new`] on this image.
    pub fn read_at(&self, offset: u64, buf: &mut [u8], cache: &mut ChunkCache) -> io::Result<()> {
        let in_range = u64::try_from(buf.len())
            .ok()
            .and_then(|len| offset.checked_add(len))
            .is_some_and(|end| end <= self.image_bytes);
        if !in_range {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "read lies outside the packed image",
            ));
        }
        let mut position = offset;
        let mut copied = 0;
        while copied < buf.len() {
            let chunk_bytes = self.chunk_bytes as u64;
            let index = usize::try_from(position / chunk_bytes).map_err(io::Error::other)?;
            let within = usize::try_from(position % chunk_bytes).map_err(io::Error::other)?;
            let chunk_len = self.chunk_len(index);
            if cache.index != Some(index) {
                cache.index = None;
                self.decode_chunk(index, &mut cache.bytes[..chunk_len])?;
                cache.index = Some(index);
            }
            let take = (chunk_len - within).min(buf.len() - copied);
            buf[copied..copied + take].copy_from_slice(&cache.bytes[within..within + take]);
            copied += take;
            position += take as u64;
        }
        Ok(())
    }
}

/// Builds the container; `compress_block` compresses one chunk to an LZ4 block.
pub fn pack(
    image: &[u8],
    kind: GuestImage,
    mut compress_block: impl FnMut(&[u8]) -> io::Result<Vec<u8>>,
) -> io::Result<Vec<u8>> {
    if image.is_empty() {
        return Err(invalid_data_error("cannot pack an empty image"));
    }
    let chunk_bytes = chunk_bytes(kind);
    let chunk_size = chunk_bytes as usize;
    let max_compressed = lz4_flex::block::get_maximum_output_size(chunk_size);
    let chunk_count = u32::try_from(image.len().div_ceil(chunk_size)).map_err(io::Error::other)?;
    let mut table = Vec::new();
    let mut payload = Vec::new();
    for chunk in image.chunks(chunk_size) {
        let block = compress_block(chunk)?;
        if block.is_empty() || block.len() > max_compressed {
            return Err(invalid_data_error("compressed chunk has an invalid size"));
        }
        let block_len = u32::try_from(block.len()).map_err(io::Error::other)?;
        table.extend_from_slice(&block_len.to_le_bytes());
        table.extend_from_slice(&crc32fast::hash(chunk).to_le_bytes());
        payload.extend_from_slice(&block);
    }
    let mut packed = Vec::with_capacity(HEADER_BYTES + table.len() + payload.len());
    packed.extend_from_slice(&MAGIC);
    packed.extend_from_slice(&kind.marker());
    packed.extend_from_slice(&chunk_bytes.to_le_bytes());
    packed.extend_from_slice(&(image.len() as u64).to_le_bytes());
    packed.extend_from_slice(&chunk_count.to_le_bytes());
    packed.extend_from_slice(&table);
    packed.extend_from_slice(&payload);
    Ok(packed)
}

/// The fast LZ4 block compressor, for [`pack`] in tests.
#[cfg(any(test, feature = "test-support"))]
pub fn compress_fast(chunk: &[u8]) -> io::Result<Vec<u8>> {
    Ok(lz4_flex::block::compress(chunk))
}

/// Packs and parses `image` with [`compress_fast`], leaking the packed bytes; a test fixture.
#[cfg(any(test, feature = "test-support"))]
pub fn pack_fast_leaked(image: &[u8], kind: GuestImage) -> io::Result<PackedImage<'static>> {
    PackedImage::parse(pack(image, kind, compress_fast)?.leak(), kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(len: usize) -> Vec<u8> {
        (0..len)
            .map(|index| u8::try_from((index * 7 + index / 251) % 256).unwrap())
            .collect()
    }

    fn pack_lz4(image: &[u8], kind: GuestImage) -> Vec<u8> {
        pack(image, kind, compress_fast).unwrap()
    }

    fn read_all(image: &PackedImage<'_>) -> io::Result<Vec<u8>> {
        let mut out = vec![0; usize::try_from(image.image_bytes()).unwrap()];
        image.read_at(0, &mut out, &mut ChunkCache::new(image))?;
        Ok(out)
    }

    fn boot_image() -> Vec<u8> {
        sample(2 * BOOT_CHUNK_BYTES as usize + 100)
    }

    fn assert_invalid(result: io::Result<PackedImage<'_>>) {
        assert_eq!(result.err().unwrap().kind(), io::ErrorKind::InvalidData);
    }

    /// Multi-chunk images with a short last chunk survive pack, parse and decode.
    #[test]
    fn round_trips_with_a_short_last_chunk() {
        for (kind, image) in [
            (GuestImage::Boot, boot_image()),
            (
                GuestImage::Kernel,
                sample(2 * KERNEL_CHUNK_BYTES as usize + 5),
            ),
        ] {
            let packed = pack_lz4(&image, kind);
            let parsed = PackedImage::parse(&packed, kind).unwrap();
            assert_eq!(parsed.image_bytes(), image.len() as u64);
            assert_eq!(parsed.chunks.len(), 3);
            assert_eq!(parsed.chunk_len(0), parsed.chunk_bytes);
            assert_eq!(parsed.chunk_len(2), image.len() - 2 * parsed.chunk_bytes);
            assert_eq!(read_all(&parsed).unwrap(), image);
        }
    }

    /// Reads inside a chunk, across boundaries, ending at the image end and empty ones match
    /// the image; reads past the end or overflowing are refused.
    #[test]
    fn read_at_matches_the_image_and_refuses_out_of_range() {
        let image = boot_image();
        let packed = pack_lz4(&image, GuestImage::Boot);
        let parsed = PackedImage::parse(&packed, GuestImage::Boot).unwrap();
        let mut cache = ChunkCache::new(&parsed);
        let chunk = parsed.chunk_bytes;
        for (offset, len) in [
            (0, 512),
            (chunk - 10, 20),
            (chunk - 10, chunk + 20),
            (image.len() - 7, 7),
            (image.len(), 0),
        ] {
            let mut bytes = vec![0; len];
            parsed
                .read_at(offset as u64, &mut bytes, &mut cache)
                .unwrap();
            assert_eq!(bytes, image[offset..offset + len], "{offset}+{len}");
        }
        for offset in [image.len() as u64 - 7, u64::MAX] {
            let error = parsed.read_at(offset, &mut [0; 8], &mut cache).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        }
    }

    /// A bad magic or a different container version is refused before anything else.
    #[test]
    fn parse_rejects_bad_magic_and_container_version() {
        let packed = pack_lz4(&boot_image(), GuestImage::Boot);
        for index in [0, MAGIC.len() - 1] {
            let mut bytes = packed.clone();
            bytes[index] ^= 1;
            assert_invalid(PackedImage::parse(&bytes, GuestImage::Boot));
        }
    }

    /// The marker check keeps the guest image's "rebuild" error, and a kernel is not a boot disk.
    #[test]
    fn parse_rejects_wrong_marker_and_kind() {
        let packed = pack_lz4(&boot_image(), GuestImage::Boot);
        let error = PackedImage::parse(&packed, GuestImage::Kernel)
            .err()
            .unwrap();
        assert!(error.to_string().contains("rebuild"), "{error}");
        let mut bytes = packed;
        bytes[MARKER_RANGE.start] ^= 1;
        assert_invalid(PackedImage::parse(&bytes, GuestImage::Boot));
    }

    /// Header fields that disagree with the kind or with each other are refused.
    #[test]
    fn parse_rejects_inconsistent_header_fields() {
        let packed = pack_lz4(&boot_image(), GuestImage::Boot);
        let patched = |range: Range<usize>, value: &[u8]| {
            let mut bytes = packed.clone();
            bytes[range].copy_from_slice(value);
            bytes
        };
        for bytes in [
            patched(CHUNK_BYTES_RANGE, &KERNEL_CHUNK_BYTES.to_le_bytes()),
            patched(IMAGE_BYTES_RANGE, &0u64.to_le_bytes()),
            patched(IMAGE_BYTES_RANGE, &u64::MAX.to_le_bytes()),
            patched(CHUNK_COUNT_RANGE, &2u32.to_le_bytes()),
            patched(CHUNK_COUNT_RANGE, &u32::MAX.to_le_bytes()),
        ] {
            assert_invalid(PackedImage::parse(&bytes, GuestImage::Boot));
        }
    }

    /// Truncation anywhere in the header, table or payload, and trailing bytes, are refused.
    #[test]
    fn parse_rejects_truncation_and_payload_length_mismatch() {
        let packed = pack_lz4(&boot_image(), GuestImage::Boot);
        for len in [0, HEADER_BYTES - 1, HEADER_BYTES + 4, packed.len() - 1] {
            assert_invalid(PackedImage::parse(&packed[..len], GuestImage::Boot));
        }
        let mut longer = packed;
        longer.push(0);
        assert_invalid(PackedImage::parse(&longer, GuestImage::Boot));
    }

    /// A table entry claiming zero or more than LZ4's worst case for a chunk is refused.
    #[test]
    fn parse_rejects_compressed_sizes_outside_the_bound() {
        let packed = pack_lz4(&boot_image(), GuestImage::Boot);
        let bound = u32::try_from(lz4_flex::block::get_maximum_output_size(
            BOOT_CHUNK_BYTES as usize,
        ))
        .unwrap();
        for size in [0, bound + 1] {
            let mut bytes = packed.clone();
            bytes[HEADER_BYTES..HEADER_BYTES + 4].copy_from_slice(&size.to_le_bytes());
            assert_invalid(PackedImage::parse(&bytes, GuestImage::Boot));
        }
    }

    /// A chunk whose checksum differs from the table is refused; the others still read.
    #[test]
    fn read_rejects_a_crc_mismatch() {
        let image = boot_image();
        let mut packed = pack_lz4(&image, GuestImage::Boot);
        packed[HEADER_BYTES + ENTRY_CRC_AT] ^= 1;
        let parsed = PackedImage::parse(&packed, GuestImage::Boot).unwrap();
        let mut cache = ChunkCache::new(&parsed);
        let chunk = parsed.chunk_bytes as u64;
        assert!(parsed.read_at(0, &mut [0; 1], &mut cache).is_err());
        parsed.read_at(chunk, &mut [0; 1], &mut cache).unwrap();
        assert!(read_all(&parsed).is_err());
    }

    /// Damaged LZ4 data is refused, and the failed decode leaves no cached chunk behind.
    #[test]
    fn read_rejects_corrupt_blocks_and_invalidates_the_cache() {
        let image = boot_image();
        let mut packed = pack_lz4(&image, GuestImage::Boot);
        let last = packed.len() - 1;
        packed[last - 10..=last].fill(0xff);
        let parsed = PackedImage::parse(&packed, GuestImage::Boot).unwrap();
        let mut cache = ChunkCache::new(&parsed);
        let last_chunk = 2 * parsed.chunk_bytes as u64;
        parsed.read_at(0, &mut [0; 1], &mut cache).unwrap();
        assert!(parsed.read_at(last_chunk, &mut [0; 1], &mut cache).is_err());
        assert_eq!(cache.index, None);
    }

    /// Packing refuses an empty image, a compressor that exceeds the bound and one that fails.
    #[test]
    fn pack_rejects_empty_images_oversized_blocks_and_compressor_errors() {
        assert!(pack(&[], GuestImage::Boot, compress_fast).is_err());
        let oversized = |_: &[u8]| {
            Ok(vec![
                0;
                lz4_flex::block::get_maximum_output_size(
                    BOOT_CHUNK_BYTES as usize
                ) + 1
            ])
        };
        assert!(pack(&[1], GuestImage::Boot, oversized).is_err());
        let failing = |_: &[u8]| Err(io::Error::other("no"));
        assert!(pack(&[1], GuestImage::Boot, failing).is_err());
    }
}
