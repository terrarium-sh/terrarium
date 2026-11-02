//! Chunked LZ4 container for the embedded guest kernel and boot disk.

use crate::guest_image::{GuestImage, MARKER_BYTES};
use std::io;
use std::ops::Range;

const MAGIC: [u8; 8] = *b"TERRALZ\x02";
const KERNEL_CHUNK_BYTES: u32 = 1024 * 1024;
const BOOT_CHUNK_BYTES: u32 = 64 * 1024;

const MAGIC_RANGE: Range<usize> = 0..MAGIC.len();
const MARKER_RANGE: Range<usize> = MAGIC_RANGE.end..MAGIC_RANGE.end + MARKER_BYTES;
const IMAGE_BYTES_RANGE: Range<usize> = MARKER_RANGE.end..MARKER_RANGE.end + 8;
const HEADER_BYTES: usize = IMAGE_BYTES_RANGE.end;
/// A chunk table entry: the chunk's compressed size.
const TABLE_ENTRY_BYTES: usize = 4;

#[must_use]
pub const fn chunk_bytes(kind: GuestImage) -> u32 {
    match kind {
        GuestImage::Kernel => KERNEL_CHUNK_BYTES,
        GuestImage::Boot => BOOT_CHUNK_BYTES,
    }
}

/// Whether `bytes` carries `kind`'s marker where a packed image does.
#[must_use]
pub const fn has_marker(bytes: &[u8], kind: GuestImage) -> bool {
    if bytes.len() < MARKER_RANGE.end {
        return false;
    }
    let (_, rest) = bytes.split_at(MARKER_RANGE.start);
    let (marker, _) = rest.split_at(MARKER_BYTES);
    kind.is_marker(marker)
}

fn invalid_data_error(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_owned())
}

/// A parsed container whose chunks are decoded on demand, keeping the last partly read chunk.
#[derive(Clone)]
pub struct PackedImage<'a> {
    image_bytes: u64,
    chunk_bytes: usize,
    /// Each chunk's LZ4 block within `payload`.
    blocks: Vec<Range<usize>>,
    payload: &'a [u8],
    cached_index: Option<usize>,
    cached_bytes: Vec<u8>,
}

impl<'a> PackedImage<'a> {
    /// Validates the whole layout without decompressing anything. The content carries no checksum:
    /// packed images are trusted build artifacts, embedded in the binary and round-tripped when
    /// packed, so a block that decodes to the right length is used as is.
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
        let image_bytes = u64::from_le_bytes(
            header[IMAGE_BYTES_RANGE]
                .try_into()
                .map_err(io::Error::other)?,
        );
        if image_bytes == 0 {
            return Err(invalid_data_error("packed image is empty"));
        }
        let chunk_size = chunk_bytes(kind) as usize;
        let table_end = usize::try_from(image_bytes.div_ceil(chunk_size as u64))
            .ok()
            .and_then(|chunk_count| chunk_count.checked_mul(TABLE_ENTRY_BYTES))
            .and_then(|table| table.checked_add(HEADER_BYTES))
            .ok_or_else(|| invalid_data_error("packed image chunk table overflows"))?;
        let table = bytes
            .get(HEADER_BYTES..table_end)
            .ok_or_else(|| invalid_data_error("packed image chunk table is truncated"))?;
        let max_compressed = lz4_flex::block::get_maximum_output_size(chunk_size);
        let (entries, _) = table.as_chunks::<TABLE_ENTRY_BYTES>();
        let mut blocks = Vec::with_capacity(entries.len());
        let mut payload_bytes = 0usize;
        for entry in entries {
            let compressed_bytes = u32::from_le_bytes(*entry) as usize;
            if compressed_bytes == 0 || compressed_bytes > max_compressed {
                return Err(invalid_data_error(
                    "packed image chunk has an invalid compressed size",
                ));
            }
            let end = payload_bytes
                .checked_add(compressed_bytes)
                .ok_or_else(|| invalid_data_error("packed image payload size overflows"))?;
            blocks.push(payload_bytes..end);
            payload_bytes = end;
        }
        let payload = &bytes[table_end..];
        if payload.len() != payload_bytes {
            return Err(invalid_data_error(
                "packed image payload length does not match its chunk table",
            ));
        }
        Ok(Self {
            image_bytes,
            chunk_bytes: chunk_size,
            blocks,
            payload,
            cached_index: None,
            cached_bytes: Vec::new(),
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

    /// Fills `buf` from `offset`. A read covering a whole chunk decodes it straight into `buf`;
    /// a partly read chunk is decoded into the cache unless it is already there.
    pub fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
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
        let payload = self.payload;
        let mut position = offset;
        let mut copied = 0;
        let chunk_size = self.chunk_bytes as u64;
        while copied < buf.len() {
            let index = usize::try_from(position / chunk_size).map_err(io::Error::other)?;
            let within = usize::try_from(position % chunk_size).map_err(io::Error::other)?;
            let chunk_len = self.chunk_len(index);
            let block = &payload[self.blocks[index].clone()];
            let wanted = buf.len() - copied;
            let take = if within == 0 && wanted >= chunk_len {
                decode_block(block, &mut buf[copied..copied + chunk_len])?;
                chunk_len
            } else {
                if self.cached_index != Some(index) {
                    self.cached_index = None;
                    self.cached_bytes.resize(self.chunk_bytes, 0);
                    decode_block(block, &mut self.cached_bytes[..chunk_len])?;
                    self.cached_index = Some(index);
                }
                let take = (chunk_len - within).min(wanted);
                buf[copied..copied + take]
                    .copy_from_slice(&self.cached_bytes[within..within + take]);
                take
            };
            copied += take;
            position += take as u64;
        }
        Ok(())
    }
}

fn decode_block(block: &[u8], out: &mut [u8]) -> io::Result<()> {
    let decoded = lz4_flex::block::decompress_into(block, out)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if decoded != out.len() {
        return Err(invalid_data_error(
            "packed image chunk decodes to the wrong length",
        ));
    }
    Ok(())
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
    let chunk_size = chunk_bytes(kind) as usize;
    let max_compressed = lz4_flex::block::get_maximum_output_size(chunk_size);
    let mut table = Vec::new();
    let mut payload = Vec::new();
    for chunk in image.chunks(chunk_size) {
        let block = compress_block(chunk)?;
        if block.is_empty() || block.len() > max_compressed {
            return Err(invalid_data_error("compressed chunk has an invalid size"));
        }
        let block_len = u32::try_from(block.len()).map_err(io::Error::other)?;
        table.extend_from_slice(&block_len.to_le_bytes());
        payload.extend_from_slice(&block);
    }
    let mut packed = Vec::with_capacity(HEADER_BYTES + table.len() + payload.len());
    packed.extend_from_slice(&MAGIC);
    packed.extend_from_slice(&kind.marker());
    packed.extend_from_slice(&(image.len() as u64).to_le_bytes());
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

    fn read_all(image: &mut PackedImage<'_>) -> io::Result<Vec<u8>> {
        let mut out = vec![0; usize::try_from(image.image_bytes()).unwrap()];
        image.read_at(0, &mut out)?;
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
            let mut parsed = PackedImage::parse(&packed, kind).unwrap();
            assert_eq!(parsed.image_bytes(), image.len() as u64);
            assert_eq!(parsed.blocks.len(), 3);
            assert_eq!(parsed.chunk_len(0), parsed.chunk_bytes);
            assert_eq!(parsed.chunk_len(2), image.len() - 2 * parsed.chunk_bytes);
            assert_eq!(read_all(&mut parsed).unwrap(), image);
        }
    }

    /// Reads inside a chunk, across boundaries, ending at the image end and empty ones match
    /// the image; reads past the end or overflowing are refused.
    #[test]
    fn read_at_matches_the_image_and_refuses_out_of_range() {
        let image = boot_image();
        let packed = pack_lz4(&image, GuestImage::Boot);
        let mut parsed = PackedImage::parse(&packed, GuestImage::Boot).unwrap();
        let chunk = parsed.chunk_bytes;
        for (offset, len) in [
            (0, 512),
            (chunk - 10, 20),
            (chunk - 10, chunk + 20),
            (0, chunk),
            (chunk, chunk + 50),
            (image.len() - 7, 7),
            (image.len(), 0),
        ] {
            let mut bytes = vec![0; len];
            parsed.read_at(offset as u64, &mut bytes).unwrap();
            assert_eq!(bytes, image[offset..offset + len], "{offset}+{len}");
        }
        for offset in [image.len() as u64 - 7, u64::MAX] {
            let error = parsed.read_at(offset, &mut [0; 8]).unwrap_err();
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
        assert!(has_marker(&packed, GuestImage::Boot));
        assert!(!has_marker(&packed, GuestImage::Kernel));
        assert!(!has_marker(
            &packed[..MARKER_RANGE.end - 1],
            GuestImage::Boot
        ));
        let error = PackedImage::parse(&packed, GuestImage::Kernel)
            .err()
            .unwrap();
        assert!(error.to_string().contains("rebuild"), "{error}");
        let mut bytes = packed;
        bytes[MARKER_RANGE.start] ^= 1;
        assert!(!has_marker(&bytes, GuestImage::Boot));
        assert_invalid(PackedImage::parse(&bytes, GuestImage::Boot));
    }

    /// An image length whose chunk count disagrees with the chunk table is refused.
    #[test]
    fn parse_rejects_inconsistent_header_fields() {
        let packed = pack_lz4(&boot_image(), GuestImage::Boot);
        let patched = |range: Range<usize>, value: &[u8]| {
            let mut bytes = packed.clone();
            bytes[range].copy_from_slice(value);
            bytes
        };
        for bytes in [
            patched(IMAGE_BYTES_RANGE, &0u64.to_le_bytes()),
            patched(IMAGE_BYTES_RANGE, &u64::MAX.to_le_bytes()),
            patched(
                IMAGE_BYTES_RANGE,
                &u64::from(2 * BOOT_CHUNK_BYTES).to_le_bytes(),
            ),
            patched(
                IMAGE_BYTES_RANGE,
                &u64::from(3 * BOOT_CHUNK_BYTES + 1).to_le_bytes(),
            ),
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

    /// A read covering a whole chunk decodes it without evicting the partly read chunk.
    #[test]
    fn whole_chunk_reads_leave_the_cached_chunk_in_place() {
        let image = boot_image();
        let packed = pack_lz4(&image, GuestImage::Boot);
        let mut parsed = PackedImage::parse(&packed, GuestImage::Boot).unwrap();
        let chunk = parsed.chunk_bytes;
        parsed.read_at(10, &mut [0; 1]).unwrap();
        let mut whole = vec![0; chunk];
        parsed.read_at(chunk as u64, &mut whole).unwrap();
        assert_eq!(whole, image[chunk..2 * chunk]);
        assert_eq!(parsed.cached_index, Some(0));
    }

    /// Damaged LZ4 data is refused, and the failed decode leaves no cached chunk behind.
    #[test]
    fn read_rejects_corrupt_blocks_and_invalidates_the_cache() {
        let image = boot_image();
        let mut packed = pack_lz4(&image, GuestImage::Boot);
        let last_block = PackedImage::parse(&packed, GuestImage::Boot)
            .unwrap()
            .blocks[2]
            .len();
        let payload_end = packed.len();
        packed[payload_end - last_block..].fill(0xff);
        let mut parsed = PackedImage::parse(&packed, GuestImage::Boot).unwrap();
        let last_chunk = 2 * parsed.chunk_bytes as u64;
        parsed.read_at(0, &mut [0; 1]).unwrap();
        assert!(parsed.read_at(last_chunk, &mut [0; 1]).is_err());
        assert_eq!(parsed.cached_index, None);
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
