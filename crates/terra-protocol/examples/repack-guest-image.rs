use std::{env, fs, io, io::Read};

use lz4::block::{CompressionMode, compress};
use terra_protocol::guest_image::GuestImage;
use terra_protocol::packed_image::{ChunkCache, PackedImage, pack};

const HIGH_COMPRESSION_LEVEL: i32 = 12;

fn main() -> io::Result<()> {
    let arguments: Vec<_> = env::args_os().skip(1).collect();
    let [kind, source, destination] = arguments.as_slice() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: repack-guest-image boot|kernel INPUT.gz OUTPUT.tlz4",
        ));
    };
    let kind = match kind.to_str() {
        Some("boot") => GuestImage::Boot,
        Some("kernel") => GuestImage::Kernel,
        Some(_) | None => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "guest image kind must be boot or kernel",
            ));
        }
    };
    let mut decoder = flate2::read::GzDecoder::new(fs::File::open(source)?);
    kind.validate(decoder.header().and_then(flate2::GzHeader::extra))?;
    let mut image = Vec::new();
    decoder.read_to_end(&mut image)?;
    let mode = Some(CompressionMode::HIGHCOMPRESSION(HIGH_COMPRESSION_LEVEL));
    let packed = pack(&image, kind, |chunk| compress(chunk, mode, false))?;
    // The C encoder's output is decoded here so a bad block fails the build, not a boot.
    let parsed = PackedImage::parse(&packed, kind)?;
    let mut round_trip = vec![0; image.len()];
    parsed.read_at(0, &mut round_trip, &mut ChunkCache::new(&parsed))?;
    if round_trip != image {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "packed image does not decode back to its input",
        ));
    }
    fs::write(destination, packed)
}
