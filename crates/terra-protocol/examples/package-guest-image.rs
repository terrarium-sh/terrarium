use std::{env, fs::File, io};

enum ImageKind {
    Boot,
    Kernel,
}

fn main() -> io::Result<()> {
    let arguments: Vec<_> = env::args_os().skip(1).collect();
    let [kind, source, destination] = arguments.as_slice() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: package-guest-image boot|kernel INPUT OUTPUT",
        ));
    };
    let kind = match kind.to_str() {
        Some("boot") => ImageKind::Boot,
        Some("kernel") => ImageKind::Kernel,
        Some(_) | None => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "guest image kind must be boot or kernel",
            ));
        }
    };
    let extra = match kind {
        ImageKind::Boot => terra_protocol::guest_image::boot_image_extra(),
        ImageKind::Kernel => terra_protocol::guest_image::kernel_image_extra(),
    };
    let mut source = File::open(source)?;
    let mut encoder = flate2::GzBuilder::new()
        .mtime(0)
        .extra(extra.to_vec())
        .write(File::create(destination)?, flate2::Compression::best());
    io::copy(&mut source, &mut encoder)?;
    encoder.finish()?;
    Ok(())
}
