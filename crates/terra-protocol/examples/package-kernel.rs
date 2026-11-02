use std::{env, fs::File, io};

use terra_protocol::guest_image::GuestImage;

fn main() -> io::Result<()> {
    let arguments: Vec<_> = env::args_os().skip(1).collect();
    let [source, destination] = arguments.as_slice() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: package-kernel VMLINUX OUTPUT.gz",
        ));
    };
    let mut source = File::open(source)?;
    let mut encoder = flate2::GzBuilder::new()
        .mtime(0)
        .extra(GuestImage::Kernel.marker().to_vec())
        .write(File::create(destination)?, flate2::Compression::best());
    io::copy(&mut source, &mut encoder)?;
    encoder.finish()?;
    Ok(())
}
