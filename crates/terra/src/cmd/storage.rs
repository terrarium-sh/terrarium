//! `terra <box> storage` - the box's guest filesystem and volume images.

use crate::cli::{StorageCmd, StorageFileArgs};
use crate::render::printable_path;
use crate::state::BoxRef;
use crate::{config, resolve, sys};
use anyhow::{Context, Result};
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

pub fn run(
    args: &crate::cli::StorageArgs,
    name: Option<&str>,
    project_dir: &Path,
) -> Result<ExitCode> {
    let bx = resolve::resolve_pinned_box(project_dir, name)?;
    match &args.cmd {
        StorageCmd::Show => show(&bx),
        StorageCmd::Export(StorageFileArgs { file }) => export(&bx, file),
        StorageCmd::Import(StorageFileArgs { file }) => import(&bx, file),
        StorageCmd::Prune => prune(&bx),
    }?;
    Ok(ExitCode::SUCCESS)
}

#[must_use]
fn images_of(bx: &BoxRef) -> Vec<PathBuf> {
    let mut volumes = bx.volume_images();
    volumes.sort();
    std::iter::once(bx.rootfs_img())
        .chain(volumes)
        .filter(|p| p.exists())
        .collect()
}

fn configured_volume_names(bx: &BoxRef) -> Result<Vec<String>> {
    let cfg = config::load_path(&bx.recipe(), bx.project_dir())?;
    Ok(cfg.volumes.into_iter().map(|v| v.name).collect())
}

fn show(bx: &BoxRef) -> Result<()> {
    let images = images_of(bx);
    if images.is_empty() {
        eprintln!(
            "terra: {bx} has no images yet - `terra {} setup` builds them",
            bx.name()
        );
        return Ok(());
    }
    let unused = bx.unused_volume_images(&configured_volume_names(bx)?);

    let named: Vec<(String, PathBuf)> = images
        .into_iter()
        .map(|p| {
            let name = p.file_name().unwrap_or(p.as_os_str()).to_string_lossy();
            (printable_path(Path::new(name.as_ref())), p)
        })
        .collect();
    let width = named.iter().map(|(name, _)| name.len()).max().unwrap_or(0);

    println!("{:<12} {}", bx.state(), bx.name());
    let mut total = 0;
    for (name, path) in &named {
        let meta =
            std::fs::metadata(path).with_context(|| format!("reading {}", printable_path(path)))?;
        let used = sys::disk_usage(&meta);
        total += used;
        let note = if unused.contains(path) {
            format!(
                "  (unused - `terra {} storage prune` removes it)",
                bx.name()
            )
        } else {
            String::new()
        };
        println!(
            "  {name:<width$}  {:>12}  {:>12} on disk{note}",
            mib(meta.len()),
            mib(used)
        );
    }
    println!(
        "  {:<width$}  {:>12}  {:>12} on disk",
        "total",
        "",
        mib(total)
    );
    Ok(())
}

/// Bytes as MiB with one decimal - integer arithmetic, so no size is rounded
/// by the float that printed it.
#[must_use]
fn mib(bytes: u64) -> String {
    const MIB: u64 = 1024 * 1024;
    format!("{}.{} MiB", bytes / MIB, (bytes % MIB) * 10 / MIB)
}

const MAGIC: &[u8; 16] = b"terra-storage-1\n";

fn export(bx: &BoxRef, to: &Path) -> Result<()> {
    let images = images_of(bx);
    anyhow::ensure!(
        !images.is_empty(),
        "{bx} has no images to export - `terra {} setup` builds them",
        bx.name()
    );
    let _lock = bx.lock_run()?;

    let out = File::create(to).with_context(|| format!("creating {}", printable_path(to)))?;
    match write_artifact(&images, out) {
        Ok(()) => {
            for img in &images {
                eprintln!("terra: exported {}", printable_path(img));
            }
            eprintln!("terra: wrote {}", printable_path(to));
            Ok(())
        }
        // A half-written artifact reads as one until the entry that is cut off.
        Err(e) => {
            let _ = std::fs::remove_file(to);
            Err(e)
        }
    }
}

fn write_artifact(images: &[PathBuf], to: File) -> Result<()> {
    // `fast`: the images are mostly the zeros a sparse file reads as, which
    // compress the same at any level, and a multi-GiB box should not spend
    // minutes on the rest.
    let mut gz = GzEncoder::new(BufWriter::new(to), Compression::fast());
    gz.write_all(MAGIC)?;
    for img in images {
        let printable = printable_path(img);
        let name = img
            .file_name()
            .and_then(|n| n.to_str())
            .with_context(|| format!("{printable} is not a name an artifact can carry"))?;
        let mut file = File::open(img).with_context(|| format!("opening {printable}"))?;
        let len = file
            .metadata()
            .with_context(|| format!("reading {printable}"))?
            .len();
        write_entry_header(&mut gz, name, len)?;
        let copied =
            std::io::copy(&mut file, &mut gz).with_context(|| format!("reading {printable}"))?;
        anyhow::ensure!(
            copied == len,
            "{printable} changed size while it was being exported"
        );
    }
    gz.finish()
        .context("compressing the artifact")?
        .flush()
        .context("writing the artifact")
}

fn write_entry_header(out: &mut impl Write, name: &str, len: u64) -> Result<()> {
    let name_len = u16::try_from(name.len())
        .with_context(|| format!("{name} is too long to name in an artifact"))?;
    out.write_all(&name_len.to_le_bytes())?;
    out.write_all(&len.to_le_bytes())?;
    out.write_all(name.as_bytes())?;
    Ok(())
}

/// The next entry's name and length, or `None` at the end of the artifact.
fn read_entry_header(src: &mut impl Read) -> Result<Option<(String, u64)>> {
    let mut head = [0u8; 10];
    match src.read_exact(&mut head) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e).context("reading the artifact"),
    }
    // Bounded by its own type: at most 64 KiB of name is allocated for it.
    let name_len = usize::from(u16::from_le_bytes([head[0], head[1]]));
    let len = u64::from_le_bytes([
        head[2], head[3], head[4], head[5], head[6], head[7], head[8], head[9],
    ]);
    let mut name = vec![0u8; name_len];
    src.read_exact(&mut name).context("reading the artifact")?;
    let name = String::from_utf8(name).context("the artifact names a file in no known encoding")?;
    Ok(Some((name, len)))
}

fn import(bx: &BoxRef, from: &Path) -> Result<()> {
    let file = File::open(from).with_context(|| format!("opening {}", printable_path(from)))?;
    let _lock = bx.lock_run()?;
    let mut gz = GzDecoder::new(BufReader::new(file));

    let mut magic = [0u8; MAGIC.len()];
    gz.read_exact(&mut magic)
        .ok()
        .filter(|()| &magic == MAGIC)
        .with_context(|| {
            format!(
                "{} is not a terra storage artifact (`terra <box> storage export` \
                 writes one)",
                printable_path(from)
            )
        })?;

    let mut restored: Vec<PathBuf> = Vec::new();
    while let Some((name, len)) = read_entry_header(&mut gz)? {
        let path = bx.image_named(&name).with_context(|| {
            format!(
                "{} carries '{}', which is not an image a box holds",
                printable_path(from),
                crate::render::printable(&name)
            )
        })?;
        anyhow::ensure!(
            !restored.contains(&path),
            "{} carries '{}' twice",
            printable_path(from),
            crate::render::printable(&name)
        );
        write_sparse(&path, &mut gz, len)?;
        eprintln!("terra: restored {}", printable_path(&path));
        restored.push(path);
    }
    anyhow::ensure!(
        !restored.is_empty(),
        "{} holds no images",
        printable_path(from)
    );

    // Deleting an image the artifact did not carry would throw away the data
    // this import is for.
    for kept in images_of(bx).iter().filter(|p| !restored.contains(p)) {
        eprintln!(
            "terra: warning: keeping {} - the artifact did not carry it \
             (`terra {} storage prune` removes it if the recipe no longer \
             names that volume)",
            printable_path(kept),
            bx.name()
        );
    }
    eprintln!("terra: imported into {bx} - `terra {}` boots it", bx.name());
    Ok(())
}

/// The images are sparse, and a plain copy would give a 512 MiB filesystem
/// holding 40 MiB the whole 512 on the disk it lands on.
fn write_sparse(path: &Path, src: &mut impl Read, len: u64) -> Result<()> {
    const CHUNK: usize = 64 * 1024;
    let printable = printable_path(path);
    let mut out = File::create(path).with_context(|| format!("creating {printable}"))?;
    let mut src = src.take(len);
    let mut buf = vec![0u8; CHUNK];
    loop {
        let read = src.read(&mut buf).context("reading the artifact")?;
        if read == 0 {
            break;
        }
        let chunk = &buf[..read];
        if chunk.iter().all(|b| *b == 0) {
            out.seek(SeekFrom::Current(i64::try_from(read)?))
                .with_context(|| format!("seeking in {printable}"))?;
        } else {
            out.write_all(chunk)
                .with_context(|| format!("writing {printable}"))?;
        }
    }
    // The offset is what was read *and* what was written, hole or not.
    let written = out
        .stream_position()
        .with_context(|| format!("writing {printable}"))?;
    anyhow::ensure!(
        written == len,
        "the artifact ends part-way through {printable}"
    );
    // A trailing hole is only a hole once the file is long enough to have one.
    out.set_len(len)
        .with_context(|| format!("sizing {printable}"))?;
    Ok(())
}

fn prune(bx: &BoxRef) -> Result<()> {
    let configured = configured_volume_names(bx)?;
    let _lock = bx.lock_run()?;
    let unused = bx.unused_volume_images(&configured);
    if unused.is_empty() {
        eprintln!("terra: {bx} holds no volume image its recipe dropped");
        return Ok(());
    }
    for img in unused {
        let printable = printable_path(&img);
        std::fs::remove_file(&img).with_context(|| format!("removing {printable}"))?;
        eprintln!("terra: removed {printable} - the recipe no longer names that volume");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::TestHome;

    /// A box with a pinned recipe, a root filesystem and the volumes named.
    fn built(project_dir: &Path, volumes: &[&str]) -> BoxRef {
        use std::fmt::Write as _;
        let bx = BoxRef::resolve(project_dir, "dev").unwrap();
        std::fs::create_dir_all(bx.dir()).unwrap();
        let mut recipe = String::from("hw:\n  cpus: 1\nvolumes:\n");
        for (i, name) in volumes.iter().enumerate() {
            let _ = writeln!(recipe, "  - {{name: {name}, guest: /v{i}, size_mib: 8}}");
            std::fs::write(bx.volume_img(name), format!("{name} data").as_bytes()).unwrap();
        }
        std::fs::write(bx.recipe(), recipe).unwrap();
        std::fs::write(bx.rootfs_img(), b"rootfs data").unwrap();
        bx
    }

    /// The whole point of the artifact: every image of one box arrives in
    /// another byte for byte, sizes included - a rootfs whose tail is a hole
    /// has to come back the same length, or the guest's filesystem is truncated.
    #[test]
    fn an_artifact_carries_every_image_of_a_box_into_another() {
        let dir = tempfile::tempdir().unwrap();
        let _home = TestHome::new();
        let from = built(dir.path(), &["data", "cache"]);
        // A sparse tail, which is what a real rootfs image is mostly made of.
        File::options()
            .write(true)
            .open(from.rootfs_img())
            .unwrap()
            .set_len(1 << 20)
            .unwrap();

        let artifact = dir.path().join("dev.terra");
        export(&from, &artifact).unwrap();

        let into = BoxRef::resolve(&dir.path().join("elsewhere"), "dev").unwrap();
        std::fs::create_dir_all(into.dir()).unwrap();
        std::fs::write(into.recipe(), "hw:\n  cpus: 1\n").unwrap();
        import(&into, &artifact).unwrap();

        for image in [
            from.rootfs_img(),
            from.volume_img("data"),
            from.volume_img("cache"),
        ] {
            let name = image.file_name().unwrap().to_str().unwrap();
            let there = into.dir().join(name);
            assert_eq!(
                std::fs::read(&there).unwrap(),
                std::fs::read(&image).unwrap(),
                "{name} did not survive the round trip"
            );
            assert_eq!(
                std::fs::metadata(&there).unwrap().len(),
                std::fs::metadata(&image).unwrap().len(),
                "{name} changed size"
            );
        }
    }

    /// The names in an artifact were written on another machine, so they are
    /// matched against what this box would call its own images rather than
    /// joined onto its directory - `../../` in one would otherwise write
    /// through the box and over a file of the user's.
    #[test]
    fn an_artifact_naming_a_path_outside_the_box_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let _home = TestHome::new();
        let bx = built(dir.path(), &[]);
        let outside = dir.path().join("private.txt");
        std::fs::write(&outside, b"mine").unwrap();

        for smuggled in [
            "../../private.txt",
            "/etc/passwd",
            "vol-../../private.txt.img",
            "recipe.yaml",
            "",
        ] {
            let artifact = dir.path().join("evil.terra");
            let mut gz = GzEncoder::new(
                BufWriter::new(File::create(&artifact).unwrap()),
                Compression::fast(),
            );
            gz.write_all(MAGIC).unwrap();
            write_entry_header(&mut gz, smuggled, 4).unwrap();
            gz.write_all(b"pwnd").unwrap();
            gz.finish().unwrap().flush().unwrap();

            let err = import(&bx, &artifact)
                .expect_err("a name that is not one of this box's images must be refused")
                .to_string();
            assert!(
                err.contains("not an image a box holds"),
                "{smuggled}: {err}"
            );
        }
        assert_eq!(std::fs::read(&outside).unwrap(), b"mine");
        assert!(
            std::fs::read_to_string(bx.recipe())
                .unwrap()
                .contains("cpus")
        );
    }

    /// An import writes over the box's filesystem, so a file that is not an
    /// artifact has to be refused by the header rather than part-way through.
    #[test]
    fn a_file_that_is_not_an_artifact_is_refused_before_anything_is_written() {
        let dir = tempfile::tempdir().unwrap();
        let _home = TestHome::new();
        let bx = built(dir.path(), &[]);
        let not_one = dir.path().join("holiday.jpg");
        std::fs::write(&not_one, b"\xff\xd8\xff\xe0 not a terra artifact at all").unwrap();

        let err = import(&bx, &not_one).unwrap_err().to_string();
        assert!(err.contains("not a terra storage artifact"), "{err}");
        assert_eq!(std::fs::read(bx.rootfs_img()).unwrap(), b"rootfs data");

        // …and one that is an artifact but carries nothing: an empty box is
        // never what an import was asked for.
        let empty = dir.path().join("empty.terra");
        let mut gz = GzEncoder::new(File::create(&empty).unwrap(), Compression::fast());
        gz.write_all(MAGIC).unwrap();
        gz.finish().unwrap();
        assert!(
            import(&bx, &empty)
                .unwrap_err()
                .to_string()
                .contains("no images")
        );
    }

    /// `prune` takes the volume images the recipe dropped, and only those: it
    /// is the one command whose whole job is deleting a box's data, so a
    /// volume that is still named must survive it.
    #[test]
    fn prune_removes_the_volumes_the_recipe_dropped_and_nothing_else() {
        let dir = tempfile::tempdir().unwrap();
        let _home = TestHome::new();
        let bx = built(dir.path(), &["data"]);
        std::fs::write(bx.volume_img("old"), b"dropped").unwrap();

        prune(&bx).unwrap();
        assert!(
            !bx.volume_img("old").exists(),
            "the dropped volume was kept"
        );
        assert!(bx.volume_img("data").exists(), "a named volume was removed");
        assert!(bx.rootfs_img().exists(), "the guest filesystem was removed");

        // Nothing left to take is not an error - a prune in a script runs again.
        prune(&bx).unwrap();
    }

    /// Neither an export nor an import may run against a live VM: one would
    /// copy a filesystem mid-write, and the other would replace the image a
    /// guest is running out of.
    #[test]
    fn a_running_box_is_neither_exported_nor_imported() {
        let dir = tempfile::tempdir().unwrap();
        let _home = TestHome::new();
        let bx = built(dir.path(), &[]);
        let artifact = dir.path().join("dev.terra");
        export(&bx, &artifact).unwrap();

        let running = bx.lock_run().unwrap();
        for refused in [export(&bx, &artifact), import(&bx, &artifact)] {
            assert!(
                refused.unwrap_err().to_string().contains("already in use"),
                "a box a VM is holding was operated on"
            );
        }
        drop(running);
        import(&bx, &artifact).unwrap();
    }
}
