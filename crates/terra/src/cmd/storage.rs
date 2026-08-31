//! `terra <box> storage` - the box's guest filesystem and volume images.

use crate::cli::{StorageCmd, StorageFileArgs};
use crate::render::escape_printable_path;
use crate::state::BoxRef;
use crate::vm::image;
use crate::{config, resolve};
use anyhow::{Context, Result};
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const BYTES_PER_MIB: u64 = 1024 * 1024;

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
fn list_images_of(bx: &BoxRef) -> Vec<PathBuf> {
    let mut volumes = bx.list_volume_images();
    volumes.sort();
    std::iter::once(bx.get_dir().join(crate::state::ROOTFS_FILE))
        .chain(volumes)
        .filter(|p| p.exists())
        .collect()
}

fn list_configured_volume_names(bx: &BoxRef) -> Result<Vec<String>> {
    let cfg = config::load_path(
        &bx.get_dir().join(crate::state::RECIPE_FILE),
        bx.get_project_dir(),
    )?;
    Ok(cfg.volumes.into_iter().map(|v| v.name).collect())
}

fn show(bx: &BoxRef) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let images = list_images_of(bx);
    if images.is_empty() {
        eprintln!(
            "terra: {bx} has no images yet - `terra {} setup` builds them",
            bx.get_name()
        );
        return Ok(());
    }
    let unused = bx.list_unused_volume_images(&list_configured_volume_names(bx)?);

    let named: Vec<(String, PathBuf)> = images
        .into_iter()
        .map(|p| {
            let name = p.file_name().unwrap_or(p.as_os_str()).to_string_lossy();
            (escape_printable_path(Path::new(name.as_ref())), p)
        })
        .collect();
    let width = named.iter().map(|(name, _)| name.len()).max().unwrap_or(0);

    println!("{:<12} {}", bx.get_state(), bx.get_name());
    let mut total = 0;
    for (name, path) in &named {
        let meta = std::fs::metadata(path)
            .with_context(|| format!("reading {}", escape_printable_path(path)))?;
        let used = meta.blocks() * 512;
        total += used;
        let note = if unused.contains(path) {
            format!(
                "  (unused - `terra {} storage prune` removes it)",
                bx.get_name()
            )
        } else {
            String::new()
        };
        println!(
            "  {name:<width$}  {:>12}  {:>12} on disk{note}",
            format_mib(meta.len()),
            format_mib(used)
        );
    }
    println!(
        "  {:<width$}  {:>12}  {:>12} on disk",
        "total",
        "",
        format_mib(total)
    );
    Ok(())
}

/// Bytes as MiB with one decimal - integer arithmetic, so no size is rounded
/// by the float that printed it.
#[must_use]
fn format_mib(bytes: u64) -> String {
    format!(
        "{}.{} MiB",
        bytes / BYTES_PER_MIB,
        (bytes % BYTES_PER_MIB) * 10 / BYTES_PER_MIB
    )
}

const STORAGE_ARTIFACT_MAGIC: &[u8; 16] = b"terra-storage-1\n";

fn export(bx: &BoxRef, to: &Path) -> Result<()> {
    let _lock = bx.lock_run()?;
    let rootfs = bx.get_dir().join(crate::state::ROOTFS_FILE);
    let configured = list_configured_volume_names(bx)?
        .into_iter()
        .map(|name| bx.get_volume_image(&name))
        .collect::<Vec<_>>();
    let images = list_images_of(bx)
        .into_iter()
        .filter(|path| path == &rootfs || configured.contains(path))
        .collect::<Vec<_>>();
    anyhow::ensure!(
        !images.is_empty(),
        "{bx} has no images to export - `terra {} setup` builds them",
        bx.get_name()
    );

    image::staged_write(to, |out| write_artifact(&images, out))
        .with_context(|| format!("writing {}", escape_printable_path(to)))?;
    for img in &images {
        eprintln!("terra: exported {}", escape_printable_path(img));
    }
    eprintln!("terra: wrote {}", escape_printable_path(to));
    Ok(())
}

fn write_artifact(images: &[PathBuf], to: &mut File) -> Result<()> {
    // `fast`: the images are mostly the zeros a sparse file reads as, which
    // compress the same at any level, and a multi-GiB box should not spend
    // minutes on the rest.
    let mut gz = GzEncoder::new(BufWriter::new(to), Compression::fast());
    gz.write_all(STORAGE_ARTIFACT_MAGIC)?;
    for img in images {
        let printable = escape_printable_path(img);
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
    let mut first = [0u8; 1];
    match src.read_exact(&mut first) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e).context("reading the artifact"),
    }
    let mut rest = [0u8; 9];
    src.read_exact(&mut rest).context("reading the artifact")?;
    let mut head = [0u8; 10];
    head[..1].copy_from_slice(&first);
    head[1..].copy_from_slice(&rest);
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
    let file = crate::sys::open_no_symlinks(from)
        .with_context(|| format!("opening {}", escape_printable_path(from)))?;
    let _lock = bx.lock_run()?;
    let cfg = config::load_path(
        &bx.get_dir().join(crate::state::RECIPE_FILE),
        bx.get_project_dir(),
    )?;
    let rootfs_limit = u64::from(cfg.hw.rootfs_mib) * BYTES_PER_MIB;
    let volume_limit = |name: &str| {
        let volume_name = name.strip_prefix("vol-")?.strip_suffix(".img")?;
        cfg.volumes
            .iter()
            .find(|volume| volume.name == volume_name)
            .map(|volume| u64::from(volume.size_mib) * BYTES_PER_MIB)
    };
    let total_limit = rootfs_limit
        + cfg
            .volumes
            .iter()
            .map(|volume| u64::from(volume.size_mib) * BYTES_PER_MIB)
            .sum::<u64>();
    let mut gz = GzDecoder::new(BufReader::new(file));

    let mut magic = [0u8; STORAGE_ARTIFACT_MAGIC.len()];
    if gz.read_exact(&mut magic).is_err() || magic != *STORAGE_ARTIFACT_MAGIC {
        anyhow::bail!(
            "{} is not a terra storage artifact (`terra <box> storage export` \
             writes one)",
            escape_printable_path(from)
        );
    }

    let mut restored: Vec<PathBuf> = Vec::new();
    let mut total = 0u64;
    while let Some((name, len)) = read_entry_header(&mut gz)? {
        let path = bx.find_image_named(&name).with_context(|| {
            format!(
                "{} carries '{}', which is not an image a box holds",
                escape_printable_path(from),
                crate::render::escape_printable(&name)
            )
        })?;
        anyhow::ensure!(
            !restored.contains(&path),
            "{} carries '{}' twice",
            escape_printable_path(from),
            crate::render::escape_printable(&name)
        );
        let limit = if name == crate::state::ROOTFS_FILE {
            Some(rootfs_limit)
        } else {
            volume_limit(&name)
        }
        .with_context(|| format!("{name} is not a configured image"))?;
        anyhow::ensure!(
            len <= limit,
            "{} carries '{}' at {len} bytes, past its configured {limit}-byte limit",
            escape_printable_path(from),
            crate::render::escape_printable(&name)
        );
        total = total
            .checked_add(len)
            .context("the artifact's image lengths overflow")?;
        anyhow::ensure!(
            total <= total_limit,
            "{} carries {total} bytes of images, past the {total_limit}-byte import limit",
            escape_printable_path(from)
        );
        write_sparse(&path, &mut gz, len)?;
        eprintln!("terra: restored {}", escape_printable_path(&path));
        restored.push(path);
    }
    anyhow::ensure!(
        !restored.is_empty(),
        "{} holds no images",
        escape_printable_path(from)
    );

    // Deleting an image the artifact did not carry would throw away the data
    // this import is for.
    for kept in list_images_of(bx).iter().filter(|p| !restored.contains(p)) {
        eprintln!(
            "terra: warning: keeping {} - the artifact did not carry it \
             (`terra {} storage prune` removes it if the recipe no longer \
             names that volume)",
            escape_printable_path(kept),
            bx.get_name()
        );
    }
    eprintln!(
        "terra: imported into {bx} - `terra {}` boots it",
        bx.get_name()
    );
    Ok(())
}

/// The images are sparse, and a plain copy would give a 512 MiB filesystem
/// holding 40 MiB the whole 512 on the disk it lands on. Staged: an import cut
/// off part-way leaves whatever image it was restoring byte-identical.
fn write_sparse(path: &Path, src: &mut impl Read, len: u64) -> Result<()> {
    const CHUNK: usize = 64 * 1024;
    let printable = escape_printable_path(path);
    image::staged_write(path, |out| {
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
    })
}

fn prune(bx: &BoxRef) -> Result<()> {
    let configured = list_configured_volume_names(bx)?;
    let _lock = bx.lock_run()?;
    let unused = bx.list_unused_volume_images(&configured);
    if unused.is_empty() {
        eprintln!("terra: {bx} holds no volume image its recipe dropped");
        return Ok(());
    }
    for img in unused {
        let printable = escape_printable_path(&img);
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
    fn build_box_ref(project_dir: &Path, volumes: &[&str]) -> BoxRef {
        use std::fmt::Write as _;
        let bx = BoxRef::resolve(project_dir, "dev").unwrap();
        std::fs::create_dir_all(bx.get_dir()).unwrap();
        let mut recipe = String::from("hw:\n  cpus: 1\nvolumes:\n");
        for (i, name) in volumes.iter().enumerate() {
            let _ = writeln!(recipe, "  - {{name: {name}, guest: /v{i}, size_mib: 8}}");
            std::fs::write(bx.get_volume_image(name), format!("{name} data").as_bytes()).unwrap();
        }
        std::fs::write(bx.get_dir().join(crate::state::RECIPE_FILE), recipe).unwrap();
        std::fs::write(bx.get_dir().join(crate::state::ROOTFS_FILE), b"rootfs data").unwrap();
        bx
    }

    /// The whole point of the artifact: every image of one box arrives in
    /// another byte for byte, sizes included - a rootfs whose tail is a hole
    /// has to come back the same length, or the guest's filesystem is truncated.
    #[test]
    fn an_artifact_carries_every_image_of_a_box_into_another() {
        let dir = tempfile::tempdir().unwrap();
        let _home = TestHome::new();
        let from = build_box_ref(dir.path(), &["data", "cache"]);
        // A sparse tail, which is what a real rootfs image is mostly made of.
        File::options()
            .write(true)
            .open(from.get_dir().join(crate::state::ROOTFS_FILE))
            .unwrap()
            .set_len(1 << 20)
            .unwrap();

        let artifact = dir.path().join("dev.terra");
        export(&from, &artifact).unwrap();

        let into = build_box_ref(&dir.path().join("elsewhere"), &["data", "cache"]);
        import(&into, &artifact).unwrap();

        for image in [
            from.get_dir().join(crate::state::ROOTFS_FILE),
            from.get_volume_image("data"),
            from.get_volume_image("cache"),
        ] {
            let name = image.file_name().unwrap().to_str().unwrap();
            let there = into.get_dir().join(name);
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

    #[test]
    fn export_omits_volume_images_the_recipe_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let _home = TestHome::new();
        let from = build_box_ref(dir.path(), &["data"]);
        std::fs::write(from.get_volume_image("old"), b"dropped").unwrap();

        let artifact = dir.path().join("dev.terra");
        export(&from, &artifact).unwrap();

        let into = build_box_ref(&dir.path().join("elsewhere"), &["data"]);
        import(&into, &artifact).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn export_refuses_a_symlink_destination() {
        let dir = tempfile::tempdir().unwrap();
        let _home = TestHome::new();
        let bx = build_box_ref(dir.path(), &[]);
        let sentinel = dir.path().join("sentinel");
        let destination = dir.path().join("export");
        std::fs::write(&sentinel, b"keep me").unwrap();
        std::os::unix::fs::symlink(&sentinel, &destination).unwrap();

        assert!(export(&bx, &destination).is_err());
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"keep me");
    }

    #[cfg(unix)]
    #[test]
    fn export_refuses_a_symlinked_destination_parent() {
        let dir = tempfile::tempdir().unwrap();
        let _home = TestHome::new();
        let bx = build_box_ref(dir.path(), &[]);
        let real_parent = dir.path().join("real");
        let linked_parent = dir.path().join("linked");
        std::fs::create_dir(&real_parent).unwrap();
        std::os::unix::fs::symlink(&real_parent, &linked_parent).unwrap();

        assert!(export(&bx, &linked_parent.join("export.terra")).is_err());
        assert!(!real_parent.join("export.terra").exists());
    }

    /// The names in an artifact were written on another machine, so they are
    /// matched against what this box would call its own images rather than
    /// joined onto its directory - `../../` in one would otherwise write
    /// through the box and over a file of the user's.
    #[test]
    fn an_artifact_naming_a_path_outside_the_box_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let _home = TestHome::new();
        let bx = build_box_ref(dir.path(), &[]);
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
            gz.write_all(STORAGE_ARTIFACT_MAGIC).unwrap();
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
            std::fs::read_to_string(bx.get_dir().join(crate::state::RECIPE_FILE))
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
        let bx = build_box_ref(dir.path(), &[]);
        let not_one = dir.path().join("holiday.jpg");
        std::fs::write(&not_one, b"\xff\xd8\xff\xe0 not a terra artifact at all").unwrap();

        let err = import(&bx, &not_one).unwrap_err().to_string();
        assert!(err.contains("not a terra storage artifact"), "{err}");
        assert_eq!(
            std::fs::read(bx.get_dir().join(crate::state::ROOTFS_FILE)).unwrap(),
            b"rootfs data"
        );

        // …and one that is an artifact but carries nothing: an empty box is
        // never what an import was asked for.
        let empty = dir.path().join("empty.terra");
        let mut gz = GzEncoder::new(File::create(&empty).unwrap(), Compression::fast());
        gz.write_all(STORAGE_ARTIFACT_MAGIC).unwrap();
        gz.finish().unwrap();
        assert!(
            import(&bx, &empty)
                .unwrap_err()
                .to_string()
                .contains("no images")
        );
    }

    #[test]
    fn an_artifact_larger_than_the_configured_image_is_refused_before_staging() {
        let dir = tempfile::tempdir().unwrap();
        let _home = TestHome::new();
        let bx = build_box_ref(dir.path(), &[]);
        let artifact = dir.path().join("too-large.terra");
        let mut gz = GzEncoder::new(File::create(&artifact).unwrap(), Compression::fast());
        gz.write_all(STORAGE_ARTIFACT_MAGIC).unwrap();
        write_entry_header(&mut gz, "rootfs.img", 512 * 1024 * 1024 + 1).unwrap();
        gz.finish().unwrap();

        let err = import(&bx, &artifact).unwrap_err().to_string();
        assert!(err.contains("configured"), "{err}");
        assert_eq!(
            std::fs::read(bx.get_dir().join(crate::state::ROOTFS_FILE)).unwrap(),
            b"rootfs data"
        );
    }

    #[test]
    fn a_partial_entry_header_is_refused_as_incomplete() {
        for len in 1..10 {
            let bytes = vec![0; len];
            assert!(
                read_entry_header(&mut std::io::Cursor::new(bytes)).is_err(),
                "{len}"
            );
        }
    }

    /// Images are replaced only through a staged write's rename, so one
    /// artifact cut off part-way leaves every image it reached byte-identical -
    /// the import is all of them or none of them.
    #[test]
    fn an_import_cut_off_part_way_leaves_the_images_it_reached_intact() {
        let dir = tempfile::tempdir().unwrap();
        let _home = TestHome::new();
        let bx = build_box_ref(dir.path(), &[]);

        let artifact = dir.path().join("cut-off.terra");
        let mut gz = GzEncoder::new(
            BufWriter::new(File::create(&artifact).unwrap()),
            Compression::fast(),
        );
        gz.write_all(STORAGE_ARTIFACT_MAGIC).unwrap();
        write_entry_header(&mut gz, "rootfs.img", 1 << 20).unwrap();
        gz.write_all(b"a few bytes").unwrap(); // far short of the declared length
        gz.finish().unwrap().flush().unwrap();

        let err = format!("{:#}", import(&bx, &artifact).unwrap_err());
        assert!(err.contains("part-way through"), "{err}");
        assert_eq!(
            std::fs::read(bx.get_dir().join(crate::state::ROOTFS_FILE)).unwrap(),
            b"rootfs data",
            "a truncated artifact replaced the live image"
        );
        let left: Vec<String> = std::fs::read_dir(bx.get_dir())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            !left.iter().any(|n| std::path::Path::new(n)
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("tmp"))),
            "a staging temporary was left: {left:?}"
        );
    }

    /// `prune` takes the volume images the recipe dropped, and only those: it
    /// is the one command whose whole job is deleting a box's data, so a
    /// volume that is still named must survive it.
    #[test]
    fn prune_removes_the_volumes_the_recipe_dropped_and_nothing_else() {
        let dir = tempfile::tempdir().unwrap();
        let _home = TestHome::new();
        let bx = build_box_ref(dir.path(), &["data"]);
        std::fs::write(bx.get_volume_image("old"), b"dropped").unwrap();

        prune(&bx).unwrap();
        assert!(
            !bx.get_volume_image("old").exists(),
            "the dropped volume was kept"
        );
        assert!(
            bx.get_volume_image("data").exists(),
            "a named volume was removed"
        );
        assert!(
            bx.get_dir().join(crate::state::ROOTFS_FILE).exists(),
            "the guest filesystem was removed"
        );

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
        let bx = build_box_ref(dir.path(), &[]);
        let artifact = dir.path().join("dev.terra");
        export(&bx, &artifact).unwrap();

        let running = bx.lock_run().unwrap();
        for refused in [export(&bx, &artifact), import(&bx, &artifact)] {
            assert!(
                refused
                    .unwrap_err()
                    .to_string()
                    .contains("locked by another terra command"),
                "a box a VM is holding was operated on"
            );
        }
        drop(running);
        import(&bx, &artifact).unwrap();
    }
}
