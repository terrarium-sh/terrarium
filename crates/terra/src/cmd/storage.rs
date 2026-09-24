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
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::vm::image::BYTES_PER_MIB;
const IMPORT_JOURNAL: &str = ".import-journal";

#[derive(Deserialize, Serialize)]
struct ImportJournal {
    staging: String,
    entries: Vec<ImportEntry>,
    committed: bool,
}

#[derive(Deserialize, Serialize)]
struct ImportEntry {
    image: String,
    existed: bool,
}

pub fn run(
    args: &crate::cli::StorageArgs,
    name: Option<&str>,
    project_dir: &Path,
) -> Result<ExitCode> {
    let bx = resolve::resolve_pinned_box(project_dir, name)?;
    match &args.cmd {
        StorageCmd::Show(show_args) => show(&bx, show_args.json),
        StorageCmd::Export(StorageFileArgs { file }) => export(&bx, file),
        StorageCmd::Import(StorageFileArgs { file }) => import(&bx, file),
        StorageCmd::Prune => prune(&bx),
    }?;
    Ok(ExitCode::SUCCESS)
}

fn list_images_of(bx: &BoxRef) -> Result<Vec<PathBuf>> {
    let mut volumes = bx.list_volume_images()?;
    volumes.sort();
    Ok(
        std::iter::once(bx.get_dir().join(crate::state::ROOTFS_FILE))
            .chain(volumes)
            .filter(|p| p.exists())
            .collect(),
    )
}

fn list_configured_volume_names(bx: &BoxRef) -> Result<Vec<String>> {
    let cfg = config::load_path(
        &bx.get_dir().join(crate::state::RECIPE_FILE),
        bx.get_project_dir(),
    )
    .context("reading the pinned recipe")?;
    Ok(cfg.volumes.into_iter().map(|v| v.name).collect())
}

#[derive(Serialize)]
struct StorageShowOutput<'a> {
    images: Vec<StorageImageEntry<'a>>,
    total_disk_bytes: u64,
}

#[derive(Serialize)]
struct StorageImageEntry<'a> {
    name: String,
    path: &'a Path,
    virtual_bytes: u64,
    disk_bytes: u64,
    is_unused: bool,
}

fn show(bx: &BoxRef, json: bool) -> Result<()> {
    let images = list_images_of(bx)?;
    if json {
        let unused = if images.is_empty() {
            Vec::new()
        } else {
            bx.list_unused_volume_images(&list_configured_volume_names(bx)?)?
        };
        let mut entries = Vec::with_capacity(images.len());
        let mut total_disk_bytes = 0;
        for path in &images {
            let meta = std::fs::metadata(path)
                .with_context(|| format!("reading {}", escape_printable_path(path)))?;
            let disk_bytes = crate::sys::allocated_size(path, &meta);
            total_disk_bytes += disk_bytes;
            let name = path
                .file_name()
                .unwrap_or_else(|| path.as_os_str())
                .to_string_lossy();
            entries.push(StorageImageEntry {
                name: name.into_owned(),
                path,
                virtual_bytes: meta.len(),
                disk_bytes,
                is_unused: unused.contains(path),
            });
        }
        let output = StorageShowOutput {
            images: entries,
            total_disk_bytes,
        };
        let rendered =
            serde_json::to_string_pretty(&output).context("serializing storage images to json")?;
        let mut out = std::io::stdout().lock();
        crate::render::finish_stdout_write(writeln!(out, "{rendered}"))?;
        return Ok(());
    }
    if images.is_empty() {
        eprintln!(
            "terra: {bx} has no images yet - `terra {} setup` builds them",
            bx.get_name()
        );
        return Ok(());
    }
    let unused = bx.list_unused_volume_images(&list_configured_volume_names(bx)?)?;

    let named: Vec<(String, PathBuf)> = images
        .into_iter()
        .map(|p| {
            let name = p.file_name().unwrap_or(p.as_os_str()).to_string_lossy();
            (escape_printable_path(Path::new(name.as_ref())), p)
        })
        .collect();
    let width = named.iter().map(|(name, _)| name.len()).max().unwrap_or(0);

    let mut out = std::io::stdout().lock();
    crate::render::finish_stdout_write(writeln!(out, "{:<12} {}", bx.get_state()?, bx.get_name()))?;
    let mut total = 0;
    for (name, path) in &named {
        let meta = std::fs::metadata(path)
            .with_context(|| format!("reading {}", escape_printable_path(path)))?;
        let used = crate::sys::allocated_size(path, &meta);
        total += used;
        let note = if unused.contains(path) {
            format!(
                "  (unused - `terra {} storage prune` removes it)",
                bx.get_name()
            )
        } else {
            String::new()
        };
        crate::render::finish_stdout_write(writeln!(
            out,
            "  {name:<width$}  {:>12}  {:>12} on disk{note}",
            format_mib(meta.len()),
            format_mib(used)
        ))?;
    }
    crate::render::finish_stdout_write(writeln!(
        out,
        "  {:<width$}  {:>12}  {:>12} on disk",
        "total",
        "",
        format_mib(total)
    ))?;
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
    let destination = std::path::absolute(to).context("resolving export destination")?;
    let rename_destination = destination
        .parent()
        .zip(destination.file_name())
        .map(|(parent, name)| crate::sys::canonicalize_existing_prefix(parent).join(name));
    let destination = crate::sys::canonicalize_existing_prefix(&destination);
    let box_dir = crate::sys::canonicalize_existing_prefix(bx.get_dir());
    anyhow::ensure!(
        !destination.starts_with(&box_dir)
            && rename_destination.is_none_or(|path| !path.starts_with(&box_dir)),
        "export destination {} is inside box state; choose a destination outside {}",
        escape_printable_path(to),
        escape_printable_path(&box_dir)
    );
    let _lock = bx.lock_run()?;
    recover_import(bx)?;
    let rootfs = bx.get_dir().join(crate::state::ROOTFS_FILE);
    let configured = list_configured_volume_names(bx)?
        .into_iter()
        .map(|name| bx.get_volume_image(&name))
        .collect::<Vec<_>>();
    let images = list_images_of(bx)?
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
    let mut head = [0u8; 10];
    match src.read_exact(&mut head[..1]) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e).context("reading the artifact"),
    }
    src.read_exact(&mut head[1..])
        .context("reading the artifact")?;
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
    let file = crate::sys::open_regular_file(from)
        .with_context(|| format!("opening {}", escape_printable_path(from)))?;
    let _lock = bx.lock_run()?;
    recover_import(bx)?;
    let cfg = config::load_path(
        &bx.get_dir().join(crate::state::RECIPE_FILE),
        bx.get_project_dir(),
    )
    .context("reading the pinned recipe")?;
    let (staging_dir, staging_name) =
        crate::sys::reserve_staging_directory(bx.get_dir(), "import")?;
    write_import_journal(
        &bx.get_dir().join(IMPORT_JOURNAL),
        &ImportJournal {
            staging: staging_name,
            entries: Vec::new(),
            committed: false,
        },
    )?;
    let plan = match stage_import(bx, from, &cfg, file, &staging_dir) {
        Ok(plan) => plan,
        Err(error) => {
            recover_import(bx).context("cleaning failed import")?;
            return Err(error);
        }
    };
    let staged = plan
        .iter()
        .map(|(path, _)| {
            (
                path.clone(),
                staging_dir.join(path.file_name().unwrap_or_default()),
            )
        })
        .collect::<Vec<_>>();
    let committed = commit_import(bx, &staged);
    for (_, stage) in &staged {
        let _ = std::fs::remove_file(stage);
    }
    let _ = std::fs::remove_dir(&staging_dir);
    committed?;

    for (path, _) in &staged {
        eprintln!("terra: restored {}", escape_printable_path(path));
    }
    for kept in list_images_of(bx)?
        .iter()
        .filter(|p| !plan.iter().any(|(restored, _)| restored == *p))
    {
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

fn stage_import(
    bx: &BoxRef,
    from: &Path,
    cfg: &config::Config,
    file: File,
    staging_dir: &Path,
) -> Result<Vec<(PathBuf, u64)>> {
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

    let mut restored: Vec<(PathBuf, u64)> = Vec::new();
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
            !restored.iter().any(|(restored, _)| restored == &path),
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
        write_sparse(&staging_dir.join(&name), &mut gz, len)?;
        restored.push((path, len));
    }
    anyhow::ensure!(
        !restored.is_empty(),
        "{} holds no images",
        escape_printable_path(from)
    );

    Ok(restored)
}

fn commit_import(bx: &BoxRef, staged: &[(PathBuf, PathBuf)]) -> Result<()> {
    let staging = staged
        .first()
        .and_then(|(_, stage)| stage.parent())
        .context("import has no staged images")?;
    let staging_name = staging
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| name.starts_with(".import."))
        .context("import staging directory has an invalid name")?
        .to_owned();
    let journal = bx.get_dir().join(IMPORT_JOURNAL);
    let entries = staged
        .iter()
        .map(|(path, _)| {
            let exists = match std::fs::symlink_metadata(path) {
                Ok(metadata) => !metadata.is_dir(),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
                Err(error) => {
                    return Err(error).with_context(|| format!("reading {}", path.display()));
                }
            };
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .context("image has no name")?;
            Ok(ImportEntry {
                image: name.to_owned(),
                existed: exists,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let mut record = ImportJournal {
        staging: staging_name,
        entries,
        committed: false,
    };
    write_import_journal(&journal, &record)?;
    let mut committed: Vec<(&Path, Option<PathBuf>)> = Vec::new();
    let result = (|| {
        for (index, (path, stage)) in staged.iter().enumerate() {
            let backup = stage.with_file_name(format!("original-{index}"));
            let original = match std::fs::symlink_metadata(path) {
                Ok(metadata) => {
                    anyhow::ensure!(
                        !metadata.is_dir(),
                        "image {} is a directory",
                        path.display()
                    );
                    std::fs::rename(path, &backup)
                        .with_context(|| format!("backing up {}", path.display()))?;
                    Some(backup)
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => {
                    return Err(error).with_context(|| format!("reading {}", path.display()));
                }
            };
            committed.push((path, original));
            std::fs::rename(stage, path)
                .with_context(|| format!("restoring {}", path.display()))?;
        }
        Ok(())
    })();
    if let Err(error) = result {
        for (path, backup) in committed.into_iter().rev() {
            if let Err(failure) = std::fs::remove_file(path)
                && failure.kind() != std::io::ErrorKind::NotFound
            {
                return Err(error).context(format!("rollback could not remove {}: {failure}; original images remain in the import staging directory", path.display()));
            }
            if let Some(backup) = backup {
                std::fs::rename(&backup, path).with_context(|| {
                    format!(
                        "{error:#}; rollback failed: restore {} from {}",
                        path.display(),
                        backup.display()
                    )
                })?;
            }
        }
        let _ = std::fs::remove_file(&journal);
        return Err(error);
    }
    record.committed = true;
    write_import_journal(&journal, &record)?;
    recover_import(bx)
}

fn write_import_journal(path: &Path, record: &ImportJournal) -> Result<()> {
    image::staged_write(path, |file| Ok(serde_json::to_writer(file, record)?))
        .with_context(|| format!("recording {}", path.display()))
}

pub(crate) fn recover_import(bx: &BoxRef) -> Result<()> {
    let journal = bx.get_dir().join(IMPORT_JOURNAL);
    let record: ImportJournal = match File::open(&journal) {
        Ok(file) => serde_json::from_reader(file).context("reading import recovery journal")?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).with_context(|| format!("reading {}", journal.display())),
    };
    anyhow::ensure!(
        record.staging.starts_with(".import.") && !record.staging.contains(['/', '\\']),
        "import recovery journal has an invalid staging directory"
    );
    let staging = bx.get_dir().join(&record.staging);
    if record.committed {
        if record
            .entries
            .iter()
            .any(|entry| entry.image == crate::state::ROOTFS_FILE)
        {
            let stamp = bx.get_dir().join(crate::state::BAKE_STAMP);
            match std::fs::remove_file(&stamp) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error).with_context(|| format!("removing {}", stamp.display()));
                }
            }
            #[cfg(unix)]
            File::open(bx.get_dir())?.sync_all()?;
        }
        if let Err(error) = std::fs::remove_dir_all(&staging)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            return Err(error).with_context(|| format!("removing {}", staging.display()));
        }
        return std::fs::remove_file(journal).context("removing import recovery journal");
    }
    for (index, entry) in record.entries.iter().enumerate() {
        let path = bx
            .find_image_named(&entry.image)
            .context("import recovery journal names an invalid image")?;
        let backup = staging.join(format!("original-{index}"));
        let backup_exists = match std::fs::symlink_metadata(&backup) {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => {
                return Err(error).with_context(|| format!("reading {}", backup.display()));
            }
        };
        if entry.existed && backup_exists {
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error).with_context(|| format!("removing {}", path.display()));
                }
            }
            std::fs::rename(&backup, &path)?;
        } else if !entry.existed && !staging.join(&entry.image).exists() {
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error).with_context(|| format!("removing {}", path.display()));
                }
            }
        }
    }
    if let Err(error) = std::fs::remove_dir_all(&staging)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        return Err(error).with_context(|| format!("removing {}", staging.display()));
    }
    std::fs::remove_file(journal).context("removing import recovery journal")
}

/// The images are sparse, and a plain copy would give a 512 MiB filesystem
/// holding 40 MiB the whole 512 on the disk it lands on. Staged: an import cut
/// off part-way leaves whatever image it was restoring byte-identical.
fn write_sparse(path: &Path, src: &mut impl Read, len: u64) -> Result<()> {
    const CHUNK: usize = 64 * 1024;
    let printable = escape_printable_path(path);
    image::staged_write(path, |out| {
        crate::sys::make_sparse(out).with_context(|| format!("making {printable} sparse"))?;
        let mut src = src.take(len);
        let mut buf = vec![0u8; CHUNK];
        loop {
            let read = match src.read(&mut buf) {
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                result => result.context("reading the artifact")?,
            };
            if read == 0 {
                break;
            }
            image::write_sparse_chunk(out, &buf[..read])
                .with_context(|| format!("writing {printable}"))?;
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
    let _lock = bx.lock_run()?;
    recover_import(bx)?;
    let configured = list_configured_volume_names(bx)?;
    let unused = bx.list_unused_volume_images(&configured)?;
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

    #[test]
    fn a_late_import_commit_failure_restores_all_original_images() {
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path().join("rootfs.img");
        let volume = dir.path().join("vol-data.img");
        let staging = dir.path().join(".import.test");
        std::fs::create_dir(&staging).unwrap();
        std::fs::write(&rootfs, b"old rootfs").unwrap();
        std::fs::write(&volume, b"old volume").unwrap();
        let new_rootfs = staging.join("rootfs.img");
        std::fs::write(&new_rootfs, b"new rootfs").unwrap();
        let staged = vec![
            (rootfs.clone(), new_rootfs),
            (volume.clone(), staging.join("missing-volume")),
        ];
        let bx = BoxRef::from_state_dir(dir.path().to_owned(), dir.path());
        assert!(commit_import(&bx, &staged).is_err());
        assert_eq!(std::fs::read(&rootfs).unwrap(), b"old rootfs");
        assert_eq!(std::fs::read(&volume).unwrap(), b"old volume");
        assert_eq!(std::fs::read_dir(staging).unwrap().count(), 0);
    }

    #[test]
    fn only_rootfs_imports_clear_the_bake_stamp() {
        for name in [crate::state::ROOTFS_FILE, "vol-data.img"] {
            let dir = tempfile::tempdir().unwrap();
            let bx = BoxRef::from_state_dir(dir.path().to_owned(), dir.path());
            let stamp = bx.get_dir().join(crate::state::BAKE_STAMP);
            std::fs::write(&stamp, b"baked").unwrap();
            let staging = dir.path().join(".import.test");
            std::fs::create_dir(&staging).unwrap();
            let stage = staging.join(name);
            std::fs::write(&stage, b"new").unwrap();
            commit_import(&bx, &[(dir.path().join(name), stage)]).unwrap();
            assert_eq!(stamp.exists(), name != crate::state::ROOTFS_FILE);
        }
    }

    #[test]
    fn failed_stamp_removal_keeps_the_committed_journal_for_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let bx = BoxRef::from_state_dir(dir.path().to_owned(), dir.path());
        let stamp = bx.get_dir().join(crate::state::BAKE_STAMP);
        std::fs::create_dir(&stamp).unwrap();
        let staging = dir.path().join(".import.test");
        std::fs::create_dir(&staging).unwrap();
        let stage = staging.join(crate::state::ROOTFS_FILE);
        std::fs::write(&stage, b"new").unwrap();
        let rootfs = dir.path().join(crate::state::ROOTFS_FILE);
        std::fs::write(&rootfs, b"old").unwrap();
        assert!(commit_import(&bx, &[(rootfs.clone(), stage)]).is_err());
        assert!(dir.path().join(IMPORT_JOURNAL).exists());
        assert!(recover_import(&bx).is_err());
        std::fs::remove_dir(&stamp).unwrap();
        recover_import(&bx).unwrap();
        assert_eq!(std::fs::read(rootfs).unwrap(), b"new");
        assert!(!dir.path().join(IMPORT_JOURNAL).exists());
    }

    #[test]
    fn import_commit_creates_missing_images() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("new.img");
        let stage_dir = dir.path().join(".import.test");
        std::fs::create_dir(&stage_dir).unwrap();
        let stage = stage_dir.join("stage.img");
        std::fs::write(&stage, b"new image").unwrap();
        let bx = BoxRef::from_state_dir(dir.path().to_owned(), dir.path());
        commit_import(&bx, &[(path.clone(), stage)]).unwrap();
        assert_eq!(std::fs::read(path).unwrap(), b"new image");
    }

    #[test]
    fn recovery_restores_each_interrupted_import_stage() {
        let dir = tempfile::tempdir().unwrap();
        let bx = BoxRef::from_state_dir(dir.path().to_owned(), dir.path());
        let root = bx.get_dir().join(crate::state::ROOTFS_FILE);
        for stage in 0..3 {
            let staging = bx.get_dir().join(format!(".import.{stage}"));
            std::fs::create_dir(&staging).unwrap();
            std::fs::write(&root, b"old").unwrap();
            if stage == 1 || stage == 2 {
                std::fs::rename(&root, staging.join("original-0")).unwrap();
                if stage == 2 {
                    std::fs::write(&root, b"new").unwrap();
                }
            } else {
                std::fs::write(staging.join("rootfs.img"), b"new").unwrap();
            }
            write_import_journal(
                &bx.get_dir().join(IMPORT_JOURNAL),
                &ImportJournal {
                    staging: format!(".import.{stage}"),
                    entries: vec![ImportEntry {
                        image: "rootfs.img".into(),
                        existed: true,
                    }],
                    committed: false,
                },
            )
            .unwrap();
            recover_import(&bx).unwrap();
            assert_eq!(std::fs::read(&root).unwrap(), b"old", "stage {stage}");
            assert!(!staging.exists());
        }
    }

    #[test]
    fn interrupted_staging_is_cleaned_before_the_next_storage_operation() {
        let dir = tempfile::tempdir().unwrap();
        let bx = BoxRef::from_state_dir(dir.path().to_owned(), dir.path());
        let staging = dir.path().join(".import.test");
        std::fs::create_dir(&staging).unwrap();
        std::fs::write(staging.join("rootfs.img"), b"partial").unwrap();
        std::fs::write(dir.path().join("rootfs.img"), b"original").unwrap();
        write_import_journal(
            &dir.path().join(IMPORT_JOURNAL),
            &ImportJournal {
                staging: ".import.test".into(),
                entries: Vec::new(),
                committed: false,
            },
        )
        .unwrap();
        let _lock = bx.lock_run().unwrap();
        recover_import(&bx).unwrap();
        assert!(!staging.exists());
        assert_eq!(
            std::fs::read(dir.path().join("rootfs.img")).unwrap(),
            b"original"
        );
    }

    #[test]
    fn storage_recovery_restores_a_partial_multi_image_commit() {
        for mutations in 0..=5 {
            for committed in [false, true] {
                if committed && mutations != 5 {
                    continue;
                }
                let dir = tempfile::tempdir().unwrap();
                let bx = BoxRef::from_state_dir(dir.path().to_owned(), dir.path());
                let staging = dir.path().join(".import.test");
                std::fs::create_dir(&staging).unwrap();
                let names = ["rootfs.img", "vol-data.img", "vol-new.img"];
                let stamp = bx.get_dir().join(crate::state::BAKE_STAMP);
                std::fs::write(&stamp, b"baked").unwrap();
                for (index, name) in names.iter().enumerate() {
                    if index < 2 {
                        std::fs::write(dir.path().join(name), b"old").unwrap();
                    }
                    std::fs::write(staging.join(name), b"new").unwrap();
                }
                let mut operations = 0;
                for (index, name) in names.iter().enumerate() {
                    if index < 2 {
                        if operations == mutations {
                            break;
                        }
                        std::fs::rename(
                            dir.path().join(name),
                            staging.join(format!("original-{index}")),
                        )
                        .unwrap();
                        operations += 1;
                    }
                    if operations == mutations {
                        break;
                    }
                    std::fs::rename(staging.join(name), dir.path().join(name)).unwrap();
                    operations += 1;
                }
                write_import_journal(
                    &dir.path().join(IMPORT_JOURNAL),
                    &ImportJournal {
                        staging: ".import.test".into(),
                        entries: names
                            .iter()
                            .enumerate()
                            .map(|(index, name)| ImportEntry {
                                image: (*name).into(),
                                existed: index < 2,
                            })
                            .collect(),
                        committed,
                    },
                )
                .unwrap();
                let lock = bx.lock_run().unwrap();
                recover_import(&bx).unwrap();
                assert_eq!(stamp.exists(), !committed);
                for (index, name) in names.iter().enumerate() {
                    if committed || index < 2 {
                        assert_eq!(
                            std::fs::read(dir.path().join(name)).unwrap(),
                            if committed { b"new" } else { b"old" },
                            "{mutations} mutations, {name}"
                        );
                    } else {
                        assert!(!dir.path().join(name).exists());
                    }
                }
                assert!(!staging.exists());
                assert!(!dir.path().join(IMPORT_JOURNAL).exists());
                drop(lock);
                drop(bx.lock_run().unwrap());
            }
        }
    }

    #[test]
    fn sparse_import_retries_interrupted_reads() {
        use crate::cmd::InterruptedOnce;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("disk.img");
        let payload = [1, 0, 0, 2, 0, 0];
        let mut source = InterruptedOnce(true).chain(payload.as_slice());
        write_sparse(&path, &mut source, payload.len() as u64).unwrap();
        assert_eq!(std::fs::read(path).unwrap(), payload);
    }

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

    #[test]
    fn export_refuses_box_state_and_preserves_its_files() {
        let dir = tempfile::tempdir().unwrap();
        let _home = TestHome::new();
        let bx = build_box_ref(dir.path(), &[]);
        let pid = bx.get_dir().join(crate::state::PID_FILE);
        std::fs::write(&pid, b"keep identity").unwrap();
        for name in [
            crate::state::ROOTFS_FILE,
            crate::state::RECIPE_FILE,
            crate::state::PID_FILE,
        ] {
            let destination = bx.get_dir().join(name);
            let original = std::fs::read(&destination).unwrap();
            let error = export(&bx, &destination).unwrap_err().to_string();
            assert!(error.contains("inside box state"), "{error}");
            assert_eq!(std::fs::read(destination).unwrap(), original);
        }
        for destination in [
            bx.get_dir().to_path_buf(),
            bx.get_dir().join("new/artifact"),
        ] {
            assert!(
                export(&bx, &destination)
                    .unwrap_err()
                    .to_string()
                    .contains("inside box state")
            );
        }
        let alias = dir.path().join("state-alias");
        crate::sys::symlink_dir(bx.get_dir(), &alias).unwrap();
        assert!(
            export(&bx, &alias.join("artifact"))
                .unwrap_err()
                .to_string()
                .contains("inside box state")
        );

        let outside = dir.path().join("outside");
        std::fs::write(&outside, b"keep outside").unwrap();
        let internal_link = bx.get_dir().join("link");
        crate::sys::symlink_file(&outside, &internal_link).unwrap();
        assert!(
            export(&bx, &internal_link)
                .unwrap_err()
                .to_string()
                .contains("inside box state")
        );
        assert!(
            std::fs::symlink_metadata(internal_link)
                .unwrap()
                .is_symlink()
        );
        assert_eq!(std::fs::read(pid).unwrap(), b"keep identity");
    }

    #[test]
    fn export_replaces_a_symlink_destination() {
        let dir = tempfile::tempdir().unwrap();
        let _home = TestHome::new();
        let bx = build_box_ref(dir.path(), &["data"]);
        let sentinel = dir.path().join("sentinel");
        let destination = dir.path().join("export");
        std::fs::write(&sentinel, b"keep me").unwrap();
        crate::sys::symlink_file(&sentinel, &destination).unwrap();

        export(&bx, &destination).unwrap();
        assert!(std::fs::symlink_metadata(&destination).unwrap().is_file());
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"keep me");
    }

    #[test]
    fn export_follows_a_symlinked_destination_parent() {
        let dir = tempfile::tempdir().unwrap();
        let _home = TestHome::new();
        let bx = build_box_ref(dir.path(), &[]);
        let real_parent = dir.path().join("real");
        let linked_parent = dir.path().join("linked");
        std::fs::create_dir(&real_parent).unwrap();
        crate::sys::symlink_dir(&real_parent, &linked_parent).unwrap();

        export(&bx, &linked_parent.join("export.terra")).unwrap();
        assert!(real_parent.join("export.terra").is_file());
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

    /// A truncated later entry leaves every live image unchanged, including earlier complete entries.
    #[test]
    fn an_import_cut_off_part_way_leaves_the_images_it_reached_intact() {
        let dir = tempfile::tempdir().unwrap();
        let _home = TestHome::new();
        let bx = build_box_ref(dir.path(), &["data"]);

        let artifact = dir.path().join("cut-off.terra");
        let mut gz = GzEncoder::new(
            BufWriter::new(File::create(&artifact).unwrap()),
            Compression::fast(),
        );
        gz.write_all(STORAGE_ARTIFACT_MAGIC).unwrap();
        write_entry_header(&mut gz, "rootfs.img", 1 << 20).unwrap();
        gz.write_all(&vec![0; 1 << 20]).unwrap();
        write_entry_header(&mut gz, "vol-data.img", 1 << 20).unwrap();
        gz.write_all(b"a few bytes").unwrap(); // far short of the declared length
        gz.finish().unwrap().flush().unwrap();

        let err = format!("{:#}", import(&bx, &artifact).unwrap_err());
        assert!(err.contains("part-way through"), "{err}");
        assert_eq!(
            std::fs::read(bx.get_dir().join(crate::state::ROOTFS_FILE)).unwrap(),
            b"rootfs data",
            "a truncated artifact replaced the live image"
        );
        assert_eq!(
            std::fs::read(bx.get_volume_image("data")).unwrap(),
            b"data data",
            "an earlier complete artifact entry replaced the live image"
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

    #[test]
    fn storage_show_json_renders_images_and_total() {
        let dir = tempfile::tempdir().unwrap();
        let _home = TestHome::new();
        let bx = build_box_ref(dir.path(), &["data"]);

        let output = StorageShowOutput {
            images: vec![StorageImageEntry {
                name: "rootfs.ext4".to_string(),
                path: Path::new("/tmp/rootfs.ext4"),
                virtual_bytes: 1024,
                disk_bytes: 512,
                is_unused: false,
            }],
            total_disk_bytes: 512,
        };
        let json = serde_json::to_string(&output).unwrap();
        assert!(json.contains(r#""name":"rootfs.ext4""#));
        assert!(json.contains(r#""virtual_bytes":1024"#));
        assert!(json.contains(r#""disk_bytes":512"#));
        assert!(json.contains(r#""is_unused":false"#));
        assert!(json.contains(r#""total_disk_bytes":512"#));

        assert!(show(&bx, true).is_ok());
    }
}
