//! `terra <box> storage` - the box's guest filesystem and volume images.

use crate::approval::{Approval, request_recipe_approval};
use crate::cli::{StorageArgs, StorageCmd, StorageFileArgs, StorageImportArgs};
use crate::recipe::resolve;
use crate::recipe::{MAX_RECIPE_BYTES, Recipe, Volume, VolumeLifetime, load_path};
use crate::render::{escape_printable, escape_printable_path, finish_stdout_write};
use crate::state::{BoxRef, RECIPE_FILE, ROOTFS_FILE, StagedImportFile};
use crate::vm::image::{self, BYTES_PER_MIB};
use anyhow::{Context, Result};
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use serde::Serialize;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const STORAGE_ARTIFACT_MAGIC: &[u8; 16] = b"terra-storage-1\n";

pub fn run(
    args: &StorageArgs,
    name: Option<&str>,
    project_dir: &Path,
    is_at_a_terminal: bool,
) -> Result<ExitCode> {
    let pinned_box = || resolve::resolve_box(name, project_dir, resolve::Existence::MustExist);
    match &args.cmd {
        StorageCmd::Show(show_args) => show(&pinned_box()?, show_args.json),
        StorageCmd::Export(StorageFileArgs { file }) => export(&pinned_box()?, file),
        StorageCmd::Import(StorageImportArgs {
            file: StorageFileArgs { file },
            trust_recipe,
        }) => {
            let bx = resolve::resolve_box(name, project_dir, resolve::Existence::MayBeMissing)?;
            let approval = Approval::ChosenByHand {
                trust_recipe: *trust_recipe,
            };
            import(&bx, file, &approval, is_at_a_terminal)
        }
        StorageCmd::Prune => prune(&pinned_box()?),
    }?;
    Ok(ExitCode::SUCCESS)
}

fn list_recipe_volumes(bx: &BoxRef) -> Result<Vec<Volume>> {
    let recipe = load_path(&bx.get_dir().join(RECIPE_FILE), bx.get_project_dir())
        .context("reading the pinned recipe")?;
    Ok(recipe.volumes)
}

fn list_recipe_volume_names(bx: &BoxRef) -> Result<Vec<String>> {
    Ok(list_recipe_volumes(bx)?
        .into_iter()
        .map(|volume| volume.name)
        .collect())
}

#[derive(Serialize)]
struct StorageShowOutput {
    images: Vec<StorageImageEntry>,
    total_disk_bytes: u64,
}

#[derive(Serialize)]
struct StorageImageEntry {
    name: String,
    path: PathBuf,
    virtual_bytes: u64,
    disk_bytes: u64,
    is_unused: bool,
}

fn show(bx: &BoxRef, json: bool) -> Result<()> {
    let images = list_image_entries(bx)?;
    let total_disk_bytes = images.iter().map(|image| image.disk_bytes).sum();
    let mut out = std::io::stdout().lock();
    if json {
        let rendered = serde_json::to_string_pretty(&StorageShowOutput {
            images,
            total_disk_bytes,
        })
        .context("serializing storage images to json")?;
        return finish_stdout_write(writeln!(out, "{rendered}"));
    }
    if images.is_empty() {
        eprintln!(
            "terra: {bx} has no images yet - `terra {} setup` builds them",
            bx.get_name()
        );
        return Ok(());
    }
    let names: Vec<String> = images
        .iter()
        .map(|image| escape_printable_path(Path::new(&image.name)))
        .collect();
    let width = names.iter().map(String::len).max().unwrap_or(0);
    finish_stdout_write(writeln!(out, "{:<12} {}", bx.get_state()?, bx.get_name()))?;
    for (name, image) in names.iter().zip(&images) {
        let note = if image.is_unused {
            format!(
                "  (unused - `terra {} storage prune` removes it)",
                bx.get_name()
            )
        } else {
            String::new()
        };
        finish_stdout_write(writeln!(
            out,
            "  {name:<width$}  {:>12}  {:>12} on disk{note}",
            format_mib(image.virtual_bytes),
            format_mib(image.disk_bytes)
        ))?;
    }
    finish_stdout_write(writeln!(
        out,
        "  {:<width$}  {:>12}  {:>12} on disk",
        "total",
        "",
        format_mib(total_disk_bytes)
    ))
}

fn list_image_entries(bx: &BoxRef) -> Result<Vec<StorageImageEntry>> {
    let images = bx.list_images()?;
    if images.is_empty() {
        // A box with no images may have no pin to name its volumes by.
        return Ok(Vec::new());
    }
    let unused = bx.list_unused_volume_images(&list_recipe_volume_names(bx)?)?;
    images
        .into_iter()
        .map(|path| {
            let meta = std::fs::metadata(&path)
                .with_context(|| format!("reading {}", escape_printable_path(&path)))?;
            Ok(StorageImageEntry {
                name: path
                    .file_name()
                    .unwrap_or(path.as_os_str())
                    .to_string_lossy()
                    .into_owned(),
                virtual_bytes: meta.len(),
                disk_bytes: crate::sys::allocated_size(&path, &meta),
                is_unused: unused.contains(&path),
                path,
            })
        })
        .collect()
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

fn export(bx: &BoxRef, to: &Path) -> Result<()> {
    refuse_a_destination_inside_box_state(bx, to)?;
    let _lock = bx.lock_run()?;
    bx.recover_import()?;
    anyhow::ensure!(
        bx.is_set_up(),
        "{bx} is not set up - `terra {} setup` finishes it; an artifact carries the \
         recipe its root was set up for",
        bx.get_name()
    );
    let recipe_path = bx.get_dir().join(RECIPE_FILE);
    let recipe = std::fs::read(&recipe_path)
        .with_context(|| format!("reading {}", recipe_path.display()))?;
    let images = list_exportable_images(bx)?;
    image::staged_write(to, |out| write_artifact(&recipe, &images, out))
        .with_context(|| format!("writing {}", escape_printable_path(to)))?;
    for img in &images {
        eprintln!("terra: exported {}", escape_printable_path(img));
    }
    eprintln!("terra: wrote {}", escape_printable_path(to));
    Ok(())
}

fn refuse_a_destination_inside_box_state(bx: &BoxRef, to: &Path) -> Result<()> {
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
    Ok(())
}

fn list_exportable_images(bx: &BoxRef) -> Result<Vec<PathBuf>> {
    let rootfs = bx.get_dir().join(ROOTFS_FILE);
    let box_volumes = list_recipe_volumes(bx)?
        .into_iter()
        .filter(|volume| volume.lifetime == VolumeLifetime::Box)
        .map(|volume| bx.get_volume_image_path(&volume.name))
        .collect::<Vec<_>>();
    Ok(bx
        .list_images()?
        .into_iter()
        .filter(|path| path == &rootfs || box_volumes.contains(path))
        .collect())
}

fn write_artifact(recipe: &[u8], images: &[PathBuf], to: &mut File) -> Result<()> {
    // `fast`: the images are mostly the zeros a sparse file reads as, which
    // compress the same at any level, and a multi-GiB box should not spend
    // minutes on the rest.
    let mut gz = GzEncoder::new(BufWriter::new(to), Compression::fast());
    gz.write_all(STORAGE_ARTIFACT_MAGIC)?;
    write_entry_header(&mut gz, RECIPE_FILE, recipe.len() as u64)?;
    gz.write_all(recipe)?;
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

/// Check the artifact's magic and read its leading recipe.
fn read_artifact_recipe(artifact: &mut impl Read, from: &Path) -> Result<String> {
    let mut magic = [0u8; STORAGE_ARTIFACT_MAGIC.len()];
    if artifact.read_exact(&mut magic).is_err() || magic != *STORAGE_ARTIFACT_MAGIC {
        anyhow::bail!(
            "{} is not a terra storage artifact (`terra <box> storage export` \
             writes one)",
            escape_printable_path(from)
        );
    }
    let recipe_len = match read_entry_header(artifact)? {
        Some((name, len)) if name == RECIPE_FILE => len,
        _ => anyhow::bail!(
            "{} does not start with the box's recipe - an older terra wrote it; \
             export it again",
            escape_printable_path(from)
        ),
    };
    anyhow::ensure!(
        recipe_len <= MAX_RECIPE_BYTES,
        "{} carries a recipe past the {}-byte limit",
        escape_printable_path(from),
        MAX_RECIPE_BYTES
    );
    let mut text = String::new();
    artifact
        .take(recipe_len)
        .read_to_string(&mut text)
        .context("reading the artifact's recipe")?;
    anyhow::ensure!(
        text.len() as u64 == recipe_len,
        "the artifact ends part-way through its recipe"
    );
    Ok(text)
}

fn import(bx: &BoxRef, from: &Path, approval: &Approval, is_at_a_terminal: bool) -> Result<()> {
    let file = crate::sys::open_regular_file(from)
        .with_context(|| format!("opening {}", escape_printable_path(from)))?;
    let mut artifact = GzDecoder::new(BufReader::new(file));
    let recipe = resolve::RecipeFile {
        from: std::path::absolute(from).context("resolving the artifact path")?,
        text: read_artifact_recipe(&mut artifact, from)?,
    };
    let held = bx.lock_if_present()?;
    let approved = request_recipe_approval(
        resolve::ResolvedRecipe {
            bx: bx.clone(),
            source: resolve::Source::Artifact(recipe),
            manifest: None,
        },
        approval,
        is_at_a_terminal,
    )?;
    let _lock = match held {
        Some(lock) => lock,
        None => bx.lock_and_repair()?,
    };
    bx.prepare_state_dir()?;
    let staging_dir = bx.begin_import()?;
    let staged = stage_images(bx, from, &approved.recipe, &mut artifact, &staging_dir).and_then(
        |mut staged| {
            for name in approved.write_pin(&staging_dir)? {
                staged.push(StagedImportFile {
                    live: bx.get_dir().join(name),
                    stage: staging_dir.join(name),
                });
            }
            Ok(staged)
        },
    );
    let staged = match staged {
        Ok(staged) => staged,
        Err(error) => {
            bx.recover_import().context("cleaning failed import")?;
            return Err(error);
        }
    };
    let committed = bx.commit_import(&staged);
    for file in &staged {
        let _ = std::fs::remove_file(&file.stage);
    }
    let _ = std::fs::remove_dir(&staging_dir);
    committed?;
    report_import(bx, &staged)
}

fn stage_images(
    bx: &BoxRef,
    from: &Path,
    recipe: &Recipe,
    gz: &mut impl Read,
    staging_dir: &Path,
) -> Result<Vec<StagedImportFile>> {
    let rootfs_limit = u64::from(recipe.hw.rootfs_mib) * BYTES_PER_MIB;
    let volume_limit = |name: &str| {
        let volume_name = name.strip_prefix("vol-")?.strip_suffix(".img")?;
        recipe
            .volumes
            .iter()
            .find(|volume| volume.name == volume_name)
            .map(|volume| u64::from(volume.size_mib) * BYTES_PER_MIB)
    };
    let total_limit = rootfs_limit
        + recipe
            .volumes
            .iter()
            .map(|volume| u64::from(volume.size_mib) * BYTES_PER_MIB)
            .sum::<u64>();

    let mut staged: Vec<StagedImportFile> = Vec::new();
    let mut total = 0u64;
    while let Some((name, len)) = read_entry_header(gz)? {
        let live = bx.find_image_named(&name).with_context(|| {
            format!(
                "{} carries '{}', which is not an image a box holds",
                escape_printable_path(from),
                escape_printable(&name)
            )
        })?;
        anyhow::ensure!(
            !staged.iter().any(|file| file.live == live),
            "{} carries '{}' twice",
            escape_printable_path(from),
            escape_printable(&name)
        );
        let limit = if name == ROOTFS_FILE {
            Some(rootfs_limit)
        } else {
            volume_limit(&name)
        }
        .with_context(|| format!("{name} is not an image the recipe names"))?;
        anyhow::ensure!(
            len <= limit,
            "{} carries '{}' at {len} bytes, past the recipe's {limit}-byte limit",
            escape_printable_path(from),
            escape_printable(&name)
        );
        total = total
            .checked_add(len)
            .context("the artifact's image lengths overflow")?;
        anyhow::ensure!(
            total <= total_limit,
            "{} carries {total} bytes of images, past the {total_limit}-byte import limit",
            escape_printable_path(from)
        );
        let stage = staging_dir.join(&name);
        write_sparse(&stage, gz, len)?;
        staged.push(StagedImportFile { live, stage });
    }
    let rootfs = bx.get_dir().join(ROOTFS_FILE);
    anyhow::ensure!(
        staged.iter().any(|file| file.live == rootfs),
        "{} carries no {ROOTFS_FILE}",
        escape_printable_path(from)
    );
    Ok(staged)
}

fn report_import(bx: &BoxRef, staged: &[StagedImportFile]) -> Result<()> {
    for file in staged {
        eprintln!("terra: restored {}", escape_printable_path(&file.live));
    }
    for kept in bx
        .list_images()?
        .iter()
        .filter(|image| !staged.iter().any(|file| file.live == **image))
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
    bx.recover_import()?;
    let recipe_volumes = list_recipe_volume_names(bx)?;
    let unused = bx.list_unused_volume_images(&recipe_volumes)?;
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
    fn sparse_import_retries_interrupted_reads() {
        use crate::cmd::InterruptedOnce;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("disk.img");
        let payload = [1, 0, 0, 2, 0, 0];
        let mut source = InterruptedOnce(true).chain(payload.as_slice());
        write_sparse(&path, &mut source, payload.len() as u64).unwrap();
        assert_eq!(std::fs::read(path).unwrap(), payload);
    }

    const TEST_RECIPE: &str =
        "hw:\n  cpus: 1\nvolumes:\n  - {name: data, guest: /v0, size_mib: 8}\n";

    fn write_test_recipe(gz: &mut impl Write) {
        write_entry_header(gz, RECIPE_FILE, TEST_RECIPE.len() as u64).unwrap();
        gz.write_all(TEST_RECIPE.as_bytes()).unwrap();
    }

    fn import_trusting(bx: &BoxRef, from: &Path, trust_recipe: bool) -> Result<()> {
        super::import(bx, from, &Approval::ChosenByHand { trust_recipe }, false)
    }

    fn import(bx: &BoxRef, from: &Path) -> Result<()> {
        import_trusting(bx, from, true)
    }

    /// A set-up box with a pinned recipe, a root filesystem and the volumes
    /// named.
    fn build_box_ref(project_dir: &Path, volumes: &[&str]) -> BoxRef {
        use std::fmt::Write as _;
        let bx = BoxRef::resolve(project_dir, "dev").unwrap();
        std::fs::create_dir_all(bx.get_dir()).unwrap();
        let mut recipe = String::from("hw:\n  cpus: 1\nvolumes:\n");
        for (i, name) in volumes.iter().enumerate() {
            let _ = writeln!(recipe, "  - {{name: {name}, guest: /v{i}, size_mib: 8}}");
            std::fs::write(
                bx.get_volume_image_path(name),
                format!("{name} data").as_bytes(),
            )
            .unwrap();
        }
        std::fs::write(bx.get_dir().join(crate::state::RECIPE_FILE), recipe).unwrap();
        std::fs::write(bx.get_dir().join(crate::state::ROOTFS_FILE), b"rootfs data").unwrap();
        bx.write_setup_stamp().unwrap();
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

        let elsewhere = dir.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        let into = BoxRef::resolve(&elsewhere, "dev").unwrap();
        import(&into, &artifact).unwrap();
        assert_eq!(
            std::fs::read(into.get_dir().join(RECIPE_FILE)).unwrap(),
            std::fs::read(from.get_dir().join(RECIPE_FILE)).unwrap()
        );
        assert!(into.is_set_up(), "an import must boot without a setup");

        for image in [
            from.get_dir().join(crate::state::ROOTFS_FILE),
            from.get_volume_image_path("data"),
            from.get_volume_image_path("cache"),
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
        std::fs::write(from.get_volume_image_path("old"), b"dropped").unwrap();

        let artifact = dir.path().join("dev.terra");
        export(&from, &artifact).unwrap();

        let elsewhere = dir.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).unwrap();
        let into = BoxRef::resolve(&elsewhere, "dev").unwrap();
        import(&into, &artifact).unwrap();
        assert!(!into.get_volume_image_path("old").exists());
    }

    /// A boot-lifetime image can outlive a crashed VM, but the artifact carries
    /// only what a restart would have kept.
    #[test]
    fn export_skips_boot_lifetime_volumes() {
        let dir = tempfile::tempdir().unwrap();
        let _home = TestHome::new();
        let bx = build_box_ref(dir.path(), &["data"]);
        std::fs::write(bx.get_volume_image_path("scratch"), b"scratch data").unwrap();
        std::fs::write(
            bx.get_dir().join(crate::state::RECIPE_FILE),
            "hw:\n  cpus: 1\nvolumes:\n  - {name: data, guest: /v0, size_mib: 8}\n  - {name: scratch, guest: /v1, size_mib: 8, lifetime: boot}\n",
        )
        .unwrap();
        bx.write_setup_stamp().unwrap();

        let artifact = dir.path().join("dev.terra");
        export(&bx, &artifact).unwrap();

        assert_eq!(
            artifact_entry_names(&artifact),
            [RECIPE_FILE, "rootfs.img", "vol-data.img"]
        );
    }

    fn write_crafted_artifact(path: &Path, recipe: Option<&str>, images: &[(&str, u64)]) {
        let mut gz = GzEncoder::new(File::create(path).unwrap(), Compression::fast());
        gz.write_all(STORAGE_ARTIFACT_MAGIC).unwrap();
        if let Some(recipe) = recipe {
            write_entry_header(&mut gz, RECIPE_FILE, recipe.len() as u64).unwrap();
            gz.write_all(recipe.as_bytes()).unwrap();
        }
        for (name, len) in images {
            write_entry_header(&mut gz, name, *len).unwrap();
            gz.write_all(&vec![0; usize::try_from(*len).unwrap()])
                .unwrap();
        }
        gz.finish().unwrap();
    }

    fn new_project(dir: &Path) -> BoxRef {
        let project = dir.join("elsewhere");
        std::fs::create_dir(&project).unwrap();
        BoxRef::resolve(&project, "dev").unwrap()
    }

    #[test]
    fn export_refuses_a_box_that_is_not_set_up() {
        let dir = tempfile::tempdir().unwrap();
        let _home = TestHome::new();
        let bx = build_box_ref(dir.path(), &[]);
        bx.remove_setup_stamp().unwrap();
        let error = export(&bx, &dir.path().join("dev.terra"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("terra dev setup"), "{error}");
        assert!(!dir.path().join("dev.terra").exists());
    }

    /// With nobody to ask and no `--trust-recipe`, the import shows the carried
    /// recipe - it has no file to point at - and unpacks nothing.
    #[test]
    fn an_untrusted_import_shows_the_recipe_and_leaves_nothing_behind() {
        let dir = tempfile::tempdir().unwrap();
        let _home = TestHome::new();
        let artifact = dir.path().join("dev.terra");
        write_crafted_artifact(
            &artifact,
            Some(TEST_RECIPE),
            &[("rootfs.img", 1 << 20), ("vol-data.img", 1 << 20)],
        );
        let into = new_project(dir.path());

        let error = import_trusting(&into, &artifact, false)
            .unwrap_err()
            .to_string();
        assert!(error.contains("cpus: 1"), "{error}");
        assert!(error.contains("It would grant"), "{error}");
        assert!(error.contains("--trust-recipe"), "{error}");
        assert!(
            !into.get_dir().exists(),
            "a refused import left a box behind"
        );

        import_trusting(&into, &artifact, true).unwrap();
        assert!(into.is_set_up());
    }

    /// An import stamps the root it brings for the carried recipe, so an
    /// artifact without one would stamp the box's old root for a recipe that
    /// never baked it.
    #[test]
    fn an_artifact_without_a_root_is_refused_and_keeps_the_box() {
        let dir = tempfile::tempdir().unwrap();
        let _home = TestHome::new();
        let bx = build_box_ref(dir.path(), &["data"]);
        let artifact = dir.path().join("partial.terra");
        write_crafted_artifact(&artifact, Some(TEST_RECIPE), &[("vol-data.img", 1 << 20)]);
        assert!(import(&bx, &artifact).is_err());
        assert!(bx.is_set_up());
    }

    #[test]
    fn an_artifact_without_a_leading_recipe_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let _home = TestHome::new();
        let bx = build_box_ref(dir.path(), &[]);
        let artifact = dir.path().join("old.terra");
        write_crafted_artifact(&artifact, None, &[("rootfs.img", 1 << 20)]);
        let error = import(&bx, &artifact).unwrap_err().to_string();
        assert!(error.contains("export it again"), "{error}");
    }

    fn artifact_entry_names(path: &Path) -> Vec<String> {
        let mut src = GzDecoder::new(BufReader::new(File::open(path).unwrap()));
        let mut magic = [0u8; STORAGE_ARTIFACT_MAGIC.len()];
        src.read_exact(&mut magic).unwrap();
        assert_eq!(&magic, STORAGE_ARTIFACT_MAGIC);
        let mut names = Vec::new();
        while let Some((name, len)) = read_entry_header(&mut src).unwrap() {
            names.push(name);
            std::io::copy(&mut (&mut src).take(len), &mut std::io::sink()).unwrap();
        }
        names
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
            write_test_recipe(&mut gz);
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

        // …and one that is an artifact but carries no images: an empty box is
        // never what an import was asked for.
        let empty = dir.path().join("empty.terra");
        let mut gz = GzEncoder::new(File::create(&empty).unwrap(), Compression::fast());
        gz.write_all(STORAGE_ARTIFACT_MAGIC).unwrap();
        write_test_recipe(&mut gz);
        gz.finish().unwrap();
        assert!(
            import(&bx, &empty)
                .unwrap_err()
                .to_string()
                .contains("carries no rootfs.img")
        );
    }

    #[test]
    fn an_artifact_larger_than_the_recipe_allows_is_refused_before_staging() {
        let dir = tempfile::tempdir().unwrap();
        let _home = TestHome::new();
        let bx = build_box_ref(dir.path(), &[]);
        let artifact = dir.path().join("too-large.terra");
        let mut gz = GzEncoder::new(File::create(&artifact).unwrap(), Compression::fast());
        gz.write_all(STORAGE_ARTIFACT_MAGIC).unwrap();
        write_test_recipe(&mut gz);
        write_entry_header(&mut gz, "rootfs.img", 512 * 1024 * 1024 + 1).unwrap();
        gz.finish().unwrap();

        let err = import(&bx, &artifact).unwrap_err().to_string();
        assert!(err.contains("the recipe's"), "{err}");
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
        write_test_recipe(&mut gz);
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
            std::fs::read(bx.get_volume_image_path("data")).unwrap(),
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
        std::fs::write(bx.get_volume_image_path("old"), b"dropped").unwrap();

        prune(&bx).unwrap();
        assert!(
            !bx.get_volume_image_path("old").exists(),
            "the dropped volume was kept"
        );
        assert!(
            bx.get_volume_image_path("data").exists(),
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
                path: PathBuf::from("/tmp/rootfs.ext4"),
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
