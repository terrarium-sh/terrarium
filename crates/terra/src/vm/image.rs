//! The payloads terra ships inside its own binary - the guest kernel, the boot
//! volume, and the prebaked filesystems a box is made of - and how each gets
//! onto disk. Every one is installed the same way: unpack beside the
//! destination, rename it in.

use anyhow::{Context, Result, bail};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};

static ROOTFS_IMG_GZ: &[u8] = include_bytes!(env!("TERRA_ROOTFS_IMG"));

/// The prebaked *empty* filesystem for scratch volumes
static VOLUME_IMG_GZ: &[u8] = include_bytes!(env!("TERRA_VOLUME_IMG"));

/// The guest kernel built from vendor/libkrunfw; the Makefile sets
/// `TERRA_KERNEL_GZ`. An ELF vmlinux on `x86_64`, a flat `Image` on aarch64 —
/// see `libkrun_ext::KERNEL_FORMAT`, which has to agree with it.
static KERNEL_GZ: &[u8] = include_bytes!(env!("TERRA_KERNEL_GZ"));
const KERNEL_NAME: &str = concat!("vmlinux-", include_str!(env!("TERRA_KERNEL_GZ_SHA256")));

/// A read-only ext4 with the guest agent and `resize2fs`. The guest's root
/// filesystem is this volume, never a host directory.
static BOOT_IMG_GZ: &[u8] = include_bytes!(env!("TERRA_BOOT_IMG"));
const BOOT_NAME: &str = concat!("boot-", include_str!(env!("TERRA_BOOT_IMG_SHA256")));

fn to_stage_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .unwrap_or(path.as_os_str())
        .to_string_lossy()
        .into_owned();
    // the leading `.` hides a leftover from both directory sweeps; the pid keeps concurrent runs apart.
    path.with_file_name(format!(".{name}.{}.tmp", std::process::id()))
}

/// Unpack `src` next to `path` and rename it into place, so a half-written
/// payload never ends up where a later run would take it as good. `finish`
/// runs on the completed temporary before the rename; if it errors, the
/// temporary is removed.
fn install(
    path: &Path,
    src: &mut impl Read,
    finish: impl FnOnce(&File, u64) -> Result<()>,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let tmp = to_stage_path(path);
    match unpack_into(&tmp, src, finish) {
        Ok(()) => {
            std::fs::rename(&tmp, path).with_context(|| format!("installing {}", path.display()))
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

fn unpack_into(
    tmp: &Path,
    src: &mut impl Read,
    finish: impl FnOnce(&File, u64) -> Result<()>,
) -> Result<()> {
    let mut out = File::create(tmp).with_context(|| format!("creating {}", tmp.display()))?;
    let written = std::io::copy(src, &mut out)
        .with_context(|| format!("unpacking into {}", tmp.display()))?;
    finish(&out, written)
}

/// Write the prebaked root filesystem to `path`, sized to `size_mib` (sparse;
/// the guest grows the filesystem into it on first boot).
pub fn ensure_rootfs_image(path: &Path, size_mib: u32) -> Result<()> {
    ensure_image(path, size_mib, ROOTFS_IMG_GZ, "hw.rootfs_mib")
}

pub fn ensure_volume_image(path: &Path, size_mib: u32) -> Result<()> {
    ensure_image(path, size_mib, VOLUME_IMG_GZ, "size_mib")
}

fn ensure_image(path: &Path, size_mib: u32, gz: &[u8], field: &str) -> Result<()> {
    let target = u64::from(size_mib) * 1024 * 1024;
    if path.exists() {
        return resize_image(path, target, field);
    }
    // One byte past the cap proves it does not fit without unpacking it all.
    let mut bounded = flate2::read::GzDecoder::new(gz).take(target + 1);
    install(path, &mut bounded, |out, baked| {
        if target < baked {
            bail!("the prebaked filesystem does not fit {field} ({size_mib} MiB)");
        }
        out.set_len(target)
            .with_context(|| format!("sizing {}", path.display()))
    })
}

/// Growing a sparse image is free; shrinking would truncate the filesystem
/// inside it, so a smaller size only warns and keeps the current size.
fn resize_image(path: &Path, target: u64, field: &str) -> Result<()> {
    let current = std::fs::metadata(path)
        .with_context(|| format!("reading {}", path.display()))?
        .len();
    let mib = |n: u64| n.div_ceil(1024 * 1024);
    match target.cmp(&current) {
        std::cmp::Ordering::Equal => {}
        std::cmp::Ordering::Greater => {
            OpenOptions::new()
                .write(true)
                .open(path)
                .with_context(|| format!("opening {}", path.display()))?
                .set_len(target)
                .with_context(|| format!("growing {}", path.display()))?;
            eprintln!(
                "terra: {field} raised to {} MiB - the guest will expand {} on this boot",
                mib(target),
                path.file_name().unwrap_or(path.as_os_str()).display()
            );
        }
        std::cmp::Ordering::Less => {
            eprintln!(
                "terra: warning: {field} is {} MiB but {} is already {} MiB; \
                 shrinking would truncate the filesystem, so the existing size is kept \
                 (`terra rm` rebuilds the box at the smaller size)",
                mib(target),
                path.file_name().unwrap_or(path.as_os_str()).display(),
                mib(current),
            );
        }
    }
    Ok(())
}

pub fn ensure_kernel_on_disk() -> Result<PathBuf> {
    cached(KERNEL_GZ, KERNEL_NAME, "guest kernel")
}

pub fn ensure_boot_volume_on_disk() -> Result<PathBuf> {
    cached(BOOT_IMG_GZ, BOOT_NAME, "boot image")
}

/// Unpack an embedded payload into [`crate::state::cache_path`], skipping the
/// work when it is already there. `name` embeds the payload's hash, so entries
/// are trusted by name and length alone; the owner-only directory
/// `ensure_cache_dir` insists on is what makes that trust safe.
fn cached(gz: &[u8], name: &str, what: &str) -> Result<PathBuf> {
    let dir = crate::state::ensure_cache_dir()?;
    let path = dir.join(name);

    let trailer = gz
        .last_chunk::<4>()
        .with_context(|| format!("the embedded {what} is not a gzip stream"))?;
    let unpacked = u64::from(u32::from_le_bytes(*trailer));

    // `symlink_metadata`: a link parked at this name is a miss, not a hit on
    // whatever it points at.
    if std::fs::symlink_metadata(&path).is_ok_and(|m| m.is_file() && m.len() == unpacked) {
        return Ok(path);
    }
    install(&path, &mut flate2::read::GzDecoder::new(gz), |_, _| Ok(()))
        .with_context(|| format!("unpacking the {what}"))?;

    let stale = format!("{}-", name.split_once('-').map_or(name, |(p, _)| p));
    for entry in crate::sys::dir_entries(&dir) {
        if entry.path() != path && entry.file_name().to_string_lossy().starts_with(&stale) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resizing_grows_but_never_shrinks() {
        let dir = tempfile::tempdir().unwrap();
        let img = dir.path().join("rootfs.img");
        let mib = 1024 * 1024;
        std::fs::write(&img, vec![0u8; 0]).unwrap();
        File::options()
            .write(true)
            .open(&img)
            .unwrap()
            .set_len(4 * mib)
            .unwrap();

        resize_image(&img, 4 * mib, "hw.rootfs_mib").unwrap(); // unchanged
        assert_eq!(std::fs::metadata(&img).unwrap().len(), 4 * mib);

        resize_image(&img, 16 * mib, "hw.rootfs_mib").unwrap(); // grows
        assert_eq!(std::fs::metadata(&img).unwrap().len(), 16 * mib);

        resize_image(&img, 8 * mib, "hw.rootfs_mib").unwrap(); // refuses to shrink
        assert_eq!(std::fs::metadata(&img).unwrap().len(), 16 * mib);
    }

    #[test]
    fn a_rootfs_smaller_than_the_prebaked_image_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        assert!(ensure_rootfs_image(&dir.path().join("tiny.img"), 1).is_err());
    }

    /// Nothing is renamed into place until it is whole, and a payload that was
    /// refused takes its temporary with it. A leftover named like the thing it
    /// was going to be is the failure: in a box's state directory
    /// [`crate::state::BoxRef::unused_volume_images`] would read it as a
    /// volume image, and in the cache it would be read back as a kernel.
    #[test]
    fn a_refused_payload_leaves_nothing_behind() {
        let dir = tempfile::tempdir().unwrap();
        let img = dir.path().join("vol-data.img");

        // A prebaked filesystem that does not fit is the refusal every caller
        // can actually reach.
        assert!(ensure_volume_image(&img, 1).is_err());
        assert!(!img.exists(), "a half-written image was installed");
        let left: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert!(left.is_empty(), "a temporary was left behind: {left:?}");
    }
}
