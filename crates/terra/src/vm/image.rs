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

/// The guest kernel from the pinned kernel source; the Makefile sets
/// `TERRA_KERNEL_GZ`.
static KERNEL_GZ: &[u8] = include_bytes!(env!("TERRA_KERNEL_GZ"));
const KERNEL_NAME: &str = concat!("vmlinux-", include_str!(env!("TERRA_KERNEL_GZ_SHA256")));

/// A read-only ext4 with the guest agent and `resize2fs`. The guest's root
/// filesystem is this volume, never a host directory.
static BOOT_IMG_GZ: &[u8] = include_bytes!(env!("TERRA_BOOT_IMG"));
const BOOT_NAME: &str = concat!("boot-", include_str!(env!("TERRA_BOOT_IMG_SHA256")));
pub(crate) const BYTES_PER_MIB: u64 = 1024 * 1024;

pub(crate) fn write_sparse_chunk(out: &mut File, chunk: &[u8]) -> std::io::Result<()> {
    use std::io::{Seek, SeekFrom, Write};
    if chunk.iter().all(|byte| *byte == 0) {
        let offset = i64::try_from(chunk.len()).map_err(std::io::Error::other)?;
        out.seek(SeekFrom::Current(offset))?;
        Ok(())
    } else {
        out.write_all(chunk)
    }
}

fn to_stage_path(path: &Path, attempt: u64) -> PathBuf {
    let name = path
        .file_name()
        .unwrap_or(path.as_os_str())
        .to_string_lossy()
        .into_owned();
    path.with_file_name(format!(".{name}.{attempt}.{}.tmp", std::process::id()))
}

fn parse_staged_pid(name: &str) -> Option<u32> {
    name.strip_prefix('.')?
        .strip_suffix(".tmp")?
        .rsplit('.')
        .next()?
        .parse()
        .ok()
}

/// Remove staging temporaries whose writer is gone: `is_alive` answers for
/// the pid in a temp's name, and a live writer keeps its temporary - only it
/// knows how far the write got.
pub(crate) fn sweep_staging_temps(dir: &Path, is_alive: impl Fn(u32) -> bool) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries {
        let Ok(entry) = entry else {
            continue;
        };
        let Some(pid) = entry.file_name().to_str().and_then(parse_staged_pid) else {
            continue;
        };
        if !is_alive(pid) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

pub(crate) fn staged_write(path: &Path, write: impl FnOnce(&mut File) -> Result<()>) -> Result<()> {
    #[cfg(unix)]
    let parent = File::open(
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new(".")),
    )?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut attempt = 0u64;
    let (tmp, mut out) = loop {
        let tmp = to_stage_path(path, attempt);
        match options.open(&tmp) {
            Ok(file) => break (tmp, file),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                attempt = attempt.checked_add(1).context("too many staging files")?;
            }
            Err(error) => return Err(error).with_context(|| format!("creating {}", tmp.display())),
        }
    };
    let result = write(&mut out).and_then(|()| out.sync_all().context("syncing staged image"));
    drop(out);
    let result = result.and_then(|()| {
        std::fs::rename(&tmp, path).with_context(|| format!("installing {}", path.display()))?;
        #[cfg(unix)]
        parent.sync_all().context("syncing image directory")?;
        Ok(())
    });
    if result.is_err() {
        let _ = std::fs::remove_file(tmp);
    }
    result
}

/// Unpack `src` into a staging temporary for `path`; `finish` sees the open
/// temporary and its byte count before the rename.
fn install(
    path: &Path,
    src: &mut impl Read,
    finish: impl FnOnce(&File, u64) -> Result<()>,
) -> Result<()> {
    staged_write(path, |out| {
        let written =
            std::io::copy(src, out).with_context(|| format!("unpacking {}", path.display()))?;
        finish(out, written)
    })
}

fn install_sparse(
    path: &Path,
    src: &mut impl Read,
    finish: impl FnOnce(&File, u64) -> Result<()>,
) -> Result<()> {
    staged_write(path, |out| {
        crate::sys::make_sparse(out)
            .with_context(|| format!("making {} sparse", path.display()))?;
        let mut buf = vec![0; 64 * 1024];
        let mut written = 0;
        loop {
            let read = match src.read(&mut buf) {
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                result => result.with_context(|| format!("unpacking {}", path.display()))?,
            };
            if read == 0 {
                break;
            }
            write_sparse_chunk(out, &buf[..read])
                .with_context(|| format!("unpacking {}", path.display()))?;
            written += u64::try_from(read).unwrap_or_default();
        }
        finish(out, written)
    })
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
    let target = u64::from(size_mib) * BYTES_PER_MIB;
    if path.exists() {
        return resize_image(path, target, field);
    }
    // One byte past the cap proves it does not fit without unpacking it all.
    let mut bounded = flate2::read::GzDecoder::new(gz).take(target + 1);
    install_sparse(path, &mut bounded, |out, baked| {
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
    let mib = |n: u64| n.div_ceil(BYTES_PER_MIB);
    let name = path.file_name().unwrap_or(path.as_os_str()).display();
    match target.cmp(&current) {
        std::cmp::Ordering::Equal => {}
        std::cmp::Ordering::Greater => {
            let image = OpenOptions::new()
                .write(true)
                .open(path)
                .with_context(|| format!("opening {}", path.display()))?;
            crate::sys::make_sparse(&image)
                .with_context(|| format!("making {} sparse", path.display()))?;
            image
                .set_len(target)
                .with_context(|| format!("growing {}", path.display()))?;
            log::info!(
                "{field} raised to {} MiB; guest filesystem {} will expand on boot",
                mib(target),
                name
            );
            eprintln!(
                "terra: {field} raised to {} MiB - the guest will expand {} on this boot",
                mib(target),
                name
            );
        }
        std::cmp::Ordering::Less => {
            log::warn!(
                "{field} is {} MiB but {} is {} MiB; keeping existing filesystem size (terra rm rebuilds it)",
                mib(target),
                name,
                mib(current)
            );
            eprintln!(
                "terra: warning: {field} is {} MiB but {} is already {} MiB; \
                 shrinking would truncate the filesystem, so the existing size is kept \
                 (`terra rm` rebuilds the box at the smaller size)",
                mib(target),
                name,
                mib(current),
            );
        }
    }
    Ok(())
}

pub fn ensure_kernel_on_disk() -> Result<PathBuf> {
    ensure_cached_payload(KERNEL_GZ, KERNEL_NAME, "guest kernel")
}

pub fn ensure_boot_volume_on_disk() -> Result<PathBuf> {
    ensure_cached_payload(BOOT_IMG_GZ, BOOT_NAME, "boot image")
}

/// Unpack an embedded payload into [`crate::state::get_cache_path`], skipping the
/// work when it is already there. `name` embeds the payload's hash, so entries
/// are trusted by name and length alone; the owner-only directory
/// `ensure_cache_dir` insists on is what makes that trust safe.
fn ensure_cached_payload(gz: &[u8], name: &str, what: &str) -> Result<PathBuf> {
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
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        if entry.path() != path && entry.file_name().to_string_lossy().starts_with(&stale) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
    sweep_staging_temps(&dir, crate::sys::pid_exists);
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resizing_grows_but_never_shrinks() {
        let dir = tempfile::tempdir().unwrap();
        let img = dir.path().join(crate::state::ROOTFS_FILE);
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

    #[test]
    fn sparse_install_preserves_contents_and_trailing_hole() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("image.img");
        let mut bytes = vec![1; 64 * 1024];
        bytes.extend(vec![0; 64 * 1024]);
        bytes.extend(vec![2; 64 * 1024]);
        bytes.extend(vec![0; 64 * 1024]);
        let mut source = bytes.as_slice();

        install_sparse(&path, &mut source, |out, written| {
            out.set_len(written)?;
            Ok(())
        })
        .unwrap();

        assert_eq!(std::fs::metadata(&path).unwrap().len(), bytes.len() as u64);
        assert_eq!(std::fs::read(path).unwrap(), bytes);
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

    /// A staged write replaces its target only through the final rename: a
    /// failure anywhere in filling the temporary leaves what was installed
    /// byte-identical and takes the temporary with it.
    #[test]
    fn a_failed_staged_write_leaves_the_installed_file_alone() {
        use std::io::Write as _;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join(crate::state::ROOTFS_FILE);
        std::fs::write(&target, b"old bytes").unwrap();

        let err = staged_write(&target, |out| {
            out.write_all(b"half of something")?;
            anyhow::bail!("the write failed")
        })
        .expect_err("the closure failed on purpose");
        assert!(err.to_string().contains("the write failed"), "{err}");
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"old bytes",
            "a failed write replaced the live file"
        );
        let left: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(left.len(), 1, "no temporary was left behind: {left:?}");

        staged_write(&target, |out| {
            out.write_all(b"fresh bytes")?;
            Ok(())
        })
        .expect("an uneventful write installs");
        assert_eq!(std::fs::read(&target).unwrap(), b"fresh bytes");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        let target_dir = dir.path().join("target-dir");
        std::fs::create_dir(&target_dir).unwrap();
        assert!(staged_write(&target_dir, |_| Ok(())).is_err());
        assert!(!to_stage_path(&target_dir, 0).exists());
    }

    #[test]
    fn stale_staging_files_do_not_block_installation() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("image.img");
        for attempt in 0..3 {
            std::fs::write(to_stage_path(&target, attempt), b"stale").unwrap();
        }
        staged_write(&target, |out| {
            std::io::Write::write_all(out, b"new")?;
            Ok(())
        })
        .unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"new");
        assert_eq!(std::fs::read(to_stage_path(&target, 0)).unwrap(), b"stale");
        assert!(!to_stage_path(&target, 3).exists());
    }

    #[test]
    fn a_staged_symlink_is_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("image.img");
        let redirected = dir.path().join("redirected");
        std::fs::write(&redirected, b"original").unwrap();
        crate::sys::symlink_file(&redirected, to_stage_path(&target, 0)).unwrap();

        staged_write(&target, |_| Ok(())).unwrap();
        assert!(target.is_file());
        assert_eq!(std::fs::read(&redirected).unwrap(), b"original");
    }

    #[test]
    fn a_staged_write_replaces_a_symlink_destination() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("image.img");
        let redirected = dir.path().join("redirected");
        std::fs::write(&redirected, b"original").unwrap();
        crate::sys::symlink_file(&redirected, &target).unwrap();

        staged_write(&target, |_| Ok(())).unwrap();
        assert!(std::fs::symlink_metadata(&target).unwrap().is_file());
        assert_eq!(std::fs::read(&redirected).unwrap(), b"original");
    }

    #[test]
    fn a_staged_write_follows_a_parent_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let real_parent = dir.path().join("real");
        std::fs::create_dir(&real_parent).unwrap();
        let linked_parent = dir.path().join("linked");
        crate::sys::symlink_dir(&real_parent, &linked_parent).unwrap();

        staged_write(&linked_parent.join("image.img"), |_| Ok(())).unwrap();
        assert!(real_parent.join("image.img").is_file());
    }

    #[test]
    fn read_stage_pid_from_the_writer_name() {
        assert_eq!(parse_staged_pid(".rootfs.img.42.tmp"), Some(42));
        assert_eq!(parse_staged_pid(".boot-deadbeef.7.tmp"), Some(7));
        for other in ["vol-data.img", ".half", ".x.nopid.tmp", "", ".tmp"] {
            assert_eq!(
                parse_staged_pid(other),
                None,
                "{other:?} is not a staging temp"
            );
        }
    }

    /// The cache-directory sweep trusts only the pid in the name: a writer
    /// that may still be running keeps its temporary, a dead one's is taken,
    /// and anything not named like a staging temp is nobody's to remove.
    #[test]
    fn a_sweep_takes_a_dead_writers_temp_and_keeps_a_live_ones() {
        let dir = tempfile::tempdir().unwrap();
        let mine = format!(".rootfs.img.{}.tmp", std::process::id());
        std::fs::write(dir.path().join(&mine), b"staging").unwrap();
        std::fs::write(dir.path().join(".vmlinux-abc.4242.tmp"), b"staging").unwrap();
        std::fs::write(dir.path().join("vol-data.img"), b"installed").unwrap();
        std::fs::write(dir.path().join(".stray"), b"?").unwrap();

        sweep_staging_temps(dir.path(), |pid| pid == std::process::id());

        assert!(
            dir.path().join(&mine).exists(),
            "our own staging temp was swept"
        );
        assert!(!dir.path().join(".vmlinux-abc.4242.tmp").exists());
        assert!(
            dir.path().join("vol-data.img").exists(),
            "an installed file was swept"
        );
        assert!(
            dir.path().join(".stray").exists(),
            "something not ours was swept"
        );

        // Under a box's lock no writer predates the run: everything staged goes.
        sweep_staging_temps(dir.path(), |_| false);
        assert!(!dir.path().join(&mine).exists());
    }
}
