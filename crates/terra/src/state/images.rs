//! A box's disk images: the root filesystem and its volumes.
use super::BoxRef;
use anyhow::{Context, Result};
use std::path::PathBuf;

pub(crate) const ROOTFS_FILE: &str = "rootfs.img";

const VOLUME_PREFIX: &str = "vol-";

const VOLUME_SUFFIX: &str = ".img";

impl BoxRef {
    /// The root image and the volume images that exist, root first.
    pub(crate) fn list_images(&self) -> Result<Vec<PathBuf>> {
        let mut volumes = self.list_volume_images()?;
        volumes.sort();
        Ok(std::iter::once(self.get_dir().join(ROOTFS_FILE))
            .chain(volumes)
            .filter(|p| p.exists())
            .collect())
    }

    #[must_use]
    pub fn get_volume_image_path(&self, name: &str) -> PathBuf {
        self.dir
            .join(format!("{VOLUME_PREFIX}{name}{VOLUME_SUFFIX}"))
    }

    /// Every volume image the box has, whatever its recipe names.
    pub fn list_volume_images(&self) -> Result<Vec<PathBuf>> {
        let entries = match std::fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => {
                return Err(error).with_context(|| format!("reading {}", self.dir.display()));
            }
        }
        .collect::<std::io::Result<Vec<_>>>()
        .with_context(|| format!("reading {}", self.dir.display()))?;
        Ok(entries
            .into_iter()
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with(VOLUME_PREFIX) && n.ends_with(VOLUME_SUFFIX))
                    && path.is_file()
            })
            .collect::<Vec<_>>())
    }

    pub fn list_unused_volume_images(&self, recipe_volumes: &[String]) -> Result<Vec<PathBuf>> {
        let images = self.list_volume_images()?;
        // see case_only_volume_rename_keeps_the_existing_image
        let kept: Vec<&PathBuf> = recipe_volumes
            .iter()
            .filter_map(|name| {
                let image = self.get_volume_image_path(name);
                images.iter().find(|path| **path == image).or_else(|| {
                    images
                        .iter()
                        .find(|path| path.as_os_str().eq_ignore_ascii_case(&image))
                })
            })
            .collect();
        Ok(images
            .iter()
            .filter(|path| !kept.contains(path))
            .cloned()
            .collect())
    }

    /// The image `name` addresses in this box, or `None` for a name that is
    /// not one terra puts there.
    pub fn find_image_named(&self, name: &str) -> Option<PathBuf> {
        if name == ROOTFS_FILE {
            return Some(self.dir.join(ROOTFS_FILE));
        }
        let volume = name
            .strip_prefix(VOLUME_PREFIX)?
            .strip_suffix(VOLUME_SUFFIX)?;
        let plain =
            !volume.is_empty() && !matches!(volume, "." | "..") && !volume.contains(['/', '\\']);
        plain.then(|| self.get_volume_image_path(volume))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::resolve_box_ref;
    use crate::state::{LOG_FILE, PID_FILE, RECIPE_FILE};
    use crate::sys::TestHome;

    /// The names in a storage artifact were written on another machine, so an
    /// image is addressed by matching what this box would have called one of
    /// its own - a name that could leave the box's directory answers `None`
    /// rather than a path outside it.
    #[test]
    fn only_a_name_this_box_would_have_given_an_image_addresses_one() {
        let _home = TestHome::new();
        let dir = tempfile::tempdir().unwrap();
        let b = resolve_box_ref(dir.path());

        assert_eq!(
            b.find_image_named(ROOTFS_FILE),
            Some(b.get_dir().join(ROOTFS_FILE))
        );
        assert_eq!(
            b.find_image_named("vol-data.img"),
            Some(b.get_volume_image_path("data"))
        );
        for outside in [
            "../../.ssh/authorized_keys",
            "/etc/passwd",
            "vol-../../evil.img",
            "vol-..img",
            "vol-.img",
            "vol-/evil.img",
            RECIPE_FILE,
            PID_FILE,
            "",
        ] {
            assert_eq!(
                b.find_image_named(outside),
                None,
                "{outside} addressed a file"
            );
        }
        // …and whatever it does answer is inside the box, by construction.
        for name in [ROOTFS_FILE, "vol-data.img", "vol-x.y.img"] {
            let path = b.find_image_named(name).unwrap();
            assert_eq!(
                path.parent(),
                Some(b.get_dir()),
                "{name} escaped the state dir"
            );
        }
    }

    /// A renamed or dropped volume leaves its image behind, and this walk is
    /// what finds them: only `vol-*.img` answers - everything else in the
    /// state directory is the box itself - and never an image the recipe
    /// still names. What to *do* with one is the caller's question
    /// (`setup::tests` pins that a boot keeps them and only `--rebuild`
    /// sweeps).
    #[test]
    fn list_unused_volume_images_dropped_by_the_recipe() {
        let _home = TestHome::new();
        let dir = tempfile::tempdir().unwrap();
        let b = resolve_box_ref(dir.path());
        assert!(
            b.list_unused_volume_images(&[]).unwrap().is_empty(),
            "a box with no state dir has nothing to list"
        );
        std::fs::create_dir_all(b.get_dir()).unwrap();
        for name in ["data", "cache", "old"] {
            std::fs::write(b.get_volume_image_path(name), b"image").unwrap();
        }
        std::fs::create_dir(b.get_volume_image_path("directory")).unwrap();
        std::fs::write(b.get_dir().join(ROOTFS_FILE), b"rootfs").unwrap();
        std::fs::write(b.get_dir().join(RECIPE_FILE), "hw:\n  cpus: 1\n").unwrap();
        let log = b.get_dir().join(LOG_FILE);
        std::fs::create_dir_all(log.parent().unwrap()).unwrap();
        std::fs::write(log, b"output").unwrap();

        let mut unused = b.list_unused_volume_images(&["data".to_string()]).unwrap();
        unused.sort();
        assert_eq!(
            unused,
            vec![
                b.get_volume_image_path("cache"),
                b.get_volume_image_path("old")
            ]
        );

        // With no volumes in the recipe every image is unused - and still nothing
        // but a volume image is listed.
        let mut all = b.list_unused_volume_images(&[]).unwrap();
        all.sort();
        assert_eq!(
            all,
            vec![
                b.get_volume_image_path("cache"),
                b.get_volume_image_path("data"),
                b.get_volume_image_path("old")
            ]
        );
    }

    /// Volume names are case-insensitive, so renaming `Data` to `data` keeps using `vol-Data.img`
    /// on macOS and Windows file systems. Listing that image as unused would let `storage prune`
    /// delete a live volume. Once a separate exact-case image exists (a case-sensitive file
    /// system), the old spelling is unused again and prunable.
    #[test]
    fn case_only_volume_rename_keeps_the_existing_image() {
        let _home = TestHome::new();
        let dir = tempfile::tempdir().unwrap();
        let b = resolve_box_ref(dir.path());
        std::fs::create_dir_all(b.get_dir()).unwrap();
        std::fs::write(b.get_volume_image_path("Data"), b"image").unwrap();
        let recipe_volumes = ["data".to_string()];
        assert_eq!(
            b.list_unused_volume_images(&recipe_volumes).unwrap(),
            Vec::<PathBuf>::new()
        );

        std::fs::write(b.get_volume_image_path("data"), b"image").unwrap();
        if b.list_volume_images().unwrap().len() == 2 {
            assert_eq!(
                b.list_unused_volume_images(&recipe_volumes).unwrap(),
                vec![b.get_volume_image_path("Data")]
            );
        }
    }
}
