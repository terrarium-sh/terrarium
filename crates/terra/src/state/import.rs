//! An import's crash-safe swap of a box's files: staged, journaled, then committed or undone.

use super::{BoxRef, PINNED_PATHS_FILE, RECIPE_FILE};
use crate::vm::image;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::path::{Path, PathBuf};

const IMPORT_JOURNAL: &str = ".import-journal";

/// A file an import stages, and the box file it replaces on commit.
pub(crate) struct StagedImportFile {
    pub(crate) live: PathBuf,
    pub(crate) stage: PathBuf,
}

#[derive(Deserialize, Serialize)]
struct ImportJournal {
    staging: String,
    entries: Vec<ImportEntry>,
    committed: bool,
}

#[derive(Deserialize, Serialize)]
struct ImportEntry {
    file: String,
    existed: bool,
}

impl BoxRef {
    /// Reserve an import's staging directory, journaled before anything is staged
    /// so the next lock undoes an import that dies part-way.
    pub(crate) fn begin_import(&self) -> Result<PathBuf> {
        let (staging_dir, staging_name) =
            crate::sys::reserve_staging_directory(self.get_dir(), "import")?;
        write_import_journal(
            &self.get_dir().join(IMPORT_JOURNAL),
            &ImportJournal {
                staging: staging_name,
                entries: Vec::new(),
                committed: false,
            },
        )?;
        Ok(staging_dir)
    }

    pub(crate) fn commit_import(&self, staged: &[StagedImportFile]) -> Result<()> {
        let staging = staged
            .first()
            .and_then(|file| file.stage.parent())
            .context("import has no staged files")?;
        let staging_name = staging
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| name.starts_with(".import."))
            .context("import staging directory has an invalid name")?
            .to_owned();
        let journal = self.get_dir().join(IMPORT_JOURNAL);
        let entries = staged
            .iter()
            .map(|file| {
                let existed = match std::fs::symlink_metadata(&file.live) {
                    Ok(metadata) => !metadata.is_dir(),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
                    Err(error) => {
                        return Err(error)
                            .with_context(|| format!("reading {}", file.live.display()));
                    }
                };
                let name = file
                    .live
                    .file_name()
                    .and_then(|name| name.to_str())
                    .context("staged file has no name")?;
                Ok(ImportEntry {
                    file: name.to_owned(),
                    existed,
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
            for (index, file) in staged.iter().enumerate() {
                let backup = file.stage.with_file_name(format!("original-{index}"));
                let original = match std::fs::symlink_metadata(&file.live) {
                    Ok(metadata) => {
                        anyhow::ensure!(
                            !metadata.is_dir(),
                            "{} is a directory",
                            file.live.display()
                        );
                        std::fs::rename(&file.live, &backup)
                            .with_context(|| format!("backing up {}", file.live.display()))?;
                        Some(backup)
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                    Err(error) => {
                        return Err(error)
                            .with_context(|| format!("reading {}", file.live.display()));
                    }
                };
                committed.push((&file.live, original));
                std::fs::rename(&file.stage, &file.live)
                    .with_context(|| format!("restoring {}", file.live.display()))?;
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
        self.recover_import()
    }

    pub(crate) fn recover_import(&self) -> Result<()> {
        let journal = self.get_dir().join(IMPORT_JOURNAL);
        let record: ImportJournal = match File::open(&journal) {
            Ok(file) => serde_json::from_reader(file).context("reading import recovery journal")?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(error).with_context(|| format!("reading {}", journal.display()));
            }
        };
        anyhow::ensure!(
            record.staging.starts_with(".import.") && !record.staging.contains(['/', '\\']),
            "import recovery journal has an invalid staging directory"
        );
        let staging = self.get_dir().join(&record.staging);
        if record.committed {
            if record.entries.iter().any(|entry| entry.file == RECIPE_FILE) {
                self.write_setup_stamp()?;
                #[cfg(unix)]
                File::open(self.get_dir())?.sync_all()?;
            }
        } else {
            for (index, entry) in record.entries.iter().enumerate() {
                let path = self
                    .find_journaled_file(&entry.file)
                    .context("import recovery journal names an invalid file")?;
                let backup = staging.join(format!("original-{index}"));
                let has_backup = match std::fs::symlink_metadata(&backup) {
                    Ok(_) => true,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
                    Err(error) => {
                        return Err(error).with_context(|| format!("reading {}", backup.display()));
                    }
                };
                if entry.existed && has_backup {
                    remove_file_if_present(&path)?;
                    std::fs::rename(&backup, &path)?;
                } else if !entry.existed && !staging.join(&entry.file).exists() {
                    remove_file_if_present(&path)?;
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

    /// The box file a journal entry names: an image, or the pin an import carries.
    fn find_journaled_file(&self, name: &str) -> Option<PathBuf> {
        match name {
            RECIPE_FILE | PINNED_PATHS_FILE => Some(self.get_dir().join(name)),
            _ => self.find_image_named(name),
        }
    }
}

fn write_import_journal(path: &Path, record: &ImportJournal) -> Result<()> {
    image::staged_write(path, |file| Ok(serde_json::to_writer(file, record)?))
        .with_context(|| format!("recording {}", path.display()))
}

fn remove_file_if_present(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
            Err(error).with_context(|| format!("removing {}", path.display()))
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest as _, Sha256};

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
            StagedImportFile {
                live: rootfs.clone(),
                stage: new_rootfs,
            },
            StagedImportFile {
                live: volume.clone(),
                stage: staging.join("missing-volume"),
            },
        ];
        let bx = BoxRef::from_state_dir(dir.path().to_owned(), dir.path());
        assert!(bx.commit_import(&staged).is_err());
        assert_eq!(std::fs::read(&rootfs).unwrap(), b"old rootfs");
        assert_eq!(std::fs::read(&volume).unwrap(), b"old volume");
        assert_eq!(std::fs::read_dir(staging).unwrap().count(), 0);
    }

    /// Only an import that carries the recipe re-stamps the box, and the stamp
    /// is for that recipe: the root it brings is baked for it.
    #[test]
    fn a_committed_import_stamps_the_box_for_the_carried_recipe() {
        for (name, is_set_up) in [(RECIPE_FILE, true), ("vol-data.img", false)] {
            let dir = tempfile::tempdir().unwrap();
            let bx = BoxRef::from_state_dir(dir.path().to_owned(), dir.path());
            std::fs::write(dir.path().join(crate::state::ROOTFS_FILE), b"root").unwrap();
            std::fs::write(bx.get_dir().join(crate::state::SETUP_STAMP), [1u8; 32]).unwrap();
            let staging = dir.path().join(".import.test");
            std::fs::create_dir(&staging).unwrap();
            let stage = staging.join(name);
            std::fs::write(&stage, b"new").unwrap();
            bx.commit_import(&[StagedImportFile {
                live: dir.path().join(name),
                stage,
            }])
            .unwrap();
            assert_eq!(bx.is_set_up(), is_set_up, "{name}");
        }
    }

    #[test]
    fn failed_stamp_write_keeps_the_committed_journal_for_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let bx = BoxRef::from_state_dir(dir.path().to_owned(), dir.path());
        let stamp = bx.get_dir().join(crate::state::SETUP_STAMP);
        std::fs::create_dir(&stamp).unwrap();
        let staging = dir.path().join(".import.test");
        std::fs::create_dir(&staging).unwrap();
        let stage = staging.join(RECIPE_FILE);
        std::fs::write(&stage, b"new").unwrap();
        let recipe = dir.path().join(RECIPE_FILE);
        std::fs::write(&recipe, b"old").unwrap();
        assert!(
            bx.commit_import(&[StagedImportFile {
                live: recipe.clone(),
                stage
            }])
            .is_err()
        );
        assert!(dir.path().join(IMPORT_JOURNAL).exists());
        assert!(bx.recover_import().is_err());
        std::fs::remove_dir(&stamp).unwrap();
        bx.recover_import().unwrap();
        assert_eq!(std::fs::read(recipe).unwrap(), b"new");
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
        bx.commit_import(&[StagedImportFile {
            live: path.clone(),
            stage,
        }])
        .unwrap();
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
                        file: "rootfs.img".into(),
                        existed: true,
                    }],
                    committed: false,
                },
            )
            .unwrap();
            bx.recover_import().unwrap();
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
        bx.recover_import().unwrap();
        assert!(!staging.exists());
        assert_eq!(
            std::fs::read(dir.path().join("rootfs.img")).unwrap(),
            b"original"
        );
    }

    #[test]
    fn storage_recovery_restores_a_partial_multi_image_commit() {
        for mutations in 0..=7 {
            for committed in [false, true] {
                if committed && mutations != 7 {
                    continue;
                }
                let dir = tempfile::tempdir().unwrap();
                let bx = BoxRef::from_state_dir(dir.path().to_owned(), dir.path());
                let staging = dir.path().join(".import.test");
                std::fs::create_dir(&staging).unwrap();
                let names = [RECIPE_FILE, "rootfs.img", "vol-data.img", "vol-new.img"];
                let stamp = bx.get_dir().join(crate::state::SETUP_STAMP);
                std::fs::write(&stamp, b"").unwrap();
                for (index, name) in names.iter().enumerate() {
                    if index < 3 {
                        std::fs::write(dir.path().join(name), b"old").unwrap();
                    }
                    std::fs::write(staging.join(name), b"new").unwrap();
                }
                let mut operations = 0;
                for (index, name) in names.iter().enumerate() {
                    if index < 3 {
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
                                file: (*name).into(),
                                existed: index < 3,
                            })
                            .collect(),
                        committed,
                    },
                )
                .unwrap();
                let lock = bx.lock_run().unwrap();
                bx.recover_import().unwrap();
                assert_eq!(
                    std::fs::read(&stamp).unwrap(),
                    if committed {
                        Sha256::digest(b"new").to_vec()
                    } else {
                        Vec::new()
                    }
                );
                for (index, name) in names.iter().enumerate() {
                    if committed || index < 3 {
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
}
