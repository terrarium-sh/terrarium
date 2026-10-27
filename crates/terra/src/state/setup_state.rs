//! How far a box's setup got, and the state `terra ls` reports for it.
use super::{BoxRef, Holder, RECIPE_FILE, ROOTFS_FILE};
use anyhow::{Context, Result};
use sha2::{Digest as _, Sha256};

pub(crate) const SETUP_STAMP: &str = "setup-finished";

/// How far a box's setup got. A non-empty setup stamp means the root image
/// finished a bake; its contents are the digest of the pin it is set up for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoxSetupState {
    Missing,
    /// The bake never finished; setup replaces the root.
    Unbaked,
    /// Baked, but set up for another pin; setup keeps the root.
    Stale,
    SetUp,
}

/// Whether a box has a guest filesystem, and whether a terra is holding it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
#[value(rename_all = "snake_case")]
pub enum BoxState {
    Running,
    SettingUp,
    Stopped,
    /// A root image exists, but setup did not finish for the pinned recipe.
    NeedsSetup,
    NotCreated,
    /// State remains, but the project directory is gone.
    Gone,
}

impl std::fmt::Display for BoxState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `pad`, not `write_str`: only `pad` honors the width the listing
        // asks for.
        f.pad(match self {
            BoxState::Running => "running",
            BoxState::SettingUp => "setting_up",
            BoxState::Stopped => "stopped",
            BoxState::NeedsSetup => "needs_setup",
            BoxState::NotCreated => "not_created",
            BoxState::Gone => "gone",
        })
    }
}

impl BoxRef {
    pub fn get_setup_state(&self) -> Result<BoxSetupState> {
        if !self.dir.join(ROOTFS_FILE).exists() {
            return Ok(BoxSetupState::Missing);
        }
        let stamp = match std::fs::read(self.dir.join(SETUP_STAMP)) {
            Ok(stamp) if !stamp.is_empty() => stamp,
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                return Err(error).with_context(|| format!("reading {SETUP_STAMP}"));
            }
            _ => return Ok(BoxSetupState::Unbaked),
        };
        let pin = std::fs::read(self.dir.join(RECIPE_FILE)).unwrap_or_default();
        Ok(if stamp == Sha256::digest(pin).as_slice() {
            BoxSetupState::SetUp
        } else {
            BoxSetupState::Stale
        })
    }

    /// An unreadable stamp reads as not set up, so a boot is refused.
    pub fn is_set_up(&self) -> bool {
        matches!(self.get_setup_state(), Ok(BoxSetupState::SetUp))
    }

    pub fn write_setup_stamp(&self) -> Result<()> {
        use std::io::Write as _;

        let recipe_path = self.dir.join(RECIPE_FILE);
        let recipe = std::fs::read(&recipe_path)
            .with_context(|| format!("reading {}", recipe_path.display()))?;
        let digest = Sha256::digest(recipe);
        let stamp = self.dir.join(SETUP_STAMP);
        crate::vm::image::staged_write(&stamp, |out| {
            out.write_all(&digest)
                .with_context(|| format!("recording {}", stamp.display()))
        })
    }

    pub fn remove_setup_stamp(&self) -> Result<()> {
        let stamp = self.dir.join(SETUP_STAMP);
        match std::fs::remove_file(&stamp) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                Err(error).with_context(|| format!("removing {}", stamp.display()))
            }
            _ => Ok(()),
        }
    }

    pub fn get_state(&self) -> Result<BoxState> {
        Ok(match self.get_holder()? {
            Holder::Running => BoxState::Running,
            Holder::SettingUp => BoxState::SettingUp,
            // "Stopped" would invite booting a box whose project directory is gone.
            Holder::Free if !self.project_dir.is_dir() => BoxState::Gone,
            Holder::Free => match self.get_setup_state()? {
                BoxSetupState::SetUp => BoxState::Stopped,
                BoxSetupState::Unbaked | BoxSetupState::Stale => BoxState::NeedsSetup,
                BoxSetupState::Missing => BoxState::NotCreated,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::RECIPE_FILE;
    use crate::state::{resolve_box_ref, wait_until_free};
    use crate::sys::TestHome;
    use std::assert_matches;

    /// Every state is one word. `terra ls --tsv` is read by scripts that split
    /// on whitespace, where a state spelled `not created` shifts every field
    /// after it - and the human listing shares this spelling, so neither can
    /// drift from what the other promises.
    #[test]
    fn every_box_state_is_a_single_word() {
        use clap::ValueEnum as _;
        for state in BoxState::value_variants() {
            let word = state.to_string();
            assert_ne!(word, "");
            assert!(
                !word.chars().any(char::is_whitespace),
                "{word:?} is not a single word"
            );
        }
    }

    #[test]
    fn box_state_serializes_to_snake_case() {
        assert_eq!(
            serde_json::to_string(&BoxState::Running).unwrap(),
            "\"running\""
        );
        assert_eq!(
            serde_json::to_string(&BoxState::SettingUp).unwrap(),
            "\"setting_up\""
        );
        assert_eq!(
            serde_json::to_string(&BoxState::Stopped).unwrap(),
            "\"stopped\""
        );
        assert_eq!(
            serde_json::to_string(&BoxState::NotCreated).unwrap(),
            "\"not_created\""
        );
        assert_eq!(
            serde_json::to_string(&BoxState::NeedsSetup).unwrap(),
            "\"needs_setup\""
        );
        assert_eq!(serde_json::to_string(&BoxState::Gone).unwrap(), "\"gone\"");
    }

    /// A missing or empty stamp is an unfinished bake, which setup replaces; a
    /// stamp for another pin is a baked root, which setup keeps.
    #[test]
    fn the_setup_state_reads_the_image_and_its_stamp() {
        let _home = TestHome::new();
        let dir = tempfile::tempdir().unwrap();
        let b = resolve_box_ref(dir.path());
        std::fs::create_dir_all(b.get_dir()).unwrap();
        let stamp = b.get_dir().join(SETUP_STAMP);

        assert_matches!(b.get_setup_state().unwrap(), BoxSetupState::Missing);
        std::fs::write(b.get_dir().join(ROOTFS_FILE), b"image").unwrap();
        assert_matches!(b.get_setup_state().unwrap(), BoxSetupState::Unbaked);
        std::fs::write(&stamp, b"").unwrap();
        assert_matches!(b.get_setup_state().unwrap(), BoxSetupState::Unbaked);
        std::fs::write(b.get_dir().join(RECIPE_FILE), "{}").unwrap();
        b.write_setup_stamp().unwrap();
        assert_matches!(b.get_setup_state().unwrap(), BoxSetupState::SetUp);
        std::fs::write(b.get_dir().join(RECIPE_FILE), "hw: {cpus: 2}\n").unwrap();
        assert_matches!(b.get_setup_state().unwrap(), BoxSetupState::Stale);
        std::fs::remove_file(&stamp).unwrap();
        std::fs::create_dir(&stamp).unwrap();
        assert!(
            b.get_setup_state().is_err(),
            "an unreadable stamp read as unbaked"
        );
        assert!(!b.is_set_up());
    }

    /// Every state a caller can meet is one of [`Holder`]'s, and only a box
    /// nobody holds falls through to what is on disk. `terra ls` reported a box
    /// mid-`terra setup` as plain `running`, which reads as a box there is
    /// something to talk to in.
    #[test]
    fn a_box_being_set_up_is_its_own_state_not_running() {
        let _home = TestHome::new();
        let dir = tempfile::tempdir().unwrap();
        let b = resolve_box_ref(dir.path());
        std::fs::create_dir_all(b.get_dir()).unwrap();

        assert_matches!(b.get_state().unwrap(), BoxState::NotCreated);
        std::fs::write(b.get_dir().join(ROOTFS_FILE), b"image").unwrap();
        // An image setup's VM never finished is not a box a boot accepts.
        assert_matches!(b.get_state().unwrap(), BoxState::NeedsSetup);
        std::fs::write(b.get_dir().join(RECIPE_FILE), "{}").unwrap();
        b.write_setup_stamp().unwrap();
        assert_matches!(b.get_state().unwrap(), BoxState::Stopped);

        let lock = b.lock_run().unwrap();
        assert_matches!(b.get_state().unwrap(), BoxState::Running);
        let marked = BoxRef::mark_setting_up(&lock).unwrap();
        assert_matches!(b.get_state().unwrap(), BoxState::SettingUp);
        assert_eq!(b.get_state().unwrap().to_string(), "setting_up");
        drop(marked);
        drop(lock);

        // A working tree that is gone outranks the filesystem still being there.
        drop(dir);
        wait_until_free(&b);
        assert_matches!(
            b.get_state().unwrap(),
            BoxState::Gone,
            "state was {} (holder {:?})",
            b.get_state().unwrap(),
            b.get_holder().unwrap()
        );
    }
}
