//! How far a box's setup got, and the state `terra ls` reports for it.
use super::{BoxRef, Holder, RECIPE_FILE, ROOTFS_FILE};
use crate::recipe::{Components, Hooks, Hw, Mount, Network, Recipe, Workload};
use anyhow::{Context, Result};
use sha2::{Digest as _, Sha256};
use std::path::PathBuf;

pub(crate) const SETUP_STAMP: &str = "setup-finished";

/// A field written with the value it has when left out (`cpus: 2`) digests
/// like one left out, and comments or layout do not count; text that is not a
/// recipe digests as its own bytes.
pub(crate) fn digest_parsed_recipe(text: &str) -> Vec<u8> {
    digest_recipe(text, |_| {})
}

/// [`digest_parsed_recipe`] of only what a setup boot reads: the digest a
/// baked root is stamped with.
#[must_use]
pub fn digest_setup_boot_inputs(text: &str) -> Vec<u8> {
    digest_recipe(text, clear_run_only_fields)
}

/// Reset what does not shape the root filesystem, so changing it keeps the baked root.
/// `hw.cpus` and `hw.mem_mib` stay because `on_create` can read them, network
/// rules stay because `on_create` runs under them, and volumes stay whole
/// because `on_create` writes into them.
fn clear_run_only_fields(recipe: &mut Recipe) {
    let Recipe {
        hw,
        components,
        mounts,
        volumes: _,
        network,
        hooks,
        daemons,
        workload,
        sudo,
        env: _,
        env_file: _,
    } = recipe;
    let Hw {
        cpus: _,
        mem_mib: _,
        rootfs_mib: _,
        rootfs_readonly,
    } = hw;
    let Network {
        enabled: _,
        mode: _,
        allow: _,
        hosts: _,
        ports,
    } = network;
    for mount in mounts {
        // The setup boot makes each share's mount point but mounts no share.
        let Mount {
            host,
            guest: _,
            readonly,
        } = mount;
        *host = PathBuf::new();
        *readonly = false;
    }
    *rootfs_readonly = false;
    *components = Components::default();
    ports.clear();
    sudo.clear();
    let Hooks {
        on_create: _,
        on_start,
        pre_stop,
    } = hooks;
    let Workload { run, workdir: _ } = workload;
    *run = None;
    on_start.clear();
    pre_stop.clear();
    daemons.clear();
}

fn digest_recipe(text: &str, prepare: fn(&mut Recipe)) -> Vec<u8> {
    let canonical = yaml_serde::from_str::<Recipe>(text)
        .ok()
        .and_then(|mut recipe| {
            prepare(&mut recipe);
            let mut value = serde_json::to_value(recipe).ok()?;
            drop_default_fields(&mut value, &serde_json::to_value(Recipe::default()).ok()?);
            serde_json::to_vec(&value).ok()
        });
    let digest = match canonical {
        Some(canonical) => Sha256::digest(canonical),
        None => Sha256::digest([UNPARSED_TEXT_DOMAIN, text.as_bytes()].concat()),
    };
    digest.to_vec()
}

/// Keeps the digest of text that is not a recipe from equaling a stamp an
/// older terra wrote as the SHA-256 of the raw text, so a box whose applied
/// recipe this terra cannot read reports `needs_setup`, not `stopped`.
const UNPARSED_TEXT_DOMAIN: &[u8] = b"terra:unparsed-recipe\0";

/// Drop every object field equal to its default, so a field a later terra adds
/// does not change the digest of a recipe that never set it.
// ponytail: entries of lists (mounts, volumes) are not pruned; a field added to
// one changes the digest of every recipe that lists it - prune per element type then.
fn drop_default_fields(value: &mut serde_json::Value, default: &serde_json::Value) {
    let (serde_json::Value::Object(fields), serde_json::Value::Object(defaults)) = (value, default)
    else {
        return;
    };
    fields.retain(|key, field| match defaults.get(key) {
        Some(default) if field == default => false,
        Some(default) => {
            drop_default_fields(field, default);
            true
        }
        None => true,
    });
}

/// How far a box's setup got. A non-empty setup stamp means the root image
/// finished a bake; its contents are the digest of the applied recipe it is set up for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoxSetupState {
    Missing,
    /// The bake never finished; setup replaces the root.
    Unbaked,
    /// Baked, but set up for another applied recipe; setup rebuilds the root.
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
    /// A root image exists, but is not set up for the applied recipe.
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

fn is_stamp_for(stamp: &[u8], recipe_text: &str) -> bool {
    stamp == digest_setup_boot_inputs(recipe_text)
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
        Ok(match self.read_applied_recipe_text() {
            Some(applied) if is_stamp_for(&stamp, &applied) => BoxSetupState::SetUp,
            _ => BoxSetupState::Stale,
        })
    }

    /// Whether the root image was baked for what `text` gives a setup boot;
    /// `Ok(false)` also for a root that never finished baking.
    pub(crate) fn is_root_baked_for(&self, text: &str) -> Result<bool> {
        match std::fs::read(self.dir.join(SETUP_STAMP)) {
            Ok(stamp) => Ok(!stamp.is_empty() && is_stamp_for(&stamp, text)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error).with_context(|| format!("reading {SETUP_STAMP}")),
        }
    }

    /// Whether `text` says what the box's applied recipe says.
    pub(crate) fn is_recipe_applied(&self, text: &str) -> bool {
        self.read_applied_recipe_text()
            .is_some_and(|applied| digest_parsed_recipe(text) == digest_parsed_recipe(&applied))
    }

    /// `None` when the applied recipe is missing or unreadable, which matches no stamp.
    fn read_applied_recipe_text(&self) -> Option<String> {
        std::fs::read_to_string(self.dir.join(RECIPE_FILE)).ok()
    }

    /// An unreadable stamp reads as not set up, so a boot is refused.
    pub fn is_set_up(&self) -> bool {
        matches!(self.get_setup_state(), Ok(BoxSetupState::SetUp))
    }

    pub fn write_setup_stamp(&self) -> Result<()> {
        use std::io::Write as _;

        let recipe_path = self.dir.join(RECIPE_FILE);
        let recipe = std::fs::read_to_string(&recipe_path)
            .with_context(|| format!("reading {}", recipe_path.display()))?;
        let digest = digest_setup_boot_inputs(&recipe);
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

    /// The setup boot makes a share's mount point and never mounts the share,
    /// so only the guest path is a setup-boot input; a volume's lifetime is one,
    /// since `on_create` writes into the volume.
    #[test]
    fn only_a_mount_s_guest_path_is_a_setup_boot_input() {
        let work = digest_setup_boot_inputs("mounts: [{host: ./a, guest: /work}]\n");
        assert_eq!(
            work,
            digest_setup_boot_inputs("mounts: [{host: ./b, guest: /work, readonly: true}]\n")
        );
        assert_ne!(
            work,
            digest_setup_boot_inputs("mounts: [{host: ./a, guest: /data}]\n")
        );
        assert_ne!(
            digest_setup_boot_inputs("volumes: [{name: v, guest: /v, size_mib: 8}]\n"),
            digest_setup_boot_inputs(
                "volumes: [{name: v, guest: /v, size_mib: 8, lifetime: boot}]\n"
            )
        );
    }

    /// An applied recipe this terra cannot parse never matches a stamp an older
    /// terra wrote as the SHA-256 of the raw text, so the box reports
    /// `needs_setup` instead of `stopped` while every recipe-reading command fails.
    #[test]
    fn an_unparseable_recipe_does_not_match_a_legacy_raw_text_stamp() {
        let text = "entrypoint: [sh]\n";
        assert!(yaml_serde::from_str::<Recipe>(text).is_err());
        assert_ne!(
            digest_setup_boot_inputs(text),
            Sha256::digest(text.as_bytes()).to_vec()
        );
        assert_eq!(
            digest_setup_boot_inputs(text),
            digest_setup_boot_inputs(text)
        );
    }

    /// A field equal to its default is left out of the digest, at any depth,
    /// so a field a later terra adds with a default does not rebuild old boxes.
    #[test]
    fn default_fields_drop_out_of_the_digest() {
        let mut value = serde_json::json!({"a": 1, "b": {"c": 2, "d": 3}, "e": [1]});
        let default = serde_json::json!({"a": 1, "b": {"c": 2, "d": 0}, "e": []});
        drop_default_fields(&mut value, &default);
        assert_eq!(value, serde_json::json!({"b": {"d": 3}, "e": [1]}));
    }

    /// A missing or empty stamp is an unfinished bake, and a stamp for another
    /// applied recipe is a root baked for that recipe; setup replaces both. A
    /// stamp follows the parsed recipe, not its comments, layout or spelled-out
    /// defaults.
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
        std::fs::write(b.get_dir().join(RECIPE_FILE), "# a comment\n{ }\n").unwrap();
        assert_matches!(b.get_setup_state().unwrap(), BoxSetupState::SetUp);
        std::fs::write(b.get_dir().join(RECIPE_FILE), "hw: {cpus: 5}\n").unwrap();
        assert_matches!(b.get_setup_state().unwrap(), BoxSetupState::Stale);
        assert!(b.is_recipe_applied("# edited\nhw:\n  cpus: 5\n"));
        assert!(!b.is_recipe_applied("hw: {cpus: 3}\n"));
        std::fs::write(b.get_dir().join(RECIPE_FILE), "{}").unwrap();
        let default_cpus = Recipe::default().hw.cpus;
        assert!(b.is_recipe_applied(&format!("hw: {{cpus: {default_cpus}}}\n")));
        b.write_setup_stamp().unwrap();
        std::fs::remove_file(b.get_dir().join(RECIPE_FILE)).unwrap();
        assert_matches!(
            b.get_setup_state().unwrap(),
            BoxSetupState::Stale,
            "a missing applied recipe read as the empty recipe the stamp was baked for"
        );
        assert!(!b.is_recipe_applied("{}"));
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
