//! `terra rm` - throw a box away. The recipe is kept unless `--purge`, and
//! `--force` takes the box from a running VM.

use crate::cmd::stop::{StopOutcome, stop_and_wait};
use crate::{resolve, state};
use anyhow::{Context, Result};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

pub fn run(args: &crate::cli::RmArgs, name: Option<&str>, project_dir: &Path) -> Result<ExitCode> {
    let bx = &resolve::resolve_any_box(project_dir, name)?;
    let state_dir = bx.dir();

    anyhow::ensure!(
        state_dir.exists(),
        "no box '{}' in {} to remove - `terra ls` shows what is there",
        bx.name(),
        bx.project_dir().display()
    );

    // `--force` is the exception the lock is for: a wedged VM's box is removed
    // without it, so a boot starting the moment that VM dies races the
    // deletion.
    let _lock = if args.force {
        if bx.holder().holds() {
            eprintln!("terra: {bx} is running - asking it to stop before removing it");

            match stop_and_wait(bx, Duration::from_secs(args.wait)) {
                Ok(
                    StopOutcome::AlreadyStopped
                    | StopOutcome::StoppedGracefully
                    | StopOutcome::Killed,
                ) => {}
                Ok(StopOutcome::Wedged) => {
                    eprintln!("terra: {bx} survived SIGKILL - removing its files anyway");
                }
                // Nothing was killed: the box published no pid to signal, so
                // there is no VM process to take it away from.
                Err(e) => eprintln!("terra: {e:#} - removing it anyway"),
            }
        }
        bx.lock_run().ok()
    } else {
        Some(bx.lock_run()?)
    };

    let mut kept_recipe = false;
    for entry in
        std::fs::read_dir(state_dir).with_context(|| format!("reading {}", state_dir.display()))?
    {
        let path = entry
            .with_context(|| format!("reading {}", state_dir.display()))?
            .path();
        if path == bx.pid_file() {
            continue;
        }
        if !args.purge && path.file_name().is_some_and(|n| n == state::RECIPE_FILE) {
            kept_recipe = true;
            continue;
        }
        let removed = if path.is_dir() {
            std::fs::remove_dir_all(&path)
        } else {
            std::fs::remove_file(&path)
        };
        removed.with_context(|| format!("removing {}", path.display()))?;
    }
    if kept_recipe {
        eprintln!("terra: removed {bx} (kept {})", state::RECIPE_FILE);
        return Ok(ExitCode::SUCCESS);
    }
    let _ = std::fs::remove_file(bx.pid_file());
    let _ = std::fs::remove_dir(state_dir);
    eprintln!("terra: removed {}", state_dir.display());
    sweep_project_dir(bx.project_dir());
    Ok(ExitCode::SUCCESS)
}

/// Remove a project's `<box_dir>/<slug>/` once its last box is gone
fn sweep_project_dir(project_dir: &Path) {
    let Ok(project) = state::project_state_dir(project_dir) else {
        return;
    };
    if state::boxes_in(&project).next().is_some() {
        return;
    }
    let _ = std::fs::remove_file(project.join(state::ORIGIN_FILE));
    // Only the label was left, so anything still here is not terra's to take.
    let _ = std::fs::remove_dir(&project);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::BoxRef;

    /// `rm` runs under the box lock, and that lock lives on `terra.pid`'s
    /// *inode* - so unlinking it mid-removal would end the exclusion while the
    /// images are still being deleted, letting a racing `terra <box>` lock a
    /// fresh file and boot onto a box this call is halfway through taking away.
    ///
    /// The two branches differ in what is left to protect: a removal that keeps
    /// the recipe keeps the lock file with it, and one that leaves nothing
    /// behind may unlink it - last, once there is nothing left to race for.
    #[test]
    fn rm_never_unlinks_the_lock_out_from_under_itself() {
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::sys::TestHome::new();
        let bx = BoxRef::resolve(dir.path(), "dev").unwrap();
        let build = || {
            std::fs::create_dir_all(bx.dir()).unwrap();
            std::fs::write(bx.recipe(), "hw:\n  cpus: 1\n").unwrap();
            std::fs::write(bx.rootfs_img(), b"image").unwrap();
            std::fs::write(bx.log(), b"output").unwrap();
        };

        let rm = |purge| crate::cli::RmArgs {
            purge,
            force: false,
            wait: 30,
        };
        build();
        run(&rm(false), Some("dev"), dir.path()).unwrap();
        assert!(bx.recipe().exists(), "the recipe should have been kept");
        assert!(!bx.rootfs_img().exists(), "the image should be gone");
        assert!(!bx.log().exists(), "the log should be gone");
        assert!(
            bx.pid_file().exists(),
            "the lock file was unlinked while the box still had a recipe to protect"
        );

        build();
        run(&rm(true), Some("dev"), dir.path()).unwrap();
        assert!(!bx.dir().exists(), "--purge should leave nothing at all");
    }

    /// A box name with nothing on disk behind it is a typo far more often than
    /// it is an idempotent second `rm`, and `terra rm dve` used to print a line
    /// about a box nobody has and exit 0 - so a cleanup step in CI passed while
    /// the box it was aimed at stayed exactly where it was.
    #[test]
    fn removing_a_box_that_was_never_there_fails_rather_than_reporting_success() {
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::sys::TestHome::new();
        let bx = BoxRef::resolve(dir.path(), "dev").unwrap();
        let rm = crate::cli::RmArgs {
            purge: true,
            force: false,
            wait: 30,
        };

        let err = run(&rm, Some("dve"), dir.path())
            .expect_err("a box that was never set up must not report a successful removal")
            .to_string();
        assert!(err.contains("no box 'dve'"), "{err}");
        assert!(err.contains("terra ls"), "the way to look: {err}");

        // A box with state - even one whose setup died before pinning a recipe,
        // which is what `resolve_any_box` is lenient for - is still removed.
        std::fs::create_dir_all(bx.dir()).unwrap();
        std::fs::write(bx.rootfs_img(), b"image").unwrap();
        run(&rm, Some("dev"), dir.path()).unwrap();
        assert!(!bx.dir().exists());
    }
}
