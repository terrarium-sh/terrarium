//! `terra rm` - throw a box away. The recipe is kept unless `--purge`, and
//! `--force` takes the box from a running VM.

use crate::cmd::stop::{SetupAction, StopOutcome, stop_and_wait};
use crate::state::BoxRef;
use crate::{resolve, state};
use anyhow::{Context, Result};
use std::fs::File;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

pub fn run(args: &crate::cli::RmArgs, name: Option<&str>, project_dir: &Path) -> Result<ExitCode> {
    let bx = &resolve::resolve(name, project_dir, None, resolve::Existence::MayBeMissing)?.bx;
    let state_dir = bx.get_dir();

    anyhow::ensure!(
        state_dir.exists(),
        "no box '{}' in {} to remove - `terra ls` shows what is there",
        bx.get_name(),
        bx.get_project_dir().display()
    );

    // A wedged VM's holder never releases the lock, so `--force` alone removes
    // without it - accepting the race against whatever boots once the wedge ends.
    let _lock = if args.force {
        let stopped = if bx.get_holder().holds() {
            eprintln!("terra: {bx} is running - asking it to stop before removing it");
            stop_and_wait(bx, Duration::from_secs(args.wait), SetupAction::Stop)
        } else {
            Ok(StopOutcome::AlreadyStopped)
        };
        lock_after_stop(bx, stopped)?
    } else {
        Some(bx.lock_run()?)
    };

    let kept_recipe = !args.purge && state_dir.join(state::RECIPE_FILE).exists();
    let entries = std::fs::read_dir(state_dir)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    let (removed_dir, _) = crate::sys::reserve_staging_directory(state_dir, "removing")?;
    let paths = entries
        .into_iter()
        .filter(|path| {
            path != &state_dir.join(state::PID_FILE)
                && !(kept_recipe
                    && (path == &state_dir.join(state::RECIPE_FILE)
                        || path == &state_dir.join(state::PINNED_PATHS_FILE)))
        })
        .collect::<Vec<_>>();
    stage_removal(&paths, &removed_dir)?;
    std::fs::remove_dir_all(&removed_dir).with_context(|| {
        format!(
            "box contents removed; cleaning up {}",
            removed_dir.display()
        )
    })?;
    if kept_recipe {
        eprintln!("terra: removed {bx} (kept {})", state::RECIPE_FILE);
        return Ok(ExitCode::SUCCESS);
    }
    std::fs::remove_file(state_dir.join(state::PID_FILE))?;
    std::fs::remove_dir(state_dir)?;
    eprintln!("terra: removed {}", state_dir.display());
    sweep_project_dir(bx.get_project_dir());
    Ok(ExitCode::SUCCESS)
}

fn stage_removal(paths: &[std::path::PathBuf], removed_dir: &Path) -> Result<()> {
    let mut staged: Vec<(&Path, std::path::PathBuf)> = Vec::new();
    for path in paths {
        let removed = removed_dir.join(path.file_name().context("entry has no file name")?);
        if let Err(error) = std::fs::rename(path, &removed) {
            for (path, removed) in staged.into_iter().rev() {
                std::fs::rename(&removed, path).with_context(|| {
                    format!(
                        "removal failed: {error}; rollback failed: restore {} from {}",
                        path.display(),
                        removed.display()
                    )
                })?;
            }
            let _ = std::fs::remove_dir(removed_dir);
            return Err(error).with_context(|| format!("staging removal of {}", path.display()));
        }
        staged.push((path, removed));
    }
    Ok(())
}

fn lock_after_stop(bx: &BoxRef, stopped: Result<StopOutcome>) -> Result<Option<File>> {
    match stopped? {
        StopOutcome::Wedged => {
            eprintln!("terra: {bx} survived SIGKILL - removing its files anyway");
            Ok(None)
        }
        StopOutcome::AlreadyStopped | StopOutcome::StoppedGracefully | StopOutcome::Killed => bx
            .lock_run()
            .map(Some)
            .with_context(|| format!("another terra took {bx} as it stopped - nothing removed")),
        StopOutcome::IdentityUnknown => anyhow::bail!(
            "{bx} is still held but its VM process identity is unknown - nothing removed"
        ),
    }
}

/// Remove a project's `<box_dir>/<slug>/` once its last box is gone
fn sweep_project_dir(project_dir: &Path) {
    let Ok(project) = state::get_project_state_dir(project_dir) else {
        return;
    };
    match state::list_boxes_in(&project) {
        Ok(boxes) if boxes.is_empty() => {}
        Ok(_) | Err(_) => return,
    }
    let _ = std::fs::remove_file(project.join(state::ORIGIN_FILE));
    // Only the label was left, so anything still here is not terra's to take.
    let _ = std::fs::remove_dir(&project);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::BoxRef;

    #[test]
    fn removal_retries_a_stale_staging_directory() {
        let _home = crate::sys::TestHome::new();
        let project = tempfile::tempdir().unwrap();
        let bx = BoxRef::resolve(project.path(), "dev").unwrap();
        std::fs::create_dir_all(bx.get_dir()).unwrap();
        std::fs::write(bx.get_dir().join(state::RECIPE_FILE), "hw: {}\n").unwrap();
        let stale = bx
            .get_dir()
            .join(format!(".removing.{}.0", std::process::id()));
        std::fs::create_dir(&stale).unwrap();
        std::fs::write(stale.join("old"), "leftover").unwrap();
        run(
            &crate::cli::RmArgs {
                purge: false,
                force: false,
                wait: 0,
            },
            Some("dev"),
            project.path(),
        )
        .unwrap();
        assert!(!stale.exists());
        assert!(bx.get_dir().join(state::RECIPE_FILE).exists());
    }

    #[test]
    fn a_late_staging_failure_restores_every_removed_entry() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("rootfs.img");
        let removed = dir.path().join("removed");
        std::fs::write(&image, b"image").unwrap();
        std::fs::create_dir(&removed).unwrap();
        assert!(stage_removal(&[image.clone(), dir.path().join("missing")], &removed).is_err());
        assert_eq!(std::fs::read(image).unwrap(), b"image");
        assert!(!removed.exists());
    }

    /// The race the lock exists for, from force's side: a stop that landed
    /// cleanly hands the box back, and a rival terra booting it in between is
    /// refused with its images intact - not deleted under it. `--force` then
    /// only ever deletes over a VM that survived SIGKILL.
    #[test]
    fn a_box_another_took_as_it_stopped_is_not_removed() {
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::sys::TestHome::new();
        let bx = BoxRef::resolve(dir.path(), "dev").unwrap();
        std::fs::create_dir_all(bx.get_dir()).unwrap();
        std::fs::write(bx.get_dir().join(state::ROOTFS_FILE), b"image").unwrap();

        // The winner of the race: holding the box when rm comes to collect.
        let _rival = bx.lock_run().unwrap();
        let err = format!(
            "{:#}",
            lock_after_stop(&bx, Ok(StopOutcome::StoppedGracefully))
                .expect_err("a box another terra holds must not be taken for removal")
        );
        assert!(err.contains("another terra took"), "{err}");
        assert!(err.contains("as it stopped"), "{err}");
        assert!(
            bx.get_dir().join(state::ROOTFS_FILE).exists(),
            "the image was deleted anyway"
        );

        // A wedge is the one outcome that removes without the lock.
        assert!(
            lock_after_stop(&bx, Ok(StopOutcome::Wedged))
                .unwrap()
                .is_none(),
            "a wedged VM never hands the lock back"
        );

        // A stop that found nothing to signal refuses too, naming itself.
        let err = lock_after_stop(&bx, Err(anyhow::anyhow!("published no pid to signal")))
            .expect_err("an unanswered stop must not read as permission to remove")
            .to_string();
        assert!(err.contains("published no pid"), "{err}");
        assert!(bx.get_dir().join(state::ROOTFS_FILE).exists());
    }

    /// `rm --force` against a held box whose holder never published a pid
    /// refuses outright: there is no VM process to take the box away from, and
    /// deleting whatever is on disk would be guessing at whose data it is.
    #[test]
    fn force_against_a_holder_that_published_no_pid_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::sys::TestHome::new();
        let bx = BoxRef::resolve(dir.path(), "dev").unwrap();
        std::fs::create_dir_all(bx.get_dir()).unwrap();
        std::fs::write(bx.get_dir().join(state::ROOTFS_FILE), b"image").unwrap();
        let _held = bx.lock_run().unwrap();
        assert_eq!(bx.read_vm_process(), None);

        let args = crate::cli::RmArgs {
            purge: true,
            force: true,
            wait: 0,
        };
        let err = run(&args, Some("dev"), dir.path())
            .expect_err("nothing was signalled, so nothing may be removed")
            .to_string();
        assert!(err.contains("published no pid"), "{err}");
        assert!(
            bx.get_dir().join(state::ROOTFS_FILE).exists(),
            "the image was deleted anyway"
        );
    }

    #[test]
    fn force_does_not_remove_a_box_with_an_unverified_pid() {
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::sys::TestHome::new();
        let bx = BoxRef::resolve(dir.path(), "dev").unwrap();
        std::fs::create_dir_all(bx.get_dir()).unwrap();
        std::fs::write(bx.get_dir().join(state::ROOTFS_FILE), b"image").unwrap();
        let lock = bx.lock_run().unwrap();
        let mut command = crate::sys::build_test_child_command();
        let inheritance = crate::sys::pass_lock(&mut command, &lock).unwrap();
        let mut child = command.spawn().unwrap();
        drop(inheritance);
        std::fs::write(bx.get_dir().join(state::PID_FILE), child.id().to_string()).unwrap();
        drop(lock);

        let error = run(
            &crate::cli::RmArgs {
                purge: true,
                force: true,
                wait: 0,
            },
            Some("dev"),
            dir.path(),
        )
        .expect_err("an unverified pid must not allow removal")
        .to_string();
        assert!(error.contains("identity is unknown"), "{error}");
        assert!(bx.get_dir().join(state::ROOTFS_FILE).exists());
        assert!(child.try_wait().unwrap().is_none());
        child.kill().unwrap();
        child.wait().unwrap();
    }

    /// A bake-marked box aborts `--force` as well - mid-bake deletion is what
    /// `--rebuild` is for, and the mark says the box's own setup still owns it.
    #[test]
    fn force_never_deletes_mid_bake() {
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::sys::TestHome::new();
        let bx = BoxRef::resolve(dir.path(), "dev").unwrap();
        std::fs::create_dir_all(bx.get_dir()).unwrap();
        std::fs::write(bx.get_dir().join(state::ROOTFS_FILE), b"image").unwrap();
        let lock = bx.lock_run().unwrap();
        let marked = bx.mark_baking(&lock);

        let args = crate::cli::RmArgs {
            purge: true,
            force: true,
            wait: 0,
        };
        let err = run(&args, Some("dev"), dir.path())
            .expect_err("a box mid-bake must not be removed")
            .to_string();
        assert!(err.contains("being set up"), "{err}");
        assert!(
            bx.get_dir().join(state::ROOTFS_FILE).exists(),
            "the image was deleted mid-bake"
        );
        drop(marked);
    }

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
            std::fs::create_dir_all(bx.get_dir()).unwrap();
            std::fs::write(bx.get_dir().join(state::RECIPE_FILE), "hw:\n  cpus: 1\n").unwrap();
            std::fs::write(bx.get_dir().join(state::ROOTFS_FILE), b"image").unwrap();
            std::fs::write(bx.get_dir().join(state::LOG_FILE), b"output").unwrap();
        };

        let rm = |purge| crate::cli::RmArgs {
            purge,
            force: false,
            wait: 30,
        };
        build();
        run(&rm(false), Some("dev"), dir.path()).unwrap();
        assert!(
            bx.get_dir().join(state::RECIPE_FILE).exists(),
            "the recipe should have been kept"
        );
        assert!(
            !bx.get_dir().join(state::ROOTFS_FILE).exists(),
            "the image should be gone"
        );
        assert!(
            !bx.get_dir().join(state::LOG_FILE).exists(),
            "the log should be gone"
        );
        assert!(
            bx.get_dir().join(state::PID_FILE).exists(),
            "the lock file was unlinked while the box still had a recipe to protect"
        );

        build();
        run(&rm(true), Some("dev"), dir.path()).unwrap();
        assert!(
            !bx.get_dir().exists(),
            "--purge should leave nothing at all"
        );
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
        // which is what lenient resolution is for - is still removed.
        std::fs::create_dir_all(bx.get_dir()).unwrap();
        std::fs::write(bx.get_dir().join(state::ROOTFS_FILE), b"image").unwrap();
        run(&rm, Some("dev"), dir.path()).unwrap();
        assert!(!bx.get_dir().exists());
    }
}
