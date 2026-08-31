//! `terra [BOX]` - the bare form: what one invocation of it decides, and the
//! doing of it.

use crate::cli::BootArgs;
use crate::cmd::setup;
use crate::resolve;
use crate::session::DETACH_KEY_NAME;
use crate::state::{BoxRef, Holder};
use crate::vm::boot::{self, BootMode};
use anyhow::Result;
use std::path::Path;
use std::process::ExitCode;

pub const EXIT_VM_ALREADY_RUNNING: u8 = 125;

/// What one invocation does about the box it names, decided by [`build_start_plan`].
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(crate) enum StartPlan {
    Boot,
    Attach,
    AlreadyRunning,
    NothingToDo,
}

fn build_start_plan(bx: &BoxRef, args: &BootArgs, is_at_a_terminal: bool) -> Result<StartPlan> {
    match bx.get_holder() {
        Holder::Free => return Ok(StartPlan::Boot),
        Holder::SettingUp => return Err(bx.setup_holds_it()),
        Holder::Running => {}
    }
    if !args.command.is_empty() || args.root {
        let asked = if args.command.is_empty() {
            "as root"
        } else {
            "a command of its own"
        };
        anyhow::bail!(
            "{bx} is already running, so it cannot be started with {asked} - \
             `terra exec {name}{root} -- …` runs one in it, or `terra stop {name}` \
             first to boot it differently",
            name = bx.get_name(),
            root = if args.root { " --root" } else { "" }
        );
    }
    if args.foreground {
        anyhow::bail!(
            "{bx} is already running, so there is no VM to run in this process - \
             `terra stop {name}` first to run it here, or leave --foreground off \
             to attach to the one that is up",
            name = bx.get_name()
        );
    }
    if args.detach {
        return Ok(StartPlan::AlreadyRunning);
    }
    if !is_at_a_terminal {
        return Ok(StartPlan::NothingToDo);
    }
    Ok(StartPlan::Attach)
}

fn choose_boot_mode(args: &BootArgs, is_at_a_terminal: bool) -> Result<BootMode> {
    match (args.detach, args.foreground, is_at_a_terminal) {
        (true, _, _) => Ok(BootMode::Detached),
        (_, true, _) => Ok(BootMode::Foreground),
        (false, false, true) => Ok(BootMode::DetachedWithJoin),
        (false, false, false) => anyhow::bail!(
            "no terminal to join - say which way to run the box: `-d` boots it in \
             the background, `--foreground` runs the VM in this process (for a \
             service manager)"
        ),
    }
}

/// `terra [BOX]` - boot a box, or join it if it is up. A box that is not set up
/// yet is offered one first, from the recipe the manifest names for it or from
/// a recipe path given here; `cwd` is what that path resolves against.
pub fn run(
    name: Option<&str>,
    args: &BootArgs,
    project_dir: &Path,
    cwd: &Path,
    is_at_a_terminal: bool,
) -> Result<ExitCode> {
    let target = resolve::resolve(
        name,
        project_dir,
        Some(cwd),
        resolve::Existence::MayBeMissing,
    )?;

    match build_start_plan(&target.bx, args, is_at_a_terminal)? {
        // One line for both: a script tells them apart by the exit code, not
        // the wording.
        outcome @ (StartPlan::AlreadyRunning | StartPlan::NothingToDo) => {
            eprintln!("terra: {} is already running", target.bx);
            return Ok(if outcome == StartPlan::NothingToDo {
                ExitCode::from(EXIT_VM_ALREADY_RUNNING)
            } else {
                ExitCode::SUCCESS
            });
        }
        StartPlan::Attach => {
            eprintln!(
                "terra: {} is already running - attaching ({} detaches)",
                target.bx, DETACH_KEY_NAME
            );
            return boot::attach(&target.bx);
        }
        StartPlan::Boot => {}
    }

    let approved =
        setup::request_recipe_approval(target, &setup::Approval::Offer, is_at_a_terminal)?;
    let mode = choose_boot_mode(args, is_at_a_terminal)?;
    let prepared = setup::prepare_box(&approved, setup::Rebuild::No)?;
    let project_dir = approved.bx.get_project_dir().to_path_buf();
    let spec = boot::BootSpec::resolve(approved.cfg, args, project_dir, mode);

    if !spec.cfg.hooks.on_create.is_empty()
        && (prepared.fresh_rootfs
            || !approved
                .bx
                .get_dir()
                .join(crate::state::BAKE_STAMP)
                .exists())
    {
        boot::run_bake(&spec.cfg, &approved.bx, &prepared.lock)?;
    }
    boot::start(&spec, &approved.bx, mode, prepared.lock)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::TestHome;
    use clap::Parser;

    /// The flags of a bare invocation, as clap parses them.
    fn build_boot_args(flags: &[&str]) -> BootArgs {
        let argv: Vec<&str> = std::iter::once("terra")
            .chain(flags.iter().copied())
            .collect();
        crate::cli::Cli::parse_from(argv).boot
    }

    /// A box on disk, held by this process when `running`. The home comes
    /// first: it is what makes the box this test's own rather than one in the
    /// developer's real `~/.terra`, and it has to be in place before the box
    /// is resolved.
    fn create_box_in(dir: &Path, running: bool) -> (BoxRef, Option<std::fs::File>, TestHome) {
        let home = TestHome::new();
        let bx = BoxRef::resolve(dir, "dev").unwrap();
        std::fs::create_dir_all(bx.get_dir()).unwrap();
        let lock = running.then(|| bx.lock_run().unwrap());
        (bx, lock, home)
    }

    /// Every mode is asked for. The background VM child is not among them: it
    /// never parses a command line (see [`crate::run`]), which is what keeps a
    /// boot from forking forever. (`-d --foreground` together never reaches
    /// this either: clap refuses the pair, which `cli::tests` pins.)
    #[test]
    fn a_boot_detaches_joins_runs_here_or_asks() {
        // `-d` asked for no terminal, so it never joins - even from one.
        for is_at_a_terminal in [false, true] {
            assert_eq!(
                choose_boot_mode(&build_boot_args(&["-d"]), is_at_a_terminal).unwrap(),
                BootMode::Detached
            );
            // `--foreground` runs the VM in this process, terminal or not.
            assert_eq!(
                choose_boot_mode(&build_boot_args(&["--foreground"]), is_at_a_terminal).unwrap(),
                BootMode::Foreground
            );
        }
        // A terminal start spawns the VM and is only its first client.
        assert_eq!(
            choose_boot_mode(&build_boot_args(&[]), true).unwrap(),
            BootMode::DetachedWithJoin
        );
        // No terminal and neither flag: refused, with both spellings named -
        // guessing "foreground service" here turned scripts into hung VMs.
        let err = choose_boot_mode(&build_boot_args(&[]), false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("-d"), "{err}");
        assert!(err.contains("--foreground"), "{err}");
    }

    /// A box that is down is [`StartPlan::Boot`] whatever the flags say - which way
    /// it runs is [`boot_mode`]'s, and is asked only once a recipe has been
    /// approved (see [`boot_mode`]'s own note).
    #[test]
    fn a_box_that_is_not_up_is_booted_however_it_was_asked_for() {
        let dir = tempfile::tempdir().unwrap();
        let (bx, _lock, _home) = create_box_in(dir.path(), false);
        for flags in [
            &[][..],
            &["-d"],
            &["--foreground"],
            &["--root"],
            &["--", "npm"],
        ] {
            for is_at_a_terminal in [false, true] {
                assert_eq!(
                    build_start_plan(&bx, &build_boot_args(flags), is_at_a_terminal).unwrap(),
                    StartPlan::Boot,
                    "{flags:?} is_at_a_terminal={is_at_a_terminal}"
                );
            }
        }
    }

    /// A bake holds the box's lock but serves no agent port, so "is it
    /// running" is the wrong question for a box being set up: `terra <box>`
    /// used to answer "already running - attaching" and then sit on a socket
    /// nothing would ever bind, until `terra setup` finished and the wait died
    /// with "stopped before it had a session to join". Neither line was true.
    #[test]
    fn a_box_being_baked_is_not_offered_as_a_session_to_join() {
        let dir = tempfile::tempdir().unwrap();
        let (bx, lock, _home) = create_box_in(dir.path(), true);

        let baking = bx.mark_baking(lock.as_ref().unwrap());
        assert_eq!(bx.get_holder(), Holder::SettingUp);
        let err = build_start_plan(&bx, &build_boot_args(&[]), false)
            .expect_err("a box mid-bake must not be offered as a session to join")
            .to_string();
        assert_eq!(err, bx.setup_holds_it().to_string());
        // …and `-d`, which used to answer plain success about a box that is
        // not up: a script cannot tell that from a box it can now use.
        assert!(build_start_plan(&bx, &build_boot_args(&["-d"]), false).is_err());

        // The mark goes with the bake, and what is left is an ordinary held
        // box: with no terminal to attach from, this is the 125 a script reads
        // as "already running".
        drop(baking);
        assert_eq!(bx.get_holder(), Holder::Running);
        assert_eq!(
            build_start_plan(&bx, &build_boot_args(&[]), false).unwrap(),
            StartPlan::NothingToDo
        );
    }

    /// `-- <cmd>`, `--root` and `--foreground` each shape a boot, and a box
    /// that is already up booted without them: attaching anyway used to hand
    /// back a session running the recipe's workload as `terri` while the
    /// command typed on the line was dropped without a word.
    ///
    /// `--foreground` is the same drop by a different route - it asks for the
    /// VM in *this* process, and attaching joins one running elsewhere. It went
    /// unrefused after the other two were fixed, which is why it is pinned
    /// beside them rather than in a test of its own.
    #[test]
    fn boot_flags_are_refused_rather_than_dropped_on_a_running_box() {
        let dir = tempfile::tempdir().unwrap();
        let (bx, _lock, _home) = create_box_in(dir.path(), true);
        let refused = |flags: &[&str], is_at_a_terminal| {
            build_start_plan(&bx, &build_boot_args(flags), is_at_a_terminal)
                .expect_err("a boot flag was dropped on a running box")
                .to_string()
        };

        let err = refused(&["--", "npm", "test"], false);
        assert!(err.contains("a command of its own"), "{err}");
        assert!(
            err.contains("terra exec dev -- …"),
            "the way to do it: {err}"
        );

        // Same for `--root`, where the surprise is worse: a session that
        // silently is not the root one that was asked for.
        let err = refused(&["--root"], false);
        assert!(err.contains("as root"), "{err}");
        assert!(err.contains("terra exec dev --root"), "{err}");

        // `--foreground` is refused from either side of the terminal question:
        // off one it used to be the 125 an already-running box answers, and at
        // one it was dropped and the session attached instead.
        for is_at_a_terminal in [false, true] {
            let err = refused(&["--foreground"], is_at_a_terminal);
            assert!(err.contains("no VM to run in this process"), "{err}");
            assert!(err.contains("terra stop dev"), "the way to do it: {err}");
        }

        // …and `-d`, which shapes nothing about the workload, is not refused:
        // it asked for a box running in the background, and there is one. Its
        // plain success is what tells it apart from the 125 off a terminal.
        assert_eq!(
            build_start_plan(&bx, &build_boot_args(&["-d"]), false).unwrap(),
            StartPlan::AlreadyRunning
        );
        // A terminal with no flags is the one case that joins.
        assert_eq!(
            build_start_plan(&bx, &build_boot_args(&[]), true).unwrap(),
            StartPlan::Attach
        );
    }
}
