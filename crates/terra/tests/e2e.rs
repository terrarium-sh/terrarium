//! End-to-end tests: run the compiled `terra` binary and assert on stdout,
//! stderr, and exit codes. Only paths that fail before a VM boot are exercised,
//! so no KVM or rootfs download is needed; booting is covered by the boot suite
//! by `tests/boot.rs` (`cargo test --test boot -- --ignored`, needs /dev/kvm).

// Integration tests are their own crate and cannot inherit the crate roots'
// `#![cfg_attr(test, ...)]` opt-out, so it is spelled out here.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::{Command, Output};

/// Run terra from wherever the test process is, for cases that address a box by
/// `--project` and never touch `~/.terra`.
fn run_terra_command(args: &[&str]) -> Output {
    run_terra(None, &[], args)
}

/// Run with an isolated home so the user's real `~/.terra` never takes part.
fn run_terra_in(dir: &std::path::Path, home: &std::path::Path, args: &[&str]) -> Output {
    run_terra(
        Some(dir),
        &[
            ("HOME", home.as_os_str()),
            ("USERPROFILE", home.as_os_str()),
        ],
        args,
    )
}

/// The state directory of the one box under `~/.terra/box` - the layout is
/// `box/<hashed project>/<box name>/`, and each test gets its own empty home,
/// so "the one" is well defined.
fn find_only_box(home: &std::path::Path) -> std::path::PathBuf {
    let dirs = |p: &std::path::Path| -> Vec<std::path::PathBuf> {
        std::fs::read_dir(p)
            .expect("no ~/.terra/box")
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_dir())
            .collect()
    };
    let projects = dirs(&home.join(".terra/box"));
    assert_eq!(projects.len(), 1, "expected one project: {projects:?}");
    let mut boxes = dirs(&projects[0]);
    assert_eq!(boxes.len(), 1, "expected one box: {boxes:?}");
    boxes.pop().unwrap()
}

/// The path terra reports for a project directory: the child resolves its cwd
/// through macOS's `/var` symlink, while Windows keeps the spelling it was
/// handed (and `canonicalize` would add a `\\?\` prefix there).
fn project_path(dir: &std::path::Path) -> std::path::PathBuf {
    #[cfg(unix)]
    {
        std::fs::canonicalize(dir).unwrap()
    }
    #[cfg(not(unix))]
    {
        dir.to_path_buf()
    }
}

fn run_terra(
    dir: Option<&std::path::Path>,
    env: &[(&str, &std::ffi::OsStr)],
    args: &[&str],
) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_terra"));
    cmd.args(args);
    if let Some(dir) = dir {
        cmd.current_dir(dir);
    }
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().expect("failed to run terra binary")
}

#[test]
fn help_lists_the_lifecycle_verbs() {
    let out = run_terra_command(&["--help"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Launch isolated microVMs"));
    for sub in [
        "setup", "put", "get", "exec", "stop", "rm", "show", "ls", "logs",
    ] {
        assert!(stdout.contains(sub), "help missing subcommand {sub}");
    }
    // Using a box has no verb at all - `terra [BOX]` covers start and attach,
    // because which one a person wants is a fact about the box.
    for gone in ["  start ", "  attach ", "  run ", "  create "] {
        assert!(
            !stdout.contains(gone),
            "{gone:?} is still a subcommand: {stdout}"
        );
    }
    assert!(stdout.contains("[BOX]"), "{stdout}");
    // …and its flags are on the top-level help, since the bare form is it.
    assert!(stdout.contains("--project"));
    assert!(stdout.contains("--detach"));
}

#[test]
fn setup_pins_a_recipe_and_the_box_then_answers_from_it() {
    let dir = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();

    std::fs::write(dir.path().join("b.yaml"), "hw:\n  cpus: 1\n").unwrap();
    let first = run_terra_in(dir.path(), home.path(), &["./b.yaml", "setup"]);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    // The box takes the file's stem for its name, and its files go under
    // ~/.terra/box, not into the directory it is a box of.
    let state = find_only_box(home.path());
    assert_eq!(state.file_name().unwrap(), "b");
    let recipe = state.join("recipe.yaml");
    assert!(recipe.exists(), "setup left no recipe");
    assert!(
        !dir.path().join(".box").exists(),
        "a new box put files in the directory it is a box of"
    );

    // A box is self-contained: addressed by a name that resolves to no source,
    // it re-checks against its own pinned recipe rather than erroring - so an
    // edit made to that copy is what answers.
    let marker = "env:\n  KEPT_BY_THE_BOX: \"1\"\n";
    std::fs::write(&recipe, marker).unwrap();
    let second = run_terra_in(dir.path(), home.path(), &["b", "setup"]);
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert_eq!(std::fs::read_to_string(&recipe).unwrap(), marker);
}

/// `terra start` boots the recipe the box was set up from; only `terra setup`
/// reads a source at all. So editing a recipe file changes nothing until a setup
/// names it again - at which point it says what it replaced.
#[test]
fn setup_adopts_recipe_edits_and_start_does_not() {
    let dir = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let other = dir.path().join("other.yaml");
    std::fs::write(&other, "hw:\n  cpus: 3\n").unwrap();

    let made = run_terra_in(dir.path(), home.path(), &["./other.yaml", "setup"]);
    assert!(
        made.status.success(),
        "{}",
        String::from_utf8_lossy(&made.stderr)
    );
    // The box is named after the file's stem.
    let state = find_only_box(home.path());
    assert_eq!(state.file_name().unwrap(), "other");

    // The source changes; the pinned copy does not, and `show` (which answers
    // for `start`) still sees the old value.
    std::fs::write(&other, "hw:\n  cpus: 5\n").unwrap();
    let shown = run_terra_in(dir.path(), home.path(), &["other", "show"]);
    assert!(
        String::from_utf8_lossy(&shown.stdout).contains("cpus: 3"),
        "start/show should answer from the pinned copy"
    );

    // `setup` is the adopt step, and says so.
    let adopted = run_terra_in(dir.path(), home.path(), &["./other.yaml", "setup"]);
    assert!(adopted.status.success());
    assert!(String::from_utf8_lossy(&adopted.stderr).contains("recipe updated"));
    let recipe = std::fs::read_to_string(state.join("recipe.yaml")).unwrap();
    assert!(recipe.contains("cpus: 5"));

    let again = run_terra_in(dir.path(), home.path(), &["./other.yaml", "setup"]);
    assert!(again.status.success());
    assert!(!String::from_utf8_lossy(&again.stderr).contains("recipe updated"));
}

/// The point of keeping a box's files in `~/.terra/box`: a box may share the
/// directory it is a box of - recipe included. That recipe - the most ordinary
/// one there is - used to be refused outright.
///
/// The counterpart: once such a box exists, its recipe file sits in a share its
/// guest could write, so *pinning* an edit is a question rather than a default.
/// `start` never reads it, so the guest still chooses nothing.
#[test]
fn a_box_can_share_the_directory_it_is_a_box_of() {
    let dir = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let recipe = dir.path().join("sandbox.yaml");
    std::fs::write(&recipe, "mounts:\n  - host: .\n    guest: /work\n").unwrap();

    let out = run_terra_in(dir.path(), home.path(), &["./sandbox.yaml", "setup"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !dir.path().join(".box").exists(),
        "the box left files in the tree it shares"
    );

    // …and it says where its files went, since they are not beside it.
    let listed = run_terra_in(dir.path(), home.path(), &["ls"]);
    let stdout = String::from_utf8_lossy(&listed.stdout);
    assert!(
        stdout.contains(&format!("files: {}", find_only_box(home.path()).display())),
        "{stdout}"
    );

    // An "edit" lands in the file - exactly what a guest of this box could have
    // done through the share. There is no terminal in a test, so the question
    // that would be asked becomes a refusal, and it shows what it refused to
    // pin: the name of a recipe file is exactly what nobody can judge it by.
    std::fs::write(
        &recipe,
        "mounts:\n  - host: .\n    guest: /work\nhw:\n  cpus: 4\nnetwork:\n  mode: unrestricted-public\n",
    )
    .unwrap();
    let refused = run_terra_in(dir.path(), home.path(), &["./sandbox.yaml", "setup"]);
    assert_eq!(refused.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(stderr.contains("may be the author"), "{stderr}");
    assert!(stderr.contains("--trust-recipe"), "{stderr}");
    // The policy, not just the filename - this is the half that makes an
    // approval mean something.
    assert!(
        stderr.contains("egress:") && stderr.contains("unrestricted"),
        "{stderr}"
    );
    assert!(
        stderr.contains("mount:") && stderr.contains("/work"),
        "{stderr}"
    );

    // `--rebuild` rebuilds the filesystem and says nothing about trust: it must
    // NOT be a way past this. The two were one flag once, which meant accepting
    // your own edit cost you the box - a price people learn to route around.
    let forced = run_terra_in(
        dir.path(),
        home.path(),
        &["./sandbox.yaml", "setup", "--rebuild"],
    );
    assert_eq!(
        forced.status.code(),
        Some(1),
        "--rebuild must not double as --trust-recipe"
    );

    // …and --trust-recipe pins it, out loud, without touching the filesystem.
    let trusted = run_terra_in(
        dir.path(),
        home.path(),
        &["./sandbox.yaml", "setup", "--trust-recipe"],
    );
    assert!(
        trusted.status.success(),
        "{}",
        String::from_utf8_lossy(&trusted.stderr)
    );
    let said = String::from_utf8_lossy(&trusted.stderr);
    assert!(said.contains("shares read-write"), "{said}");
    assert!(said.contains("may be the author"), "{said}");
}

/// The gap this CLI split closed. A guest with a read-write share of the project
/// can write both `terra.yaml` and the recipe it points at, naming a box that
/// does not exist yet. That box has no previous recipe of its own, so asking
/// only about *its* history asked nothing at all - and the old `terra run <name>`
/// pinned a guest-authored policy and booted it.
///
/// Now the sibling box that granted the share answers for it, and `start` cannot
/// pin anything at all.
#[test]
fn a_recipe_a_sibling_box_could_have_written_is_not_pinned_silently() {
    let dir = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();

    // A box that shares its own project directory read-write - the layout the
    // starter recipe recommends arriving at.
    std::fs::write(
        dir.path().join("dev.yaml"),
        "mounts:\n  - host: .\n    guest: /work\n",
    )
    .unwrap();
    let dev = run_terra_in(dir.path(), home.path(), &["./dev.yaml", "setup"]);
    assert!(
        dev.status.success(),
        "{}",
        String::from_utf8_lossy(&dev.stderr)
    );

    // What its guest could now write through /work: a manifest entry naming a
    // second box, and the recipe behind it.
    std::fs::create_dir_all(home.path().join(".ssh")).unwrap();
    std::fs::write(
        dir.path().join("terra.yaml"),
        "boxes:\n  test: ./test.yaml\n",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("test.yaml"),
        format!(
            "mounts:\n  - host: {}\n    guest: /keys\nnetwork:\n  mode: unrestricted-public\n",
            home.path().join(".ssh").display()
        ),
    )
    .unwrap();

    // `terra test` must not pin it. There is no terminal here, so there is
    // nobody to offer a setup to - and a script never pins a policy.
    let started = run_terra_in(dir.path(), home.path(), &["test"]);
    assert_eq!(started.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&started.stderr);
    assert!(stderr.contains("would build it"), "{stderr}");
    assert!(stderr.contains("no terminal"), "{stderr}");

    // …and `terra setup test`, which does read it, asks first - here, with no
    // terminal, refuses - naming the share that could have authored it and what
    // the recipe would grant.
    let setup = run_terra_in(dir.path(), home.path(), &["test", "setup"]);
    assert_eq!(setup.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&setup.stderr);
    assert!(stderr.contains("may be the author"), "{stderr}");
    assert!(
        stderr.contains(".ssh"),
        "the mount it would grant: {stderr}"
    );
    assert!(stderr.contains("unrestricted"), "{stderr}");
    assert!(stderr.contains("--trust-recipe"), "{stderr}");

    // Nothing was pinned: the box does not exist.
    assert!(
        !home
            .path()
            .join(".terra/box")
            .read_dir()
            .unwrap()
            .flatten()
            .any(|p| p.path().join("test").exists()),
        "a refused recipe was pinned anyway"
    );
}

/// One directory, several boxes: each is addressed by name, a bare command
/// refuses to guess between them, and `ls` shows them all.
#[test]
fn a_directory_can_hold_several_named_boxes() {
    let dir = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("dev.yaml"), "hw:\n  cpus: 1\n").unwrap();
    std::fs::write(dir.path().join("ci.yaml"), "hw:\n  cpus: 2\n").unwrap();

    for r in ["./dev.yaml", "./ci.yaml"] {
        let out = run_terra_in(dir.path(), home.path(), &[r, "setup"]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    // A bare command cannot mean both.
    let ambiguous = run_terra_in(dir.path(), home.path(), &["stop"]);
    assert_eq!(ambiguous.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&ambiguous.stderr);
    assert!(stderr.contains("several boxes"), "{stderr}");
    assert!(stderr.contains("ci") && stderr.contains("dev"), "{stderr}");

    // A named one addresses exactly that box.
    let stop = run_terra_in(dir.path(), home.path(), &["ci", "stop"]);
    assert!(stop.status.success());
    assert!(String::from_utf8_lossy(&stop.stderr).contains("already stopped"));

    // A bare `ls` lists them rather than refusing, and names them by name:
    // the directory is the one thing they have in common.
    let listed = run_terra_in(dir.path(), home.path(), &["ls"]);
    let stdout = String::from_utf8_lossy(&listed.stdout);
    assert!(stdout.contains("dev") && stdout.contains("ci"), "{stdout}");

    // `--all` spans directories, so there each line carries its own.
    let everywhere = run_terra_in(dir.path(), home.path(), &["ls", "--all"]);
    let stdout = String::from_utf8_lossy(&everywhere.stdout);
    assert!(
        stdout.contains("(dev)") && stdout.contains("(ci)"),
        "{stdout}"
    );
    // `ls` takes no box names - it lists; the per-box question is `show`'s.
    assert_eq!(
        run_terra_in(dir.path(), home.path(), &["ls", "--all", "dev"])
            .status
            .code(),
        Some(2)
    );
}

/// `terra.yaml` maps the project's box names to recipes - references only, so a
/// guest that can write it (it lives in the tree boxes share) can at worst
/// repoint a name at another recipe file, and pinning one of those is gated at
/// `terra setup` - see `a_recipe_a_sibling_box_could_have_written_is_not_pinned_silently`.
#[test]
fn the_manifest_names_the_projects_boxes() {
    let dir = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("dev-recipe.yaml"), "hw:\n  cpus: 3\n").unwrap();
    std::fs::write(dir.path().join("ci-recipe.yaml"), "hw:\n  cpus: 2\n").unwrap();
    std::fs::write(
        dir.path().join("terra.yaml"),
        "boxes:\n  dev: ./dev-recipe.yaml\n  ci: ./ci-recipe.yaml\n",
    )
    .unwrap();

    // With several declared and none set up, the bare form names them rather
    // than guessing - without reading any of them.
    let bare = run_terra_in(dir.path(), home.path(), &[]);
    assert_eq!(bare.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&bare.stderr);
    assert!(stderr.contains("none is set up yet"), "{stderr}");
    assert!(stderr.contains("dev") && stderr.contains("ci"), "{stderr}");

    // A manifest name resolves through its reference and names the box.
    let made = run_terra_in(dir.path(), home.path(), &["dev", "setup"]);
    assert!(
        made.status.success(),
        "{}",
        String::from_utf8_lossy(&made.stderr)
    );
    let state = find_only_box(home.path());
    assert_eq!(state.file_name().unwrap(), "dev");
    let pinned = std::fs::read_to_string(state.join("recipe.yaml")).unwrap();
    assert!(pinned.contains("cpus: 3"), "{pinned}");

    // A bare word in neither the manifest nor on disk: a recipe is only ever
    // named by path, and the error says so.
    let missing = run_terra_in(dir.path(), home.path(), &["nope", "setup"]);
    assert_eq!(missing.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&missing.stderr);
    assert!(stderr.contains("no recipe for 'nope'"), "{stderr}");
    assert!(stderr.contains("./nope.yaml"), "{stderr}");

    // A manifest entry pointing nowhere blames the manifest, not the argument.
    std::fs::write(
        dir.path().join("terra.yaml"),
        "boxes:\n  dev: ./gone.yaml\n",
    )
    .unwrap();
    let dangling = run_terra_in(dir.path(), home.path(), &["dev", "setup", "--rebuild"]);
    assert_eq!(dangling.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&dangling.stderr);
    assert!(stderr.contains("terra.yaml"), "{stderr}");
}

/// `terra ls --all` answers "what boxes are on this machine, and which are up" -
/// which only has an answer at all because every box's state is in one
/// directory. The project directories are named by a hash, so the listing reads
/// the `path` file each records rather than the names on disk.
#[test]
fn ls_all_lists_boxes_by_the_directory_they_belong_to() {
    let home = tempfile::tempdir().unwrap();
    let one = tempfile::tempdir().unwrap();
    let two = tempfile::tempdir().unwrap();
    let one_dir = project_path(one.path());
    let two_dir = project_path(two.path());

    // On stderr: the listing is what a caller redirects, and this is a hint
    // about there being none rather than a line of it.
    let empty = run_terra_in(one.path(), home.path(), &["ls", "--all"]);
    assert!(
        String::from_utf8_lossy(&empty.stderr).contains("no boxes on this machine"),
        "{}",
        String::from_utf8_lossy(&empty.stderr)
    );
    assert!(empty.stdout.is_empty(), "the listing itself is empty");

    // An explicit recipe, so each box is actually built: a bare `terra setup`
    // in an empty directory scaffolds a starter and stops, leaving nothing to
    // call "stopped".
    for d in [one.path(), two.path()] {
        std::fs::write(d.join("b.yaml"), "hw:\n  cpus: 1\n").unwrap();
        let out = run_terra_in(d, home.path(), &["./b.yaml", "setup"]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let out = run_terra_in(one.path(), home.path(), &["ls", "--all"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    for dir in [&one_dir, &two_dir] {
        assert!(
            stdout.contains(&format!("{} (b)", dir.display())),
            "{stdout}"
        );
    }
    // Set up but never booted: `terra setup` with no `on_create` never starts
    // a VM, so there is a filesystem and nothing holding the lock.
    assert_eq!(stdout.matches("stopped").count(), 2, "{stdout}");

    // A box outlives the directory it was made for, and says so rather than
    // being quietly dropped from the listing - it still owns a filesystem.
    let gone = two_dir.clone();
    two.close().unwrap();
    let out = run_terra_in(one.path(), home.path(), &["ps", "--all"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(&format!("gone         {} (b)", gone.display())),
        "{stdout}"
    );

    // `rm --purge` on the last box of a directory clears its project entry
    // too: nothing left for `ls` to list forever.
    let removed = run_terra_in(one.path(), home.path(), &["rm", "--purge"]);
    assert!(removed.status.success());
    let out = run_terra_in(one.path(), home.path(), &["ls", "--all"]);
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains(&one_dir.display().to_string()),
        "rm --purge left the project listed"
    );
}

/// `terra exec` talks to the live agent, so a box that is not up has nothing to
/// run the command on - and it must say so rather than dialling a socket that
/// is not there. (What exec does on a *running* box is the boot suite's job.)
#[test]
fn exec_on_a_box_that_is_not_running_says_so() {
    let dir = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("dev.yaml"), "hw:\n  cpus: 1\n").unwrap();
    assert!(
        run_terra_in(dir.path(), home.path(), &["./dev.yaml", "setup"])
            .status
            .success()
    );

    let out = run_terra_in(dir.path(), home.path(), &["dev", "exec", "--", "id", "-u"]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("is not running"), "{stderr}");

    // …and `--root` reaches the same check rather than a different path.
    let rooted = run_terra_in(
        dir.path(),
        home.path(),
        &["dev", "exec", "--root", "--", "id", "-u"],
    );
    assert_eq!(rooted.status.code(), Some(1));

    // A command is required: with nothing after `--` there is nothing to run.
    assert_eq!(
        run_terra_in(dir.path(), home.path(), &["dev", "exec"])
            .status
            .code(),
        Some(2),
        "clap should refuse an exec with no command"
    );
}

/// A mistake in the *command line* exits 2, as every clap usage error does -
/// never 1, which is what a box that ran and failed exits with. Both halves
/// used to disagree: clap's own refusals exited 2 while the two `Cli::validate`
/// raises came back as ordinary errors and exited 1, so a script could not tell
/// "you typed this wrong" from "the workload failed".
///
/// Pinned here rather than in `cli::tests`, because the exit code is the part
/// no unit test sees: `validate` hands back a `Result` either way, and what
/// turned it into a status was the call site.
#[test]
fn a_command_line_terra_refuses_exits_as_a_usage_error() {
    let dir = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    for args in [
        // The boot flags shape a boot, and a verb is not one.
        &["dev", "-d", "stop"][..],
        &["dev", "--foreground", "logs"][..],
        &["--root", "exec", "--", "ls"][..],
        // `ls` asks about the directory, so it takes no box before it.
        &["dev", "ls"][..],
        // …and clap's own, which this must not have drifted away from.
        &["--no-such-flag"][..],
        &["ls", "--all", "dev"][..],
    ] {
        let out = run_terra_in(dir.path(), home.path(), args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
    }

    // The refusals still say what to do instead - an exit code is not an
    // explanation.
    let flagged = run_terra_in(dir.path(), home.path(), &["dev", "-d", "stop"]);
    let stderr = String::from_utf8_lossy(&flagged.stderr);
    assert!(stderr.contains("boot flags"), "{stderr}");
    assert!(
        stderr.contains("terra dev -d"),
        "the way to do it: {stderr}"
    );

    let boxed = run_terra_in(dir.path(), home.path(), &["dev", "ls"]);
    let stderr = String::from_utf8_lossy(&boxed.stderr);
    assert!(stderr.contains("terra ls"), "{stderr}");
}

/// A bare start with no terminal and neither `-d` nor `--foreground` is
/// refused, naming both - it used to silently run the VM in this process,
/// which turned any redirected script into a hung foreground VM. Refused
/// before a VM exists, so no KVM is needed to pin it.
#[test]
fn a_bare_start_without_a_terminal_names_both_ways_to_run() {
    let dir = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("dev.yaml"), "hw:\n  cpus: 1\n").unwrap();
    assert!(
        run_terra_in(dir.path(), home.path(), &["./dev.yaml", "setup"])
            .status
            .success()
    );

    let out = run_terra_in(dir.path(), home.path(), &["dev"]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("-d"), "{stderr}");
    assert!(stderr.contains("--foreground"), "{stderr}");
}

/// A box that was never set up is "no box" to every verb that acts on an
/// existing one - not "nothing is running" or "no log", which answer a question
/// about a box that does not exist and send the user off to boot it.
///
/// `rm` reaches the same answer by its own route: it takes the box as an
/// address whether or not a recipe was ever pinned (a setup that died mid-way
/// leaves state and no recipe), so what it refuses on is having nothing on disk
/// at all. It used to be the one verb that answered a name nobody has with
/// success.
#[test]
fn every_verb_that_needs_a_box_says_when_there_is_none() {
    let dir = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    for args in [
        &["typo", "exec", "--", "ls"][..],
        &["typo", "put", "a.txt", "/a"][..],
        &["typo", "stop"][..],
        &["typo", "logs"][..],
        &["typo", "rm"][..],
    ] {
        let out = run_terra_in(dir.path(), home.path(), args);
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("no box 'typo'"), "{args:?}: {stderr}");
        assert!(!stderr.contains("not running"), "{args:?}: {stderr}");
        assert!(!stderr.contains("no log"), "{args:?}: {stderr}");
    }
}

/// Every message about a box names it - the name somebody gave it *and* the
/// directory it belongs to. One directory can hold several boxes, so "nothing is
/// running in /home/me/project" answered about none of them in particular.
#[test]
fn a_message_about_a_box_names_the_box() {
    let dir = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("dev.yaml"), "hw:\n  cpus: 1\n").unwrap();
    assert!(
        run_terra_in(dir.path(), home.path(), &["./dev.yaml", "setup"])
            .status
            .success()
    );
    let named = format!("dev ({})", project_path(dir.path()).display());
    let stopped = run_terra_in(dir.path(), home.path(), &["dev", "stop"]);
    let stderr = String::from_utf8_lossy(&stopped.stderr);
    assert!(stderr.contains(&named), "{stderr}");
    let exec = run_terra_in(dir.path(), home.path(), &["dev", "exec", "--", "ls"]);
    let stderr = String::from_utf8_lossy(&exec.stderr);
    assert!(stderr.contains(&named), "{stderr}");
}

/// A bare `terra` with nothing set up: no terminal here, so there is nobody to
/// offer a setup to and it must say what to run instead - never pin a recipe on
/// a script's behalf.
#[test]
fn the_bare_form_without_a_recipe_says_how_to_set_one_up() {
    let dir = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let out = run_terra_in(dir.path(), home.path(), &[]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("no box"), "{stderr}");
    assert!(stderr.contains("<box> setup"), "{stderr}");
}

/// Box names and terra's own words share one namespace, because using a box is
/// `terra <box>` - so terra's words are reserved. A recipe whose stem is one
/// is refused before anything is built, instead of making a box the bare form
/// could never address.
#[test]
fn a_terra_word_cannot_name_a_box() {
    let dir = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("logs.yaml"), "hw:\n  cpus: 1\n").unwrap();

    let refused = run_terra_in(dir.path(), home.path(), &["./logs.yaml", "setup"]);
    assert_eq!(refused.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(stderr.contains("cannot name a box"), "{stderr}");

    // The bare `terra logs` is the log viewer, as it always was.
    let shadowed = run_terra_in(dir.path(), home.path(), &["logs"]);
    assert!(!shadowed.status.success());
    let stderr = String::from_utf8_lossy(&shadowed.stderr);
    assert!(stderr.contains("no box"), "{stderr}");

    // …and the names people actually give sandboxes still work.
    std::fs::write(dir.path().join("dev.yaml"), "hw:\n  cpus: 1\n").unwrap();
    let ok = run_terra_in(dir.path(), home.path(), &["./dev.yaml", "setup"]);
    assert!(
        ok.status.success(),
        "{}",
        String::from_utf8_lossy(&ok.stderr)
    );
    assert_eq!(find_only_box(home.path()).file_name().unwrap(), "dev");
}

/// One line per box - its state and its name; the recipe's details are `show`'s
/// job. `running` needs a VM, so the boot suite covers it; the other two states
/// and the empty directory are pinned here.
#[test]
fn ls_reports_a_state_line_per_box() {
    let dir = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let dir_path = project_path(dir.path());

    // No boxes and nothing declared: says so, and is not an error. On stderr,
    // because the listing is what a caller redirects and this is a hint about
    // there being none rather than a line of it.
    let empty = run_terra_in(dir.path(), home.path(), &["ls"]);
    assert!(empty.status.success());
    let stderr = String::from_utf8_lossy(&empty.stderr);
    assert!(stderr.contains("no boxes in"), "{stderr}");
    assert!(stderr.contains(&dir_path.display().to_string()), "{stderr}");
    assert!(empty.stdout.is_empty(), "the listing itself is empty");

    // Declared in the manifest but never set up: listed, as not created -
    // a recipe alone can still boot one, so it is a box worth reporting.
    // No `files:` line: there are no files to point at yet.
    std::fs::write(dir.path().join("terra.yaml"), "boxes:\n  b: ./b.yaml\n").unwrap();
    std::fs::write(dir.path().join("b.yaml"), "hw:\n  cpus: 1\n").unwrap();
    let declared = run_terra_in(dir.path(), home.path(), &["ls"]);
    let stdout = String::from_utf8_lossy(&declared.stdout);
    assert!(stdout.contains("not-created"), "{stdout}");
    assert!(stdout.contains('b'), "{stdout}");
    assert!(!stdout.contains("files:"), "{stdout}");

    // Set up: created, not running.
    let setup = run_terra_in(dir.path(), home.path(), &["b", "setup"]);
    assert!(
        setup.status.success(),
        "{}",
        String::from_utf8_lossy(&setup.stderr)
    );
    let created = run_terra_in(dir.path(), home.path(), &["ls"]);
    let stdout = String::from_utf8_lossy(&created.stdout);
    assert!(stdout.contains("stopped"), "{stdout}");
    assert!(!stdout.contains("not-created"), "{stdout}");
    // A box on disk says where its files are - the state dir's name is a hash,
    // so nothing else can.
    assert!(
        stdout.contains(&format!("files: {}", find_only_box(home.path()).display())),
        "{stdout}"
    );

    // `--tsv` is the format scripts (the boot suite's runner included)
    // may rely on: one tab-separated line per box - state, name, directory,
    // files - and nothing else. The human listing above stays free to change.
    let tsv = run_terra_in(dir.path(), home.path(), &["ls", "--tsv"]);
    assert!(tsv.status.success());
    let stdout = String::from_utf8_lossy(&tsv.stdout);
    assert_eq!(
        stdout.trim_end(),
        format!(
            "stopped\tb\t{}\t{}",
            dir_path.display(),
            find_only_box(home.path()).display()
        ),
        "{stdout}"
    );

    // An empty directory is empty output, not prose a script would trip over.
    let none = tempfile::tempdir().unwrap();
    let empty = run_terra_in(none.path(), home.path(), &["ls", "--tsv"]);
    assert!(empty.status.success());
    assert!(empty.stdout.is_empty(), "{:?}", empty.stdout);
}

/// A recipe *path* names a file to pin, so a missing file is an error - not a
/// silent re-check of whatever recipe happens to be pinned under the same stem.
/// A bare *name* still answers from the box's own pinned recipe: the box is
/// self-contained, and the name stopped resolving to anything else.
#[test]
fn a_missing_recipe_path_is_an_error_even_when_the_box_exists() {
    let dir = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let recipe = dir.path().join("ci.yaml");
    std::fs::write(&recipe, "hw:\n  cpus: 1\n").unwrap();
    let first = run_terra_in(dir.path(), home.path(), &["./ci.yaml", "setup"]);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );

    std::fs::remove_file(&recipe).unwrap();
    let gone = run_terra_in(dir.path(), home.path(), &["./ci.yaml", "setup"]);
    assert_eq!(gone.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&gone.stderr);
    assert!(stderr.contains("not found"), "{stderr}");

    let by_name = run_terra_in(dir.path(), home.path(), &["ci", "setup"]);
    assert!(
        by_name.status.success(),
        "{}",
        String::from_utf8_lossy(&by_name.stderr)
    );
}

/// `show` prints the recipe a boot would run, with `env:` values redacted.
/// Every other path a value takes into a box is deliberately contained - a pipe
/// to the VM process rather than argv, host memory rather than a file - and
/// this output is the one made to be redirected into a file and pasted into a
/// bug report. The names stay: knowing `FOO` is set is the useful half.
#[test]
fn show_prints_the_resolved_recipe_without_env_values() {
    let dir = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("box.yaml");
    std::fs::write(
        &cfg,
        "hw:\n  cpus: 3\n  mem_mib: 256\nenv:\n  FOO: sk-secret\n",
    )
    .unwrap();
    let out = run_terra_in(dir.path(), home.path(), &["./box.yaml", "show"]);
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("cpus: 3"), "{stdout}");
    assert!(
        stdout.contains("FOO"),
        "the name should still be shown: {stdout}"
    );
    assert!(
        !stdout.contains("sk-secret"),
        "the value was printed: {stdout}"
    );

    // …and `--with-env-values` is how you ask for them, on the same recipe.
    let asked_for = run_terra_in(
        dir.path(),
        home.path(),
        &["./box.yaml", "show", "--with-env-values"],
    );
    assert!(asked_for.status.success());
    let stdout = String::from_utf8_lossy(&asked_for.stdout);
    assert!(stdout.contains("FOO: sk-secret"), "{stdout}");
    assert!(
        stdout.contains("cpus: 3"),
        "the rest is unchanged: {stdout}"
    );
}

/// `show` answers for a boot, and a boot reads the *pinned* recipe - so once a
/// box exists, an edit to the file it was set up from is not what `show` prints.
/// It used to re-resolve the name and print the edited source: a report of a
/// boot that was not going to happen.
///
/// A path is the exception, and the way a recipe is read before there is a box.
#[test]
fn show_answers_from_the_pinned_recipe_not_the_source_it_came_from() {
    let dir = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let shared = home.path().join(".terra");
    std::fs::create_dir_all(&shared).unwrap();
    let source = shared.join("dev.yaml");
    std::fs::write(&source, "hw:\n  cpus: 3\n").unwrap();

    let made = run_terra_in(dir.path(), home.path(), &["~/.terra/dev.yaml", "setup"]);
    assert!(
        made.status.success(),
        "{}",
        String::from_utf8_lossy(&made.stderr)
    );
    std::fs::write(&source, "hw:\n  cpus: 4\n").unwrap();

    // By name, and with no name at all - the directory's only box.
    for args in [&["dev", "show"][..], &["show"]] {
        let out = run_terra_in(dir.path(), home.path(), args);
        assert!(
            out.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(stdout.contains("cpus: 3"), "{args:?}: {stdout}");
    }

    // The file itself is still readable as a file.
    let by_path = run_terra_in(dir.path(), home.path(), &["~/.terra/dev.yaml", "show"]);
    assert!(
        String::from_utf8_lossy(&by_path.stdout).contains("cpus: 4"),
        "{}",
        String::from_utf8_lossy(&by_path.stdout)
    );
}

/// A directory whose `terra.yaml` declares exactly one box has one box to
/// address, set up or not - `terra show` with no argument reaches it rather
/// than reporting that no BOX was given.
#[test]
fn a_single_declared_box_is_what_the_directory_means() {
    let dir = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("dev-recipe.yaml"), "hw:\n  cpus: 7\n").unwrap();
    std::fs::write(
        dir.path().join("terra.yaml"),
        "boxes:\n  dev: ./dev-recipe.yaml\n",
    )
    .unwrap();

    let out = run_terra_in(dir.path(), home.path(), &["show"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("cpus: 7"),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
}

/// A box only ever has the name somebody gave it, so a directory with no boxes
/// has nothing to address: every box command says that, rather than answering
/// about a box terra made up a name for. (It used to invent `default`, which
/// made `stop` report on a box that had never existed.)
#[test]
fn a_directory_with_no_boxes_addresses_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    for args in [&["rm"][..], &["stop"], &["logs"], &["exec", "--", "true"]] {
        let out = run_terra_in(dir.path(), home.path(), args);
        assert_eq!(out.status.code(), Some(1), "{args:?}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("no box"), "{args:?}: {stderr}");
        assert!(stderr.contains("<box> setup"), "{args:?}: {stderr}");
    }
}

/// A box that exists but is not up is already in the state a stop asks for, so
/// stopping it succeeds - as `docker stop` does - and a stop-then-rebuild
/// script needs no `|| true`. A box that does not exist at all is still an
/// error (see `every_verb_that_needs_a_box_says_when_there_is_none`).
#[test]
fn stop_of_a_stopped_box_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("b.yaml"), "hw:\n  cpus: 1\n").unwrap();
    run_terra_in(dir.path(), home.path(), &["./b.yaml", "setup"]);
    let out = run_terra_in(dir.path(), home.path(), &["stop"]);
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("already stopped"));
}

#[test]
fn logs_without_a_log_errors() {
    let dir = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("b.yaml"), "hw:\n  cpus: 1\n").unwrap();
    run_terra_in(dir.path(), home.path(), &["./b.yaml", "setup"]);
    let out = run_terra_in(dir.path(), home.path(), &["logs"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("no log"));
}

/// What `terra rm` is idempotent about, and what it is not.
///
/// A plain `rm` keeps the recipe, so the box is still addressable and running
/// it again is a no-op that succeeds. A `--purge` leaves nothing at all, and a
/// name with nothing behind it is indistinguishable from a typo - so the second
/// one is an error. `terra rm dve` reporting success used to make a mistyped
/// cleanup step pass while the box it meant stayed exactly where it was.
#[test]
fn rm_is_repeatable_while_the_box_is_addressable_and_an_error_once_it_is_gone() {
    let dir = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("b.yaml"), "hw:\n  cpus: 1\n").unwrap();
    run_terra_in(dir.path(), home.path(), &["./b.yaml", "setup"]);

    // The recipe is kept, so the box is still there to remove again.
    for _ in 0..2 {
        let out = run_terra_in(dir.path(), home.path(), &["rm"]);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    assert!(
        run_terra_in(dir.path(), home.path(), &["b", "rm", "--purge"])
            .status
            .success()
    );
    // Nothing left to address: the same call again is the typo case.
    let again = run_terra_in(dir.path(), home.path(), &["b", "rm", "--purge"]);
    assert_eq!(again.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&again.stderr);
    assert!(stderr.contains("no box 'b'"), "{stderr}");

    let typo = run_terra_in(dir.path(), home.path(), &["dve", "rm", "--purge"]);
    assert_eq!(typo.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&typo.stderr).contains("no box 'dve'"),
        "{}",
        String::from_utf8_lossy(&typo.stderr)
    );
}

#[test]
fn missing_recipe_reports_the_path_and_exits_one() {
    let dir = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let out = run_terra_in(
        dir.path(),
        home.path(),
        &["./definitely-not-a-recipe-e2e.yaml", "setup"],
    );
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("config not found"), "{stderr}");
    assert!(stderr.contains("definitely-not-a-recipe-e2e"), "{stderr}");
}

#[test]
fn invalid_yaml_reports_parse_error_and_exits_one() {
    let dir = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("bad.yaml");
    std::fs::write(&cfg, "hw: [not, a, mapping]").unwrap();
    let out = run_terra_in(dir.path(), home.path(), &[cfg.to_str().unwrap(), "setup"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("failed to parse YAML"));
}

/// The example recipe shipped at the repo root must be accepted. `terra setup`
/// performs this check without booting a VM, so this needs no KVM.
#[test]
fn the_shipped_example_recipe_is_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let recipe = concat!(env!("CARGO_MANIFEST_DIR"), "/../../pi-dev.yaml");
    let out = run_terra_in(dir.path(), home.path(), &[recipe, "setup"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn missing_mount_host_path_exits_one() {
    let dir = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("cfg.yaml");
    std::fs::write(
        &cfg,
        "mounts:\n  - host: ./nonexistent-e2e-path\n    guest: /work\n",
    )
    .unwrap();
    let out = run_terra_in(dir.path(), home.path(), &[cfg.to_str().unwrap(), "setup"]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("resolving mount host path"), "{stderr}");
    assert!(stderr.contains("nonexistent-e2e-path"), "{stderr}");
}
