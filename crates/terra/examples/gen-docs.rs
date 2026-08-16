//! Render man pages and shell completions from the clap CLI (`make man`).
//!
//! An example rather than `build.rs`, so `clap_mangen`/`clap_complete` stay
//! dev-dependencies - and rather than a test, because it writes and deletes
//! files in the working tree, which is not a thing `cargo test` should do.
//! `cargo test` still compiles it.

// An example is its own crate and cannot inherit the crate root's
// `#![cfg_attr(test, ...)]` opt-out, so it is spelled out here.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use clap::CommandFactory;
use clap_complete::Shell;
use std::path::Path;
use terra::cli::Cli;

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");

    let man = root.join("packaging/man");
    if std::fs::create_dir_all(&man).is_ok() {
        let cmd = Cli::command();
        let mut rendered = vec!["terra.1".to_string()];
        write_man(&man, &cmd, "terra");
        for sub in cmd.get_subcommands() {
            let name = format!("terra-{}", sub.get_name());
            write_man(&man, sub, &name);
            rendered.push(format!("{name}.1"));
        }
        // Sweep pages for commands that no longer exist. Rendering alone only
        // ever adds, so a removed subcommand used to leave its page behind
        // forever - `terra-init.1` and `terra-inspect.1` outlived their commands
        // here, still documenting a `spec.yaml` that predates `recipe.yaml`.
        for entry in std::fs::read_dir(&man).into_iter().flatten().flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with(".1") && !rendered.contains(&name) {
                let _ = std::fs::remove_file(entry.path());
                println!("removed stale man page {name}");
            }
        }
    } // packaging dir unavailable (e.g. vendored build) - skip quietly

    let comp = root.join("packaging/completions");
    if std::fs::create_dir_all(&comp).is_ok() {
        // Conventional per-shell filenames so packaging can drop them straight in.
        for (shell, file) in [
            (Shell::Bash, "terra.bash"),
            (Shell::Zsh, "_terra"),
            (Shell::Fish, "terra.fish"),
        ] {
            let mut cmd = Cli::command();
            let mut buf = Vec::new();
            clap_complete::generate(shell, &mut cmd, "terra", &mut buf);
            write_if_changed(&comp.join(file), &buf);
        }
    }
}

fn write_man(dir: &Path, cmd: &clap::Command, name: &str) {
    let mut buf = Vec::new();
    // Rename so subcommand pages title as `terra-stop(1)`, not `stop(1)`.
    // clap's `Str` wants a `&'static str`; leaking is fine in a one-shot render.
    let cmd = cmd
        .clone()
        .name(&*Box::leak(name.to_string().into_boxed_str()));
    clap_mangen::Man::new(cmd)
        .render(&mut buf)
        .expect("rendering man page");
    write_if_changed(&dir.join(format!("{name}.1")), &buf);
}

/// Write only on change, so regenerating doesn't dirty the working tree when the
/// output is identical.
fn write_if_changed(path: &Path, bytes: &[u8]) {
    if std::fs::read(path).ok().as_deref() != Some(bytes) {
        std::fs::write(path, bytes).expect("writing generated doc");
    }
}
