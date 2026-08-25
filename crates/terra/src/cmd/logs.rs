//! `terra logs` - print or follow the box's log. The writing side is
//! [`crate::logs`]'s.

use crate::sys;
use std::path::Path;
use std::process::ExitCode;

pub fn run(
    args: &crate::cli::LogsArgs,
    name: Option<&str>,
    project_dir: &Path,
) -> anyhow::Result<ExitCode> {
    match write_log(args, name, project_dir) {
        // a broken pipe is the reader leaving, not an error.
        Err(e) if is_broken_pipe(&e) => Ok(ExitCode::SUCCESS),
        answered => answered,
    }
}

fn is_broken_pipe(e: &anyhow::Error) -> bool {
    e.downcast_ref::<std::io::Error>()
        .is_some_and(|io| io.kind() == std::io::ErrorKind::BrokenPipe)
}

fn log_moved(f: &std::fs::File, log: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let (Ok(old), Ok(new)) = (f.metadata(), std::fs::metadata(log)) else {
        return true;
    };
    old.dev() != new.dev() || old.ino() != new.ino()
}

fn write_log(
    args: &crate::cli::LogsArgs,
    name: Option<&str>,
    project_dir: &Path,
) -> anyhow::Result<ExitCode> {
    use anyhow::Context as _;
    use std::io::Write as _;
    let bx = &crate::resolve::resolve_pinned_box(project_dir, name)?;
    let log = bx.log();
    if !log.exists() {
        anyhow::bail!("no log for {bx} (no {})", log.display());
    }
    let mut out = std::io::stdout();
    let mut f = std::fs::File::open(&log).with_context(|| format!("opening {}", log.display()))?;
    if !args.follow {
        std::io::copy(&mut f, &mut out).context("streaming log")?;
        out.flush().context("writing to stdout")?;
        return Ok(ExitCode::SUCCESS);
    }

    loop {
        let alive = bx.holder().holds();
        let n = std::io::copy(&mut f, &mut out).context("streaming log")?;
        out.flush().context("writing to stdout")?;
        if n == 0 {
            if !alive {
                return Ok(ExitCode::SUCCESS);
            }
            std::thread::sleep(sys::POLL);
            if log_moved(&f, &log) {
                // The old generation is sealed now: drain what the writer put
                // there after the last copy.
                std::io::copy(&mut f, &mut out).context("streaming log")?;
                f = std::fs::File::open(&log)
                    .with_context(|| format!("reopening {}", log.display()))?;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read as _;

    /// A rotation is a new file under the same name (the appender repoints
    /// the `terra.log` symlink); the handle a follower holds keeps reading
    /// the generation it was opened on, and the name changing is what tells
    /// the follower to switch.
    #[test]
    fn a_rotated_log_is_a_new_file_under_the_same_name() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("terra.log");
        std::fs::write(&log, b"first generation").unwrap();
        let mut f = std::fs::File::open(&log).unwrap();
        assert!(!log_moved(&f, &log), "an untouched file is not a rotation");

        // Growth in place is not a rotation: the same inode, just longer.
        std::fs::write(&log, b"grown in place").unwrap();
        assert!(!log_moved(&f, &log));

        // A file that disappears and is replaced is one, as the appender
        // leaves it: the follower's handle still reads the generation it was
        // opened on.
        std::fs::remove_file(&log).unwrap();
        std::fs::write(&log, b"second generation").unwrap();
        assert!(log_moved(&f, &log), "the name points at a new file");
        let mut old = String::new();
        f.read_to_string(&mut old).unwrap();
        assert_eq!(old, "grown in place", "the old generation stays readable");
    }
}
