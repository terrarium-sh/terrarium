//! The box's one rolling log: tracing records, rotated by tracing-appender
//! (`terra.log` is the symlink to the current one). Other writers - the guest
//! console included - reach the disk only under `TERRA_DIAGNOSTICS=1`, in
//! diagnostics.log.

use crate::state::BoxRef;
use crate::sys;
use anyhow::Context as _;
use std::io::Write;
use std::str::FromStr;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::filter::{LevelFilter, Targets};
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

const KEPT_LOG_GENERATIONS: usize = 7;

/// The appender for the box's log.
fn build_appender(bx: &BoxRef) -> anyhow::Result<RollingFileAppender> {
    RollingFileAppender::builder()
        .rotation(Rotation::DAILY)
        .filename_prefix("terra")
        .filename_suffix("log")
        .max_log_files(KEPT_LOG_GENERATIONS)
        .latest_symlink("terra.log")
        .build(bx.dir())
        .map_err(|e| anyhow::anyhow!("opening log {}: {e}", bx.log().display()))
}

pub fn init(bx: &BoxRef) -> anyhow::Result<()> {
    let appender = build_appender(bx)?;

    let spec = std::env::var("RUST_LOG").ok();
    let asked = spec.as_deref().and_then(|s| match Targets::from_str(s) {
        Ok(filter) => Some(filter),
        Err(e) => {
            eprintln!(
                "terra: warning: RUST_LOG ('{s}') is not a filter this understands ({e}) - \
                 using the default (info)"
            );
            None
        }
    });

    let (filter, defaulted) = match asked {
        Some(filter) => (filter, false),
        None => (Targets::new().with_default(LevelFilter::INFO), true),
    };

    let installed = tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(appender),
        )
        .with(filter)
        .try_init()
        .is_ok();

    if installed && defaulted {
        log::set_max_level(log::LevelFilter::Info);
    }

    // A direct write, not a log record: the mark must land whatever RUST_LOG says.
    if let Ok(mut sep) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(bx.log())
    {
        let _ = writeln!(&mut sep, "\n===== terra: {bx} =====");
    }
    Ok(())
}

pub fn open_diagnostics(bx: &BoxRef) -> anyhow::Result<std::fs::File> {
    let path = bx.diagnostics_log();
    sys::create_no_symlinks(&path).with_context(|| format!("opening {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each run owns diagnostics.log: it is opened truncated, so the file is
    /// the run's alone rather than a running account that grows forever.
    #[test]
    fn diagnostics_starts_fresh_each_run() {
        let dir = tempfile::tempdir().unwrap();
        let bx = BoxRef::from_state_dir(dir.path().join("dev"), dir.path());
        std::fs::create_dir_all(bx.dir()).unwrap();
        std::fs::write(bx.diagnostics_log(), b"a previous run\n").unwrap();

        let f = open_diagnostics(&bx).unwrap();
        drop(f);
        assert_eq!(std::fs::read(bx.diagnostics_log()).unwrap(), b"");
    }

    /// The appender lays down the scheme: `terra.log` is a symlink to a
    /// dated generation.
    #[test]
    fn the_appender_lays_down_the_scheme() {
        let dir = tempfile::tempdir().unwrap();
        let bx = BoxRef::from_state_dir(dir.path().join("dev"), dir.path());
        std::fs::create_dir_all(bx.dir()).unwrap();

        build_appender(&bx).unwrap();

        let meta = std::fs::symlink_metadata(bx.log()).unwrap();
        assert!(
            meta.file_type().is_symlink(),
            "terra.log is the appender's symlink"
        );
        let dated: Vec<_> = std::fs::read_dir(bx.dir())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| {
                n.starts_with("terra.")
                    && std::path::Path::new(n)
                        .extension()
                        .is_some_and(|e| e == "log")
            })
            .collect();
        assert_eq!(dated.len(), 1, "the current generation is dated: {dated:?}");
        assert_ne!(dated[0], "terra.log", "the live name is the symlink's");
    }
}
