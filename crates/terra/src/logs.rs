//! Bounded daily host logs for each box.

use crate::state::BoxRef;
use std::io::Write;
use std::str::FromStr;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::filter::{LevelFilter, Targets};
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

const KEPT_LOG_GENERATIONS: usize = 7;

struct CappedAppender {
    appender: RollingFileAppender,
    path: std::path::PathBuf,
}

impl Write for CappedAppender {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let _ = self.appender.write(&[])?;
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .append(true)
            .open(&self.path)?;
        terra_io::log::write_capped(&mut file, bytes)?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.appender.flush()
    }
}

fn build_appender(bx: &BoxRef) -> anyhow::Result<CappedAppender> {
    let appender = RollingFileAppender::builder()
        .rotation(Rotation::DAILY)
        .filename_prefix("terra")
        .filename_suffix("log")
        .max_log_files(KEPT_LOG_GENERATIONS)
        .latest_symlink(crate::state::LOG_FILE)
        .build(bx.get_dir())
        .map_err(|e| {
            anyhow::anyhow!(
                "opening log {}: {e}",
                bx.get_dir().join(crate::state::LOG_FILE).display()
            )
        })?;
    Ok(CappedAppender {
        appender,
        path: bx.get_dir().join(crate::state::LOG_FILE),
    })
}

pub fn init(bx: &BoxRef) -> anyhow::Result<()> {
    let mut appender = build_appender(bx)?;
    let _ = writeln!(&mut appender, "\n===== terra: {bx} =====");

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

    let installation = tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(std::sync::Mutex::new(appender)),
        )
        .with(filter)
        .try_init();
    if let Err(error) = &installation {
        eprintln!("terra: warning: could not install log subscriber: {error}");
    }

    if installation.is_ok() && defaulted {
        log::set_max_level(log::LevelFilter::Info);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys;

    /// Each run owns diagnostics.log: it is opened truncated, so the file is
    /// the run's alone rather than a running account that grows forever.
    #[test]
    fn diagnostics_starts_fresh_each_run() {
        let dir = tempfile::tempdir().unwrap();
        let bx = BoxRef::from_state_dir(dir.path().join("dev"), dir.path());
        std::fs::create_dir_all(bx.get_dir()).unwrap();
        std::fs::write(
            bx.get_dir().join(crate::state::DIAGNOSTICS_LOG),
            b"a previous run\n",
        )
        .unwrap();

        let path = bx.get_dir().join(crate::state::DIAGNOSTICS_LOG);
        let f = sys::create_regular_file(&path).unwrap();
        drop(f);
        assert_eq!(
            std::fs::read(bx.get_dir().join(crate::state::DIAGNOSTICS_LOG)).unwrap(),
            b""
        );
    }

    /// The appender lays down the scheme: `terra.log` is a symlink to a
    /// dated generation.
    #[test]
    fn the_appender_lays_down_the_scheme() {
        let dir = tempfile::tempdir().unwrap();
        let bx = BoxRef::from_state_dir(dir.path().join("dev"), dir.path());
        std::fs::create_dir_all(bx.get_dir()).unwrap();

        build_appender(&bx).unwrap();

        let meta = std::fs::symlink_metadata(bx.get_dir().join(crate::state::LOG_FILE)).unwrap();
        assert!(
            meta.file_type().is_symlink(),
            "terra.log is the appender's symlink"
        );
        let dated: Vec<_> = std::fs::read_dir(bx.get_dir())
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
