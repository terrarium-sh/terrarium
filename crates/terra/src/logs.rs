//! Bounded host logs for each box.

use crate::state::BoxRef;
use log::{LevelFilter, Metadata, Record};
use std::path::PathBuf;
use std::sync::{Mutex, PoisonError};
use std::time::SystemTime;

#[cfg(unix)]
const KEPT_LOG_GENERATIONS: usize = 7;

/// A box's `terra.log`; on Unix it links to the current UTC day's generation.
struct BoxLog {
    path: PathBuf,
    filter: env_filter::Filter,
    /// The day `terra.log` links to; writes hold it so lines and rotation never interleave.
    day: Mutex<String>,
}

impl BoxLog {
    #[cfg_attr(
        unix,
        allow(
            clippy::unnecessary_wraps,
            reason = "Windows truncates the file, which can fail"
        )
    )]
    fn new(path: PathBuf, filter: env_filter::Filter) -> std::io::Result<Self> {
        #[cfg(windows)]
        crate::sys::create_regular_file(&path)?;
        Ok(Self {
            path,
            filter,
            day: Mutex::new(String::new()),
        })
    }

    fn append(&self, now: SystemTime, line: &str) -> std::io::Result<()> {
        let mut day = self.day.lock().unwrap_or_else(PoisonError::into_inner);
        #[cfg(unix)]
        {
            let today = &humantime::format_rfc3339(now).to_string()[..10];
            if *day != today {
                self.rotate(today)?;
                today.clone_into(&mut day);
            }
        }
        #[cfg(windows)]
        let _ = (now, &mut day);
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .append(true)
            .open(&self.path)?;
        terra_platform::filesystem::append_capped(
            &mut file,
            line.as_bytes(),
            terra_limits::MAX_LOG_FILE_BYTES,
        )
    }

    /// Points `terra.log` at `today`'s generation and drops the oldest past the kept count.
    #[cfg(unix)]
    fn rotate(&self, today: &str) -> std::io::Result<()> {
        let directory = self
            .path
            .parent()
            .ok_or_else(|| std::io::Error::other("log path has no parent"))?;
        let dated = format!("terra.{today}.log");
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(directory.join(&dated))?;
        let link = directory.join(".terra.log.new");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&dated, &link)?;
        // renameat, which the VM role's seccomp allowlist already holds for shares; std uses rename.
        rustix::fs::renameat(rustix::fs::CWD, &link, rustix::fs::CWD, &self.path)?;
        let mut generations: Vec<_> = std::fs::read_dir(directory)?
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| {
                name.strip_prefix("terra.")
                    .and_then(|rest| rest.strip_suffix(".log"))
                    .is_some_and(|day| day.len() == today.len())
            })
            .collect();
        generations.sort();
        let excess = generations.len().saturating_sub(KEPT_LOG_GENERATIONS);
        for name in &generations[..excess] {
            let _ = std::fs::remove_file(directory.join(name));
        }
        Ok(())
    }
}

impl log::Log for BoxLog {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        self.filter.enabled(metadata)
    }

    fn log(&self, record: &Record<'_>) {
        if !self.filter.matches(record) {
            return;
        }
        let now = SystemTime::now();
        let line = format!(
            "{} {:>5} {}: {}\n",
            humantime::format_rfc3339_micros(now),
            record.level(),
            record.target(),
            record.args()
        );
        let _ = self.append(now, &line);
    }

    fn flush(&self) {}
}

pub fn init(bx: &BoxRef) -> anyhow::Result<()> {
    let filter = build_filter(std::env::var("RUST_LOG").ok().as_deref());
    let path = bx.get_dir().join(crate::state::LOG_FILE);
    let log = BoxLog::new(path.clone(), filter)
        .map_err(|e| anyhow::anyhow!("opening log {}: {e}", path.display()))?;
    let _ = log.append(SystemTime::now(), &format!("\n===== terra: {bx} =====\n"));
    let max_level = log.filter.filter();
    match log::set_logger(Box::leak(Box::new(log))) {
        Ok(()) => log::set_max_level(max_level),
        Err(error) => eprintln!("terra: warning: could not install the box logger: {error}"),
    }
    Ok(())
}

/// `RUST_LOG`'s filter in `env_logger` syntax, or `info` when it is unset or malformed.
fn build_filter(spec: Option<&str>) -> env_filter::Filter {
    let mut builder = env_filter::Builder::new();
    let parsed = spec.is_some_and(|spec| match builder.try_parse(spec) {
        Ok(_) => true,
        Err(error) => {
            eprintln!(
                "terra: warning: RUST_LOG ('{spec}') is not a filter this understands ({error}) - \
                 using the default (info)"
            );
            false
        }
    });
    if !parsed {
        builder = env_filter::Builder::new();
        builder.filter_level(LevelFilter::Info);
    }
    builder.build()
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

    #[test]
    fn rust_log_falls_back_to_info_only_when_unset_or_malformed() {
        let level = |spec: Option<&str>, target: &str| {
            let filter = build_filter(spec);
            [
                log::Level::Trace,
                log::Level::Debug,
                log::Level::Info,
                log::Level::Warn,
            ]
            .into_iter()
            .find(|level| filter.enabled(&Metadata::builder().level(*level).target(target).build()))
        };
        assert_eq!(level(None, "terra::vm"), Some(log::Level::Info));
        assert_eq!(
            level(Some("terra=loud"), "terra::vm"),
            Some(log::Level::Info)
        );
        let spec = Some("warn,terra_runtime=debug,terra_runtime::component=off");
        assert_eq!(level(spec, "terra::vm"), Some(log::Level::Warn));
        assert_eq!(
            level(spec, "terra_runtime::orchestration"),
            Some(log::Level::Debug)
        );
        assert_eq!(level(spec, "terra_runtime::component::fs"), None);
    }

    /// `terra.log` is a symlink to the current UTC day's generation, a new day moves it, and
    /// only the newest generations survive.
    #[test]
    #[cfg(unix)]
    fn daily_generations_rotate_behind_the_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let bx = BoxRef::from_state_dir(dir.path().join("dev"), dir.path());
        std::fs::create_dir_all(bx.get_dir()).unwrap();
        let path = bx.get_dir().join(crate::state::LOG_FILE);
        let directory = path.parent().unwrap().to_owned();
        std::fs::create_dir_all(&directory).unwrap();
        for day in 1..=8 {
            std::fs::write(directory.join(format!("terra.2026-01-0{day}.log")), b"old").unwrap();
        }
        let log = BoxLog::new(path.clone(), build_filter(None)).unwrap();
        let day = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_792_615_253);
        log.append(day, "first\n").unwrap();
        log.append(day + std::time::Duration::from_hours(24), "second\n")
            .unwrap();

        assert_eq!(
            std::fs::read_link(&path).unwrap(),
            std::path::Path::new("terra.2026-10-22.log")
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "second\n");
        assert_eq!(
            std::fs::read_to_string(directory.join("terra.2026-10-21.log")).unwrap(),
            "first\n"
        );
        let mut kept: Vec<_> = std::fs::read_dir(&directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .filter(|name| name != "terra.log")
            .collect();
        kept.sort();
        assert_eq!(kept.len(), KEPT_LOG_GENERATIONS);
        assert_eq!(kept.last().unwrap(), "terra.2026-10-22.log");
    }

    #[test]
    #[cfg(windows)]
    fn the_log_writes_without_symlink_privileges() {
        let dir = tempfile::tempdir().unwrap();
        let bx = BoxRef::from_state_dir(dir.path().join("dev"), dir.path());
        std::fs::create_dir_all(bx.get_dir()).unwrap();
        let path = bx.get_dir().join(crate::state::LOG_FILE);

        let log = BoxLog::new(path.clone(), build_filter(None)).unwrap();
        log.append(SystemTime::now(), "booting\n").unwrap();
        assert!(std::fs::symlink_metadata(&path).unwrap().is_file());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "booting\n");

        BoxLog::new(path.clone(), build_filter(None)).unwrap();
        assert_eq!(std::fs::read(path).unwrap(), [] as [u8; 0]);
    }
}
