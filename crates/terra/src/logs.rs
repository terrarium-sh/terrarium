//! Bounded host logs for each box.

use crate::state::BoxRef;
use log::{LevelFilter, Metadata, Record};
use std::fs::File;
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::Path;
use std::sync::{Mutex, PoisonError};
use terra_limits::MAX_LOG_FILE_BYTES;

/// A box's `terra.log`, appended across boots and never longer than [`MAX_LOG_FILE_BYTES`].
struct BoxLog {
    file: Mutex<File>,
    filter: env_filter::Filter,
}

impl BoxLog {
    fn open(path: &Path, filter: env_filter::Filter) -> std::io::Result<Self> {
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        Ok(Self {
            file: Mutex::new(crate::sys::open_regular_file_no_follow(path, &mut options)?),
            filter,
        })
    }

    /// Writes `line` whole when it fits the cap after a trim, and its head otherwise.
    fn append(&self, line: &[u8]) -> std::io::Result<()> {
        let mut file = self.file.lock().unwrap_or_else(PoisonError::into_inner);
        let len = file.seek(SeekFrom::End(0))?;
        if len + line.len() as u64 > MAX_LOG_FILE_BYTES {
            trim_to_newest_half(&mut file, len)?;
        }
        let room = MAX_LOG_FILE_BYTES.saturating_sub(file.seek(SeekFrom::End(0))?);
        file.write_all(&line[..line.len().min(usize::try_from(room).unwrap_or(usize::MAX))])
    }
}

/// Keeps the log's newest half from a line start, behind a [`TrimMarker`] that counts every
/// byte trimmed so far.
fn trim_to_newest_half(file: &mut File, len: u64) -> std::io::Result<()> {
    let previous = TrimMarker::read(file)?;
    let start = len
        .saturating_sub(MAX_LOG_FILE_BYTES / 2)
        .max(previous.line_len);
    file.seek(SeekFrom::Start(start))?;
    let mut kept = Vec::new();
    file.read_to_end(&mut kept)?;
    let first_line = kept
        .iter()
        .position(|&byte| byte == b'\n')
        .map_or(kept.len(), |newline| newline + 1);
    let trimmed_bytes = previous
        .trimmed_bytes
        .saturating_add(start + first_line as u64 - previous.line_len);
    kept.splice(
        ..first_line,
        TrimMarker::format_line(trimmed_bytes).into_bytes(),
    );
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&kept)?;
    file.set_len(kept.len() as u64)
}

impl log::Log for BoxLog {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        self.filter.enabled(metadata)
    }

    fn log(&self, record: &Record<'_>) {
        if !self.filter.matches(record) {
            return;
        }
        let line = format!(
            "{} {:>5} {}: {}\n",
            humantime::format_rfc3339_micros(std::time::SystemTime::now()),
            record.level(),
            record.target(),
            record.args()
        );
        let _ = self.append(line.as_bytes());
    }

    fn flush(&self) {}
}

pub fn init(bx: &BoxRef) -> anyhow::Result<()> {
    let filter = build_filter(std::env::var("RUST_LOG").ok().as_deref());
    let path = bx.get_dir().join(crate::state::LOG_FILE);
    let log = BoxLog::open(&path, filter)
        .map_err(|e| anyhow::anyhow!("opening log {}: {e}", path.display()))?;
    let _ = log.append(format!("\n===== terra: {bx} =====\n").as_bytes());
    let max_level = log.filter.filter();
    match log::set_logger(Box::leak(Box::new(log))) {
        Ok(()) => log::set_max_level(max_level),
        Err(error) => eprintln!("terra: warning: could not install the box logger: {error}"),
    }
    Ok(())
}

/// Opens a box log for reading, refusing a link the VM worker could plant in its writable
/// log directory.
pub(crate) fn open_box_log(path: &Path) -> std::io::Result<File> {
    crate::sys::open_regular_file_no_follow(path, std::fs::OpenOptions::new().read(true))
}

/// The first line of a trimmed log: how many bytes were cut from its front in all.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(crate) struct TrimMarker {
    trimmed_bytes: u64,
    line_len: u64,
}

const TRIM_MARKER_PREFIX: &str = "===== terra: ";
const TRIM_MARKER_SUFFIX: &str = " earlier bytes trimmed =====\n";

impl TrimMarker {
    fn format_line(trimmed_bytes: u64) -> String {
        format!("{TRIM_MARKER_PREFIX}{trimmed_bytes}{TRIM_MARKER_SUFFIX}")
    }

    /// Reads `file`'s marker, or the default for a log never trimmed; `file`'s position stays.
    pub(crate) fn read(file: &mut File) -> std::io::Result<Self> {
        let position = file.stream_position()?;
        file.seek(SeekFrom::Start(0))?;
        let mut head = Vec::new();
        (&mut *file).take(64).read_to_end(&mut head)?;
        file.seek(SeekFrom::Start(position))?;
        let line = head
            .iter()
            .position(|&byte| byte == b'\n')
            .and_then(|newline| std::str::from_utf8(&head[..=newline]).ok());
        Ok(line
            .and_then(|line| {
                let trimmed_bytes = line
                    .strip_prefix(TRIM_MARKER_PREFIX)?
                    .strip_suffix(TRIM_MARKER_SUFFIX)?
                    .parse()
                    .ok()?;
                Some(Self {
                    trimmed_bytes,
                    line_len: line.len() as u64,
                })
            })
            .unwrap_or_default())
    }
}

/// Moves a follower's `file` to the same logical byte after the writer trimmed the log, or to
/// the start after the writer restarted it; `marker` is the one the follower last saw. `Ok(true)`
/// means the writer rewrote the log, so a partial line read before it ends there.
pub(crate) fn resume_after_rewrite(
    file: &mut File,
    marker: &mut TrimMarker,
) -> std::io::Result<bool> {
    let current = TrimMarker::read(file)?;
    let position = file.stream_position()?;
    let is_restarted = current.trimmed_bytes < marker.trimmed_bytes
        || (current.trimmed_bytes == marker.trimmed_bytes && file.metadata()?.len() < position);
    let is_trimmed = current.trimmed_bytes > marker.trimmed_bytes;
    if is_restarted {
        file.seek(SeekFrom::Start(0))?;
    } else if is_trimmed {
        let logical = marker
            .trimmed_bytes
            .saturating_add(position.saturating_sub(marker.line_len));
        file.seek(SeekFrom::Start(
            current
                .line_len
                .saturating_add(logical.saturating_sub(current.trimmed_bytes)),
        ))?;
    }
    *marker = current;
    Ok(is_restarted || is_trimmed)
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
        std::fs::create_dir_all(bx.get_dir().join(crate::state::RUNTIME_LOG_DIR)).unwrap();
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

    /// The log never passes its cap, keeps whole newest lines behind its trim marker, and the
    /// marker accounts for every byte cut, so a follower resumes without skipping or
    /// repeating a line.
    #[test]
    fn the_log_keeps_its_newest_lines_under_the_cap_for_a_follower() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("terra.log");
        let log = BoxLog::open(&path, build_filter(None)).unwrap();
        let line = |index: u64| format!("line {index:09}\n");
        let line_len = line(0).len() as u64;
        let mut written = 0;
        while (written + 1) * line_len <= MAX_LOG_FILE_BYTES {
            log.append(line(written).as_bytes()).unwrap();
            written += 1;
        }
        let mut follower = open_box_log(&path).unwrap();
        let mut marker = TrimMarker::read(&mut follower).unwrap();
        let mut seen = String::new();
        follower.read_to_string(&mut seen).unwrap();

        let quarter = written / 4;
        for _ in 0..quarter {
            log.append(line(written).as_bytes()).unwrap();
            written += 1;
        }
        let len = std::fs::metadata(&path).unwrap().len();
        assert!(len <= MAX_LOG_FILE_BYTES);
        let mut reader = open_box_log(&path).unwrap();
        let trimmed = TrimMarker::read(&mut reader).unwrap();
        assert_eq!(
            trimmed.trimmed_bytes + len - trimmed.line_len,
            written * line_len
        );
        let mut text = String::new();
        reader.read_to_string(&mut text).unwrap();
        assert!(text.split_once('\n').unwrap().1.starts_with("line "));
        assert!(text.ends_with(&line(written - 1)));

        assert!(resume_after_rewrite(&mut follower, &mut marker).unwrap());
        follower.read_to_string(&mut seen).unwrap();
        let expected: String = (0..written).map(line).collect();
        assert_eq!(seen, expected);

        let full = written;
        for _ in 0..full {
            log.append(line(written).as_bytes()).unwrap();
            written += 1;
        }
        let len = std::fs::metadata(&path).unwrap().len();
        let trimmed_again = TrimMarker::read(&mut reader).unwrap();
        assert!(len <= MAX_LOG_FILE_BYTES);
        assert!(trimmed_again.trimmed_bytes > trimmed.trimmed_bytes + MAX_LOG_FILE_BYTES / 2);
        assert_eq!(
            trimmed_again.trimmed_bytes + len - trimmed_again.line_len,
            written * line_len
        );
    }

    /// A log the writer restarted, such as a new run's diagnostics, is followed from its start,
    /// even when the old log was trimmed and the new one already outgrew the follower's place.
    #[test]
    fn a_follower_restarts_with_a_restarted_log() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("diagnostics.log");
        for (old, new) in [
            ("an earlier run\n".to_owned(), "new\n".to_owned()),
            (
                format!("{}tail\n", TrimMarker::format_line(5000)),
                "a new run, already longer than the old one\n".repeat(4),
            ),
        ] {
            std::fs::write(&path, &old).unwrap();
            let mut follower = open_box_log(&path).unwrap();
            let mut marker = TrimMarker::read(&mut follower).unwrap();
            follower.read_to_string(&mut String::new()).unwrap();
            std::fs::write(&path, &new).unwrap();
            assert!(resume_after_rewrite(&mut follower, &mut marker).unwrap());
            let mut text = String::new();
            follower.read_to_string(&mut text).unwrap();
            assert_eq!(text, new);
        }
    }

    /// The marker is written by the VM worker, so a follower's arithmetic on it never overflows.
    #[test]
    fn a_follower_survives_an_extreme_marker() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("terra.log");
        std::fs::write(
            &path,
            format!("{}line\n", TrimMarker::format_line(u64::MAX - 1)),
        )
        .unwrap();
        let mut follower = open_box_log(&path).unwrap();
        let mut marker = TrimMarker::read(&mut follower).unwrap();
        follower.read_to_string(&mut String::new()).unwrap();
        std::fs::write(
            &path,
            format!("{}line\n", TrimMarker::format_line(u64::MAX)),
        )
        .unwrap();
        assert!(resume_after_rewrite(&mut follower, &mut marker).unwrap());
    }

    /// The VM worker can write its log directory, so host readers refuse a link planted there.
    #[test]
    #[cfg(unix)]
    fn box_log_readers_refuse_a_planted_link() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("secret");
        std::fs::write(&secret, b"secret").unwrap();
        let log = dir.path().join("terra.log");
        std::os::unix::fs::symlink(&secret, &log).unwrap();
        assert!(open_box_log(&log).is_err());
        assert!(BoxLog::open(&log, build_filter(None)).is_err());
    }
}
