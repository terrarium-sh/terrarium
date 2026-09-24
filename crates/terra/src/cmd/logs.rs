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
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::BrokenPipe) =>
        {
            Ok(ExitCode::SUCCESS)
        }
        answered => answered,
    }
}

fn is_log_moved(f: &std::fs::File, log: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let (Ok(old), Ok(new)) = (f.metadata(), std::fs::metadata(log)) else {
            return true;
        };
        old.dev() != new.dev() || old.ino() != new.ino()
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        !sys::file_handle_matches_path(f.as_raw_handle(), log)
    }
}

#[derive(Default)]
struct LogText {
    pending: Vec<u8>,
}

impl LogText {
    fn drain(
        &mut self,
        input: &mut impl std::io::Read,
        output: &mut impl std::io::Write,
    ) -> std::io::Result<u64> {
        let mut buffer = [0; 4096];
        let mut total = 0;
        loop {
            let count = match input.read(&mut buffer) {
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                result => result?,
            };
            if count == 0 {
                return Ok(total);
            }
            total += count as u64;
            self.pending.extend_from_slice(&buffer[..count]);
            while !self.pending.is_empty() {
                let (valid, invalid) = match std::str::from_utf8(&self.pending) {
                    Ok(text) => (text.len(), Some(0)),
                    Err(error) => (error.valid_up_to(), error.error_len()),
                };
                let text =
                    std::str::from_utf8(&self.pending[..valid]).map_err(std::io::Error::other)?;
                for line in text.split_inclusive('\n') {
                    let content = line.strip_suffix('\n').unwrap_or(line);
                    output.write_all(crate::render::escape_printable(content).as_bytes())?;
                    if line.ends_with('\n') {
                        output.write_all(b"\n")?;
                    }
                }
                self.pending.drain(..valid);
                match invalid {
                    Some(0) | None => break,
                    Some(count) => {
                        output.write_all("�".as_bytes())?;
                        self.pending.drain(..count);
                    }
                }
            }
        }
    }

    fn finish(&mut self, output: &mut impl std::io::Write) -> std::io::Result<()> {
        if !self.pending.is_empty() {
            output.write_all("�".as_bytes())?;
            self.pending.clear();
        }
        Ok(())
    }
}

fn seek_to_tail<F: std::io::Read + std::io::Seek>(f: &mut F, lines: usize) -> std::io::Result<()> {
    let len = f.seek(std::io::SeekFrom::End(0))?;
    if len == 0 || lines == 0 {
        return Ok(());
    }
    let mut found = 0;
    let mut cursor = len;
    let mut buf = [0u8; 4096];
    let mut at_end = true;

    while cursor > 0 {
        let chunk_size = usize::try_from(cursor).map_or(buf.len(), |c| c.min(buf.len()));
        cursor -= chunk_size as u64;
        f.seek(std::io::SeekFrom::Start(cursor))?;
        f.read_exact(&mut buf[..chunk_size])?;

        for (i, &byte) in buf[..chunk_size].iter().enumerate().rev() {
            let file_offset = cursor + i as u64;
            if at_end {
                at_end = false;
                if byte == b'\n' {
                    continue;
                }
            }
            if byte == b'\n' {
                found += 1;
                if found == lines {
                    f.seek(std::io::SeekFrom::Start(file_offset + 1))?;
                    return Ok(());
                }
            }
        }
    }
    f.seek(std::io::SeekFrom::Start(0))?;
    Ok(())
}

fn write_log(
    args: &crate::cli::LogsArgs,
    name: Option<&str>,
    project_dir: &Path,
) -> anyhow::Result<ExitCode> {
    use anyhow::Context as _;
    use std::io::Write as _;
    let bx = &crate::resolve::resolve_pinned_box(project_dir, name)?;
    let log = bx.get_dir().join(if args.diagnostics {
        crate::state::DIAGNOSTICS_LOG
    } else {
        crate::state::LOG_FILE
    });
    if !log.exists() {
        anyhow::bail!("no log for {bx} (no {})", log.display());
    }
    let mut out = std::io::stdout();
    let mut text = LogText::default();
    let mut f = std::fs::File::open(&log).with_context(|| format!("opening {}", log.display()))?;
    if let Some(tail) = args.tail {
        seek_to_tail(&mut f, tail).context("seeking to tail")?;
    }
    if !args.follow {
        text.drain(&mut f, &mut out).context("streaming log")?;
        text.finish(&mut out)?;
        out.flush().context("writing to stdout")?;
        return Ok(ExitCode::SUCCESS);
    }

    loop {
        let alive = bx.get_holder()?.holds();
        let n = text.drain(&mut f, &mut out).context("streaming log")?;
        out.flush().context("writing to stdout")?;
        if n == 0 {
            if !alive {
                text.finish(&mut out)?;
                out.flush()?;
                return Ok(ExitCode::SUCCESS);
            }
            std::thread::sleep(sys::POLL);
            if is_log_moved(&f, &log) {
                // The old generation is sealed now: drain what the writer put
                // there after the last copy.
                text.drain(&mut f, &mut out).context("streaming log")?;
                text.finish(&mut out)?;
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

    #[test]
    fn log_text_escapes_controls_and_preserves_split_unicode() {
        let mut text = LogText::default();
        let mut output = Vec::new();
        text.drain(&mut &b"hello\x1b]52;clipboard\x07\r\n\xe2"[..], &mut output)
            .unwrap();
        text.drain(&mut &b"\x82\xac\xff\xe2"[..], &mut output)
            .unwrap();
        text.finish(&mut output).unwrap();
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "hello\\u{1b}]52;clipboard\\u{7}\\r\n€��"
        );
        assert!(text.pending.is_empty());
    }

    /// A rotation is a new file under the same name (the appender repoints
    /// the `terra.log` symlink); the handle a follower holds keeps reading
    /// the generation it was opened on, and the name changing is what tells
    /// the follower to switch.
    #[test]
    fn a_rotated_log_is_a_new_file_under_the_same_name() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join(crate::state::LOG_FILE);
        std::fs::write(&log, b"first generation").unwrap();
        let mut f = std::fs::File::open(&log).unwrap();
        assert!(
            !is_log_moved(&f, &log),
            "an untouched file is not a rotation"
        );

        // Growth in place is not a rotation: the same inode, just longer.
        std::fs::write(&log, b"grown in place").unwrap();
        assert!(!is_log_moved(&f, &log));

        // A file that disappears and is replaced is one, as the appender
        // leaves it: the follower's handle still reads the generation it was
        // opened on.
        std::fs::remove_file(&log).unwrap();
        std::fs::write(&log, b"second generation").unwrap();
        assert!(is_log_moved(&f, &log), "the name points at a new file");
        let mut old = String::new();
        f.read_to_string(&mut old).unwrap();
        assert_eq!(old, "grown in place", "the old generation stays readable");
    }

    #[test]
    fn seek_to_tail_positions_at_last_n_lines() {
        use std::io::Cursor;

        let content = b"line 1\nline 2\nline 3\nline 4\n";
        let mut cur = Cursor::new(content.to_vec());

        seek_to_tail(&mut cur, 2).unwrap();
        let mut out = String::new();
        cur.read_to_string(&mut out).unwrap();
        assert_eq!(out, "line 3\nline 4\n");

        cur.set_position(0);
        seek_to_tail(&mut cur, 1).unwrap();
        out.clear();
        cur.read_to_string(&mut out).unwrap();
        assert_eq!(out, "line 4\n");

        cur.set_position(0);
        seek_to_tail(&mut cur, 10).unwrap();
        out.clear();
        cur.read_to_string(&mut out).unwrap();
        assert_eq!(out, "line 1\nline 2\nline 3\nline 4\n");

        cur.set_position(0);
        seek_to_tail(&mut cur, 0).unwrap();
        out.clear();
        cur.read_to_string(&mut out).unwrap();
        assert_eq!(out, "");

        let content_no_nl = b"first\nsecond\nthird";
        let mut cur = Cursor::new(content_no_nl.to_vec());
        seek_to_tail(&mut cur, 1).unwrap();
        out.clear();
        cur.read_to_string(&mut out).unwrap();
        assert_eq!(out, "third");

        cur.set_position(0);
        seek_to_tail(&mut cur, 2).unwrap();
        out.clear();
        cur.read_to_string(&mut out).unwrap();
        assert_eq!(out, "second\nthird");

        let mut cur = Cursor::new(Vec::new());
        seek_to_tail(&mut cur, 5).unwrap();
        out.clear();
        cur.read_to_string(&mut out).unwrap();
        assert_eq!(out, "");
    }
}
