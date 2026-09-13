//! `terra <box> put` and `terra <box> get` - one file into or out of a running
//! box, over the agent's file port. The guest end is untrusted: every bound and
//! timeout below is there because a workload controls what comes back.

use crate::sys;
use crate::vm::image;
use anyhow::{Context, Result};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};
use terra_protocol::{
    AgentService, FileReply, FileRequest, MAX_FILE_BYTES, encode_frame, read_frame_with_limit,
};

const MAX_FILE_REPLY_FRAME_BYTES: usize = 64 * 1024;

const COPY_STALL_TIMEOUT: Duration = Duration::from_mins(1);

const COPY_DATA_TIMEOUT: Duration = Duration::from_hours(1);

/// Copy one file into or out of a running box
// ponytail: single files only. Directories would put an archive format on the
// wire; a mount or `tar` through the shell covers that today.
pub fn run(
    args: &crate::cli::CopyArgs,
    direction: Direction,
    name: Option<&str>,
    project_dir: &Path,
) -> Result<ExitCode> {
    let (host, guest) = resolve_host_guest_paths(args, direction)?;
    let bx = &crate::resolve::resolve_pinned_box(project_dir, name)?;
    // The file service answers only once the workload is up - after every
    // mount, `on_create` bake and `on_start` hook.
    let mut stream = crate::session::connect_to_running_agent(
        bx,
        direction.as_cli_verb(),
        AgentService::Files,
        "file service",
        args.agent.agent_timeout,
    )?;
    stream
        .set_read_timeout(Some(COPY_STALL_TIMEOUT))
        .context("setting copy read timeout")?;
    stream
        .set_write_timeout(Some(COPY_STALL_TIMEOUT))
        .context("setting copy write timeout")?;
    let deadline = Instant::now() + COPY_DATA_TIMEOUT;

    match direction {
        Direction::IntoBox => send_file_into_box(&mut stream, host, guest, deadline),
        Direction::OutOfBox => fetch_file_from_box(&mut stream, guest, host, deadline),
    }
}

fn read_reply(stream: &mut impl Read) -> Result<FileReply> {
    let rep = read_frame_with_limit(stream, MAX_FILE_REPLY_FRAME_BYTES)
        .context("reading the agent's reply")?
        .ok_or_else(|| anyhow::anyhow!("agent closed connection without replying"))?;
    match rep {
        FileReply::Err(err) => anyhow::bail!("guest: {}", sanitize_guest_error_message(&err)),
        FileReply::Put | FileReply::Get { .. } => Ok(rep),
    }
}

enum CopyTarget<'a> {
    Plain(&'a mut dyn Write),
    Sparse(&'a mut File),
}

fn copy_at_most(
    from: &mut impl Read,
    to: &mut CopyTarget<'_>,
    size: u64,
    what: &str,
    deadline: Instant,
) -> Result<u64> {
    let mut buf = [0u8; 16 * 1024];
    let mut sent = 0u64;
    while sent < size {
        if Instant::now() >= deadline {
            anyhow::bail!(
                "{what} ran past its {}s data transfer limit - the other end kept the \
                 transfer open without finishing it",
                COPY_DATA_TIMEOUT.as_secs()
            );
        }
        let want = usize::min(buf.len(), usize::try_from(size - sent).unwrap_or(buf.len()));
        let n = match from.read(&mut buf[..want]) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            result => result.with_context(|| what.to_string())?,
        };
        if n == 0 {
            break;
        }
        match to {
            CopyTarget::Plain(to) => to.write_all(&buf[..n]).context(what.to_string())?,
            CopyTarget::Sparse(to) => {
                image::write_sparse_chunk(to, &buf[..n]).context(what.to_string())?;
            }
        }
        sent += u64::try_from(n).unwrap_or_default();
    }
    Ok(sent)
}

fn send_body_padded_to_size(
    body: &mut impl Read,
    stream: &mut impl Write,
    size: u64,
    deadline: Instant,
) -> Result<u64> {
    let sent = copy_at_most(
        body,
        &mut CopyTarget::Plain(stream),
        size,
        "sending the file",
        deadline,
    )?;
    if sent < size {
        copy_at_most(
            &mut std::io::repeat(0),
            &mut CopyTarget::Plain(stream),
            size - sent,
            "completing a short transfer",
            deadline,
        )?;
    }
    Ok(sent)
}

fn report(from: &str, to: &str, bytes: u64) -> ExitCode {
    eprintln!("terra: copied {from} -> {to} ({bytes} bytes)");
    ExitCode::SUCCESS
}

fn send_file_into_box(
    stream: &mut (impl Read + Write),
    host_path: &str,
    guest_path: &str,
    deadline: Instant,
) -> Result<ExitCode> {
    let mut file = sys::open_regular_file(Path::new(host_path))
        .with_context(|| format!("opening {host_path}"))?;
    let meta = file
        .metadata()
        .with_context(|| format!("reading {host_path}"))?;
    anyhow::ensure!(
        !meta.is_dir(),
        "{host_path} is a directory - a copy carries single files \
         (use a mount, or tar through the shell)"
    );

    let size = meta.len();
    anyhow::ensure!(
        size <= MAX_FILE_BYTES,
        "{host_path} is {size} bytes, past the {} GiB copy ceiling",
        MAX_FILE_BYTES >> 30
    );
    let request = FileRequest::Put {
        path: guest_path.to_string(),
        mode: to_guest_mode(&meta),
        size,
    };
    stream
        .write_all(&encode_frame(&request).context("encoding the request")?)
        .context("sending the request")?;
    let sent = send_body_padded_to_size(&mut file, stream, size, deadline)?;

    match read_reply(stream)? {
        FileReply::Put => {}
        FileReply::Get { .. } | FileReply::Err(_) => {
            anyhow::bail!("the agent answered a put request with another kind of reply")
        }
    }
    anyhow::ensure!(
        sent == size,
        "{host_path} shrank while it was being copied ({sent} of {size} bytes); \
         the guest copy was padded to the promised length - copy it again"
    );
    Ok(report(host_path, guest_path, sent))
}

fn fetch_file_from_box(
    stream: &mut (impl Read + Write),
    guest_path: &str,
    host_path: &str,
    deadline: Instant,
) -> Result<ExitCode> {
    let request = FileRequest::Get {
        path: guest_path.to_string(),
    };
    stream
        .write_all(&encode_frame(&request).context("encoding the request")?)
        .context("sending the request")?;
    let FileReply::Get { mode, size } = read_reply(stream)? else {
        anyhow::bail!("the agent answered a get request with another kind of reply");
    };
    anyhow::ensure!(
        size <= MAX_FILE_BYTES,
        "{guest_path} says it is {size} bytes, past the {} GiB copy ceiling \
         (share a directory instead - a copy is for single files)",
        MAX_FILE_BYTES >> 30
    );

    let mut dst_path = PathBuf::from(host_path);
    if std::fs::metadata(&dst_path).is_ok_and(|m| m.is_dir()) {
        let name = extract_guest_file_name(guest_path)?;
        dst_path.push(name);
    }
    let write_path = match std::fs::metadata(&dst_path) {
        Ok(metadata) => {
            anyhow::ensure!(
                metadata.is_file(),
                "creating {}: expected a regular file",
                dst_path.display()
            );
            std::fs::canonicalize(&dst_path)
                .with_context(|| format!("resolving {}", dst_path.display()))?
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            match std::fs::symlink_metadata(&dst_path) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    anyhow::bail!(
                        "creating {}: destination is a dangling symlink",
                        dst_path.display()
                    );
                }
                Ok(_) => dst_path.clone(),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => dst_path.clone(),
                Err(error) => {
                    return Err(error).with_context(|| format!("reading {}", dst_path.display()));
                }
            }
        }
        Err(error) => return Err(error).with_context(|| format!("reading {}", dst_path.display())),
    };
    crate::vm::image::staged_write(&write_path, |file| {
        let received = copy_at_most(
            stream,
            &mut CopyTarget::Sparse(file),
            size,
            "receiving the file",
            deadline,
        )?;
        anyhow::ensure!(
            received == size,
            "{guest_path} ended after {received} of {size} promised bytes; copy it again"
        );
        file.set_len(size)
            .with_context(|| format!("sizing {}", write_path.display()))?;
        sys::set_open_file_mode(file, to_safe_mode(mode))
            .with_context(|| format!("setting permissions on {}", write_path.display()))
    })?;
    Ok(report(guest_path, &dst_path.display().to_string(), size))
}

fn extract_guest_file_name(guest_path: &str) -> Result<&std::ffi::OsStr> {
    let name = Path::new(guest_path)
        .file_name()
        .context("guest path has no file name")?;
    #[cfg(windows)]
    anyhow::ensure!(
        matches!(
            Path::new(name).components().next(),
            Some(std::path::Component::Normal(_))
        ) && Path::new(name).components().nth(1).is_none()
            && !name.to_string_lossy().contains(':'),
        "guest file name is invalid on Windows; choose an explicit destination file name"
    );
    Ok(name)
}

const MAX_GUEST_ERROR_MESSAGE: usize = 512;

fn sanitize_guest_error_message(err: &str) -> String {
    let mut chars = err.chars();
    let message: String = chars.by_ref().take(MAX_GUEST_ERROR_MESSAGE).collect();
    let mut out = crate::render::escape_printable(&message);
    if chars.next().is_some() {
        out.push('…');
    }
    out
}

/// The permission bits a copy carries into the box: rwx - setuid, setgid and
/// sticky stay on the host.
fn to_guest_mode(meta: &std::fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o0777
    }
    #[cfg(windows)]
    {
        if meta.permissions().readonly() {
            0o444
        } else {
            0o644
        }
    }
}

/// The permission bits a guest-supplied mode may set on a host file: rwx,
/// minus group and other write - a setuid bit would leave a setuid file owned
/// by whoever ran the copy, and group or world write lets any account rewrite
/// it before it is run.
fn to_safe_mode(guest_mode: u32) -> u32 {
    guest_mode & 0o755
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Direction {
    IntoBox,
    OutOfBox,
}

impl Direction {
    fn as_cli_verb(self) -> &'static str {
        match self {
            Direction::IntoBox => "put",
            Direction::OutOfBox => "get",
        }
    }
}

fn resolve_host_guest_paths(
    args: &crate::cli::CopyArgs,
    direction: Direction,
) -> Result<(&str, &str)> {
    let (host, guest) = match direction {
        Direction::IntoBox => (&args.src, &args.dst),
        Direction::OutOfBox => (&args.dst, &args.src),
    };
    anyhow::ensure!(
        guest.starts_with('/'),
        "the box's side of a copy is an absolute path, and '{guest}' is not \
         (`terra <box> {}`)",
        match direction {
            Direction::IntoBox => "put ./local.txt /tmp/remote.txt",
            Direction::OutOfBox => "get /etc/os-release ./os-release",
        }
    );
    Ok((host, guest))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deadline far enough out that no test transfer trips it.
    fn make_test_deadline() -> Instant {
        Instant::now() + Duration::from_mins(1)
    }

    /// The guest end of a get, scripted: whatever bytes the "agent" sends,
    /// then EOF. Writes (the request frame) go nowhere.
    struct GuestEnd(std::io::Cursor<Vec<u8>>);

    impl std::io::Read for GuestEnd {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.0.read(buf)
        }
    }
    impl std::io::Write for GuestEnd {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn build_reply(size: u64, body: &[u8]) -> GuestEnd {
        let mut script = encode_frame(&FileReply::Get { mode: 0o644, size }).unwrap();
        script.extend_from_slice(body);
        GuestEnd(std::io::Cursor::new(script))
    }

    #[test]
    fn oversized_file_reply_is_rejected_before_reading_its_body() {
        let prefix = u32::try_from(MAX_FILE_REPLY_FRAME_BYTES + 1)
            .unwrap()
            .to_le_bytes();
        let error = read_reply(&mut prefix.as_slice()).unwrap_err();
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::InvalidData
        );
    }

    #[cfg(windows)]
    #[test]
    fn a_windows_special_guest_basename_is_refused() {
        assert!(extract_guest_file_name("/tmp/C:notes").is_err());
        assert!(extract_guest_file_name("/tmp/notes:stream").is_err());
    }

    /// A guest that closes the stream short of the promised length must leave
    /// the existing destination alone.
    #[test]
    fn a_fetch_file_from_box_cut_short_is_an_error_not_a_success() {
        let dir = tempfile::tempdir().unwrap();
        let dst = dir.path().join("out.bin");
        std::fs::write(&dst, b"kept").unwrap();
        let dst_str = dst.to_str().unwrap();

        let err = fetch_file_from_box(
            &mut build_reply(8, b"1234"),
            "/data/out.bin",
            dst_str,
            make_test_deadline(),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("4 of 8"), "{err}");
        assert_eq!(std::fs::read(&dst).unwrap(), b"kept");

        // The full transfer still succeeds, byte for byte.
        fetch_file_from_box(
            &mut build_reply(8, b"12345678"),
            "/data/out.bin",
            dst_str,
            make_test_deadline(),
        )
        .unwrap();
        assert_eq!(std::fs::read(&dst).unwrap(), b"12345678");
    }

    #[cfg(unix)]
    #[test]
    fn a_zero_filled_get_stays_sparse() {
        use std::os::unix::fs::MetadataExt;

        let dir = tempfile::tempdir().unwrap();
        let dst = dir.path().join("zeros");
        let body = vec![0; 1024 * 1024];
        fetch_file_from_box(
            &mut build_reply(body.len() as u64, &body),
            "/data/zeros",
            dst.to_str().unwrap(),
            make_test_deadline(),
        )
        .unwrap();

        let metadata = std::fs::metadata(&dst).unwrap();
        assert_eq!(metadata.len(), body.len() as u64);
        assert!(metadata.blocks() * 512 < metadata.len());
    }

    #[cfg(unix)]
    #[test]
    fn a_get_follows_symlink_destination_or_parent() {
        let dir = tempfile::tempdir().unwrap();
        let redirected = dir.path().join("redirected");
        std::fs::write(&redirected, b"unchanged").unwrap();
        let symlink_destination = dir.path().join("destination");
        std::os::unix::fs::symlink(&redirected, &symlink_destination).unwrap();

        assert!(
            fetch_file_from_box(
                &mut build_reply(3, b"new"),
                "/data/out",
                symlink_destination.to_str().unwrap(),
                make_test_deadline(),
            )
            .is_ok()
        );
        assert_eq!(std::fs::read(&redirected).unwrap(), b"new");

        let real_parent = dir.path().join("real");
        std::fs::create_dir(&real_parent).unwrap();
        let symlink_parent = dir.path().join("linked");
        std::os::unix::fs::symlink(&real_parent, &symlink_parent).unwrap();
        let destination = symlink_parent.join("out");

        assert!(
            fetch_file_from_box(
                &mut build_reply(3, b"new"),
                "/data/out",
                destination.to_str().unwrap(),
                make_test_deadline(),
            )
            .is_ok()
        );
        assert_eq!(std::fs::read(real_parent.join("out")).unwrap(), b"new");
    }

    #[cfg(unix)]
    #[test]
    fn a_get_refuses_a_nonregular_destination() {
        use std::os::unix::fs::FileTypeExt;

        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("fifo");
        rustix::fs::mkfifoat(rustix::fs::CWD, &fifo, rustix::fs::Mode::empty()).unwrap();
        assert!(
            std::fs::symlink_metadata(&fifo)
                .unwrap()
                .file_type()
                .is_fifo()
        );
        let error = fetch_file_from_box(
            &mut build_reply(3, b"new"),
            "/data/out",
            fifo.to_str().unwrap(),
            make_test_deadline(),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("regular file"), "{error}");
    }

    /// A file that shrank between being measured and being read still has to
    /// arrive as the length this end promised: the agent blocks until it has
    /// that many bytes, this end blocks on its reply, and the vsock proxy has no
    /// half-close to break the tie - so a short body wedges the copy rather than
    /// failing it. The padding is what keeps that a reportable error (`send_file_into_box`
    /// refuses on the count this hands back) instead of a hang.
    #[test]
    fn a_file_that_shrank_after_being_measured_is_padded_out_to_the_promised_length() {
        let mut wire = Vec::new();
        let sent = send_body_padded_to_size(
            &mut std::io::Cursor::new(b"1234".to_vec()),
            &mut wire,
            8,
            make_test_deadline(),
        )
        .unwrap();
        assert_eq!(sent, 4, "the count is what was really read");
        assert_eq!(wire, b"1234\0\0\0\0", "the promised length still went out");

        // A file that is all there sends itself and not one byte more.
        let mut whole = Vec::new();
        let sent = send_body_padded_to_size(
            &mut std::io::Cursor::new(b"12345678".to_vec()),
            &mut whole,
            8,
            make_test_deadline(),
        )
        .unwrap();
        assert_eq!((sent, whole.as_slice()), (8, b"12345678".as_slice()));

        // A file that *grew* is held to the promise too - the agent stops
        // reading at the length it was given, so the rest is not the copy's.
        let mut bounded = Vec::new();
        let sent = send_body_padded_to_size(
            &mut std::io::Cursor::new(b"12345678and more".to_vec()),
            &mut bounded,
            8,
            make_test_deadline(),
        )
        .unwrap();
        assert_eq!((sent, bounded.as_slice()), (8, b"12345678".as_slice()));
    }

    #[test]
    fn file_transfer_retries_interrupted_reads() {
        use crate::cmd::InterruptedOnce;

        let payload = b"complete file";
        let mut source = InterruptedOnce(true).chain(payload.as_slice());
        let mut output = Vec::new();
        let copied = copy_at_most(
            &mut source,
            &mut CopyTarget::Plain(&mut output),
            payload.len() as u64,
            "copying",
            make_test_deadline(),
        )
        .unwrap();
        assert_eq!(copied, payload.len() as u64);
        assert_eq!(output, payload);
    }

    /// One byte at a time, forever: the stall timeout cannot see this - every
    /// syscall lands well inside it - so the data transfer limit is what ends the
    /// copy instead of letting the guest hold it open indefinitely.
    #[test]
    fn a_transfer_past_its_data_deadline_fails_rather_than_trickling_forever() {
        struct Trickle;
        impl Read for Trickle {
            fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                std::thread::sleep(Duration::from_millis(20));
                Ok(1)
            }
        }

        let mut sink = Vec::new();
        let err = copy_at_most(
            &mut Trickle,
            &mut CopyTarget::Plain(&mut sink),
            100,
            "receiving the file",
            Instant::now(),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("data transfer limit"), "{err}");
    }

    /// The verb says which side is the box's, so neither path needs a mark and
    /// both are taken as written. `put` sends its source in; `get` fetches its
    /// source out - and the pair comes back in `(host, guest)` order whichever
    /// verb was typed.
    #[test]
    fn the_verb_decides_which_side_is_the_box_s() {
        let args = |src: &str, dst: &str| crate::cli::CopyArgs {
            src: src.to_string(),
            dst: dst.to_string(),
            agent: crate::cli::AgentTimeoutArg {
                agent_timeout: None,
            },
        };
        assert_eq!(
            resolve_host_guest_paths(&args("./a.txt", "/tmp/a.txt"), Direction::IntoBox).unwrap(),
            ("./a.txt", "/tmp/a.txt")
        );
        assert_eq!(
            resolve_host_guest_paths(&args("/etc/os-release", "."), Direction::OutOfBox).unwrap(),
            (".", "/etc/os-release")
        );
        // A host path is whatever the shell handed over - `@`, `:` and all,
        // since nothing about it has to be told apart from a box any more.
        for host in ["./odd@name", "box:/legacy", "user@host", "-"] {
            assert_eq!(
                resolve_host_guest_paths(&args(host, "/tmp/x"), Direction::IntoBox).unwrap(),
                (host, "/tmp/x"),
                "{host}"
            );
        }
    }

    /// The box's side is absolute, because there is no cwd in the guest for a
    /// relative path to lean on - the agent would resolve it against a
    /// directory nobody on this end chose. Refused on whichever side the verb
    /// says is the guest's, naming the spelling that works.
    #[test]
    fn a_relative_guest_path_is_refused_on_whichever_side_it_is_on() {
        let args = |src: &str, dst: &str| crate::cli::CopyArgs {
            src: src.to_string(),
            dst: dst.to_string(),
            agent: crate::cli::AgentTimeoutArg {
                agent_timeout: None,
            },
        };
        // `put`: the destination is the guest's.
        let err = resolve_host_guest_paths(&args("./a.txt", "tmp/a.txt"), Direction::IntoBox)
            .unwrap_err()
            .to_string();
        assert!(err.contains("absolute path"), "{err}");
        assert!(err.contains("put ./local.txt"), "the spelling: {err}");

        // `get`: the source is, and the host side stays free to be relative.
        let err = resolve_host_guest_paths(&args("etc/os-release", "."), Direction::OutOfBox)
            .unwrap_err()
            .to_string();
        assert!(err.contains("absolute path"), "{err}");
        assert!(err.contains("get /etc/os-release"), "the spelling: {err}");

        // …and a relative *host* path is nobody's business but the shell's.
        assert!(
            resolve_host_guest_paths(&args("./a.txt", "/tmp/a.txt"), Direction::IntoBox).is_ok()
        );
        assert!(
            resolve_host_guest_paths(&args("/tmp/a.txt", "./a.txt"), Direction::OutOfBox).is_ok()
        );
    }
    /// The error text comes back from the guest too, and `terra put`/`get` prints it on
    /// a cooked terminal rather than inside a session the user asked to see - so
    /// an escape sequence in it must be printable, not run.
    #[test]
    fn a_guest_error_cannot_drive_the_host_terminal() {
        // An ordinary message is carried through unchanged.
        let plain = "No such file or directory (os error 2)";
        assert_eq!(sanitize_guest_error_message(plain), plain);

        // OSC (window title) and CSI (cursor movement, colour) are rendered.
        for raw in ["\x1b]0;pwned\x07", "\x1b[2J\x1b[H", "a\rterra: copied ok"] {
            let out = sanitize_guest_error_message(raw);
            assert!(!out.contains('\x1b'), "{out:?} still carries ESC");
            assert!(!out.contains('\r'), "{out:?} still carries CR");
            assert!(!out.contains('\x07'), "{out:?} still carries BEL");
        }

        // …and the guest does not choose how much scrollback an error takes.
        let flood = "x".repeat(MAX_GUEST_ERROR_MESSAGE * 4);
        let out = sanitize_guest_error_message(&flood);
        assert_eq!(out.chars().count(), MAX_GUEST_ERROR_MESSAGE + 1); // + the ellipsis
        assert!(out.ends_with('…'));
        // A message exactly at the limit is not marked as cut.
        let exact = "y".repeat(MAX_GUEST_ERROR_MESSAGE);
        assert_eq!(sanitize_guest_error_message(&exact), exact);
    }

    /// The mode comes back from the guest, which is the untrusted end: the exec
    /// bit is worth carrying, setuid is not - and neither is handing every other
    /// account on the host write access to the file that just came out.
    #[test]
    fn a_guest_cannot_hand_out_setuid_or_group_write_on_the_host() {
        assert_eq!(to_safe_mode(0o755), 0o755);
        assert_eq!(to_safe_mode(0o600), 0o600);
        assert_eq!(to_safe_mode(0o4755), 0o755); // setuid
        assert_eq!(to_safe_mode(0o2755), 0o755); // setgid
        assert_eq!(to_safe_mode(0o1777), 0o755); // sticky, and g+w/o+w with it
        assert_eq!(to_safe_mode(0o666), 0o644); // world-writable data file
        assert_eq!(to_safe_mode(u32::MAX), 0o755); // nothing else gets through
    }
}
