//! `terra <box> put` and `terra <box> get` - one file into or out of a running
//! box, over the agent's file port. The guest end is untrusted: every bound and
//! timeout below is there because a workload controls what comes back.

use crate::sys;
use anyhow::{Context, Result};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};
use terra_agent::{FileReply, FileRequest};

const MAX_GUEST_CLAIMED_BYTES: u64 = 8 << 30;

const COPY_STALL_TIMEOUT: Duration = Duration::from_mins(1);

const COPY_TOTAL_TIMEOUT: Duration = Duration::from_hours(1);

/// Copy one file into or out of a running box
// ponytail: single files only. Directories would put an archive format on the
// wire; a mount or `tar` through the shell covers that today.
pub fn run(
    args: &crate::cli::CopyArgs,
    direction: Direction,
    name: Option<&str>,
    project_dir: &Path,
) -> Result<ExitCode> {
    let (host, guest) = host_guest_paths(args, direction)?;
    let bx = &crate::resolve::resolve_pinned_box(project_dir, name)?;
    // The file service answers only once the workload is up - after every
    // mount, `on_create` bake and `on_start` hook.
    let mut stream = crate::session::connect_to_running_agent(
        bx,
        direction.verb(),
        terra_agent::AgentService::Files,
        "file service",
        args.agent.agent_timeout,
    )?;
    let _ = stream.set_read_timeout(Some(COPY_STALL_TIMEOUT));
    let _ = stream.set_write_timeout(Some(COPY_STALL_TIMEOUT));
    let deadline = Instant::now() + COPY_TOTAL_TIMEOUT;

    match direction {
        Direction::IntoBox => send_file_into_box(&mut stream, host, guest, deadline),
        Direction::OutOfBox => fetch_file_from_box(&mut stream, guest, host, deadline),
    }
}

fn send_request(stream: &mut impl Write, req: &FileRequest) -> Result<()> {
    stream
        .write_all(&terra_agent::frame(req).context("encoding the request")?)
        .context("sending the request")
}

fn read_reply(stream: &mut impl Read) -> Result<FileReply> {
    match terra_agent::read_frame(stream).context("reading the agent's reply")? {
        FileReply::Err(err) => anyhow::bail!("guest: {}", sanitize_guest_error_message(&err)),
        answered => Ok(answered),
    }
}

fn mismatched_reply(asked: &str) -> anyhow::Error {
    anyhow::anyhow!("the agent answered a {asked} request with another kind of reply")
}

fn copy_at_most(
    from: &mut impl Read,
    to: &mut impl Write,
    size: u64,
    what: &str,
    deadline: Instant,
) -> Result<u64> {
    let mut buf = [0u8; 16 * 1024];
    let mut sent = 0u64;
    while sent < size {
        if Instant::now() >= deadline {
            anyhow::bail!(
                "{what} ran past its {}s overall limit - the other end kept the \
                 transfer open without finishing it",
                COPY_TOTAL_TIMEOUT.as_secs()
            );
        }
        // Never past what remains: some sources here never EOF (the padding's
        // `io::repeat`).
        let want = usize::min(buf.len(), usize::try_from(size - sent).unwrap_or(0));
        let n = from.read(&mut buf[..want]).context(what.to_string())?;
        if n == 0 {
            break;
        }
        to.write_all(&buf[..n]).context(what.to_string())?;
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
    let sent = copy_at_most(body, stream, size, "sending the file", deadline)?;
    if sent < size {
        copy_at_most(
            &mut std::io::repeat(0),
            stream,
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
    let mut file = sys::open_no_symlinks(Path::new(host_path))
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
    send_request(
        stream,
        &FileRequest::Put {
            path: guest_path.to_string(),
            mode: to_guest_mode(&meta),
            size,
        },
    )?;
    let sent = send_body_padded_to_size(&mut file, stream, size, deadline)?;

    match read_reply(stream)? {
        FileReply::Put => {}
        _ => return Err(mismatched_reply("put")),
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
    send_request(
        stream,
        &FileRequest::Get {
            path: guest_path.to_string(),
        },
    )?;
    let FileReply::Get { mode, size } = read_reply(stream)? else {
        return Err(mismatched_reply("get"));
    };
    anyhow::ensure!(
        size <= MAX_GUEST_CLAIMED_BYTES,
        "{guest_path} says it is {size} bytes, past the {} GiB copy ceiling \
         (share a directory instead - a copy is for single files)",
        MAX_GUEST_CLAIMED_BYTES >> 30
    );

    let mut dst_path = PathBuf::from(host_path);
    if std::fs::symlink_metadata(&dst_path).is_ok_and(|m| m.is_dir()) {
        let name = Path::new(guest_path)
            .file_name()
            .context("guest path has no file name")?;
        dst_path.push(name);
    }
    let mut file = sys::create_no_symlinks(&dst_path)
        .with_context(|| format!("creating {}", dst_path.display()))?;

    let received = copy_at_most(stream, &mut file, size, "receiving the file", deadline)?;
    anyhow::ensure!(
        received == size,
        "{guest_path} ended after {received} of {size} promised bytes; {} holds the \
         truncated copy - copy it again",
        dst_path.display()
    );
    sys::set_open_file_mode(&file, to_safe_mode(mode))
        .with_context(|| format!("setting permissions on {}", dst_path.display()))?;
    Ok(report(
        guest_path,
        &dst_path.display().to_string(),
        received,
    ))
}

const MAX_GUEST_ERROR_MESSAGE: usize = 512;

fn sanitize_guest_error_message(err: &str) -> String {
    let mut out = crate::render::printable(
        &err.chars()
            .take(MAX_GUEST_ERROR_MESSAGE)
            .collect::<String>(),
    );
    if err.chars().nth(MAX_GUEST_ERROR_MESSAGE).is_some() {
        out.push('…');
    }
    out
}

/// The permission bits a copy carries into the box: rwx - setuid, setgid and
/// sticky stay on the host.
fn to_guest_mode(meta: &std::fs::Metadata) -> u32 {
    sys::mode_of(meta) & 0o777
}

/// The permission bits a guest-supplied mode may set on a host file: rwx,
/// minus group and other write - a setuid bit would leave a setuid file owned
/// by whoever ran the copy, and group or world write lets any account rewrite
/// it before it is run.
fn to_safe_mode(guest_mode: u32) -> u32 {
    guest_mode & 0o777 & !0o022
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Direction {
    IntoBox,
    OutOfBox,
}

impl Direction {
    fn verb(self) -> &'static str {
        match self {
            Direction::IntoBox => "put",
            Direction::OutOfBox => "get",
        }
    }

    fn working_spelling(self) -> &'static str {
        match self {
            Direction::IntoBox => "put ./local.txt /tmp/remote.txt",
            Direction::OutOfBox => "get /etc/os-release ./os-release",
        }
    }
}

fn host_guest_paths(args: &crate::cli::CopyArgs, direction: Direction) -> Result<(&str, &str)> {
    let (host, guest) = match direction {
        Direction::IntoBox => (&args.src, &args.dst),
        Direction::OutOfBox => (&args.dst, &args.src),
    };
    anyhow::ensure!(
        guest.starts_with('/'),
        "the box's side of a copy is an absolute path, and '{guest}' is not \
         (`terra <box> {}`)",
        direction.working_spelling()
    );
    Ok((host, guest))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deadline far enough out that no test transfer trips it.
    fn deadline() -> Instant {
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

    fn get_reply(size: u64, body: &[u8]) -> GuestEnd {
        let mut script =
            terra_agent::frame(&terra_agent::FileReply::Get { mode: 0o644, size }).unwrap();
        script.extend_from_slice(body);
        GuestEnd(std::io::Cursor::new(script))
    }

    /// A guest that closes the stream short of the promised length must not be
    /// reported as a completed copy: the stream ending is a clean EOF, so no
    /// timeout fires, and success here would let a workload fake a full export.
    #[test]
    fn a_fetch_file_from_box_cut_short_is_an_error_not_a_success() {
        let dir = tempfile::tempdir().unwrap();
        let dst = dir.path().join("out.bin");
        let dst_str = dst.to_str().unwrap();

        let err = fetch_file_from_box(
            &mut get_reply(8, b"1234"),
            "/data/out.bin",
            dst_str,
            deadline(),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("4 of 8"), "{err}");
        assert!(err.contains("truncated"), "{err}");

        // The full transfer still succeeds, byte for byte.
        fetch_file_from_box(
            &mut get_reply(8, b"12345678"),
            "/data/out.bin",
            dst_str,
            deadline(),
        )
        .unwrap();
        assert_eq!(std::fs::read(&dst).unwrap(), b"12345678");
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
            deadline(),
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
            deadline(),
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
            deadline(),
        )
        .unwrap();
        assert_eq!((sent, bounded.as_slice()), (8, b"12345678".as_slice()));
    }

    /// One byte at a time, forever: the stall timeout cannot see this - every
    /// syscall lands well inside it - so the overall limit is what ends the
    /// copy instead of letting the guest hold it open indefinitely.
    #[test]
    fn a_transfer_past_its_overall_deadline_fails_rather_than_trickling_forever() {
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
            &mut sink,
            100,
            "receiving the file",
            Instant::now(),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("overall limit"), "{err}");
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
            host_guest_paths(&args("./a.txt", "/tmp/a.txt"), Direction::IntoBox).unwrap(),
            ("./a.txt", "/tmp/a.txt")
        );
        assert_eq!(
            host_guest_paths(&args("/etc/os-release", "."), Direction::OutOfBox).unwrap(),
            (".", "/etc/os-release")
        );
        // A host path is whatever the shell handed over - `@`, `:` and all,
        // since nothing about it has to be told apart from a box any more.
        for host in ["./odd@name", "box:/legacy", "user@host", "-"] {
            assert_eq!(
                host_guest_paths(&args(host, "/tmp/x"), Direction::IntoBox).unwrap(),
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
        let err = host_guest_paths(&args("./a.txt", "tmp/a.txt"), Direction::IntoBox)
            .unwrap_err()
            .to_string();
        assert!(err.contains("absolute path"), "{err}");
        assert!(err.contains("put ./local.txt"), "the spelling: {err}");

        // `get`: the source is, and the host side stays free to be relative.
        let err = host_guest_paths(&args("etc/os-release", "."), Direction::OutOfBox)
            .unwrap_err()
            .to_string();
        assert!(err.contains("absolute path"), "{err}");
        assert!(err.contains("get /etc/os-release"), "the spelling: {err}");

        // …and a relative *host* path is nobody's business but the shell's.
        assert!(host_guest_paths(&args("./a.txt", "/tmp/a.txt"), Direction::IntoBox).is_ok());
        assert!(host_guest_paths(&args("/tmp/a.txt", "./a.txt"), Direction::OutOfBox).is_ok());
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
