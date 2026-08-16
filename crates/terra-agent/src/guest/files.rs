//! The agent's file port: one `terra put`/`get` operation per connection.

use std::io::Read;
use std::os::fd::AsRawFd;
use std::path::Path;
use terra_agent::{FileReply, FileRequest, WORKLOAD_GID, WORKLOAD_UID};

/// Missing parents are created only once the path itself has been shown not to
/// traverse a link (a symlinked component answers `ELOOP` on the first
/// attempt). That check is check-time only: a parent swapped for a link
/// *between* the probe and the mkdir can mint empty directories on the far
/// side, but the re-open still refuses, so no file is ever written or chowned
/// through one.
fn create_no_symlinks(path: &str) -> std::io::Result<std::fs::File> {
    let open = || terra_agent::nofollow::create_no_symlinks_raw(Path::new(path));
    match open() {
        // Only a genuinely absent directory earns a retry - never `ELOOP`.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = std::path::Path::new(path).parent() {
                std::fs::create_dir_all(parent)?;
            }
            open()
        }
        other => other,
    }
}

/// Serve one `terra put`/`get`. A file written in goes to the workload user
/// unless the workload is root, mirroring how volumes are handed over; generic
/// over the transport so tests can drive it over a plain socketpair instead of
/// a vsock.
pub fn serve_file_op(mut conn: impl Read + std::io::Write, root: bool) {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    let reply = |conn: &mut dyn Write, rep: &FileReply| {
        if let Ok(f) = terra_agent::frame(rep) {
            let _ = conn.write_all(&f);
        }
    };
    let refuse = |conn: &mut dyn Write, err: String| reply(conn, &FileReply::Err(err));
    // A refused put still has to swallow the body the request announced. The
    // sender writes those bytes whatever we make of the path, and closing the
    // connection with them unread resets it - so the host would see "connection
    // reset by peer" in place of the reason we refused.
    let drain = |conn: &mut dyn Read, n: u64| {
        let _ = std::io::copy(&mut conn.take(n), &mut std::io::sink());
    };
    let Ok(req) = terra_agent::read_frame::<FileRequest>(&mut conn) else {
        return;
    };
    match req {
        FileRequest::Put { path, mode, size } => {
            if !path.starts_with('/') {
                drain(&mut conn, size);
                return refuse(&mut conn, "guest path must be absolute".into());
            }
            // Opened on its own, so a refusal is distinguishable from a transfer
            // that broke midway: nothing has been consumed yet, and the body can
            // still be drained.
            let written = match create_no_symlinks(&path) {
                Err(e) => {
                    drain(&mut conn, size);
                    Err(e)
                }
                Ok(mut file) => {
                    let copied =
                        std::io::copy(&mut std::io::Read::take(&mut conn, size), &mut file);
                    // Whatever went wrong, the sender is still writing the body it
                    // announced. Take the rest before replying, or a mid-copy
                    // ENOSPC reaches the host as "Broken pipe" from its own
                    // `write_all` - the reason substitution this drain prevents,
                    // in by far the most likely failure.
                    let consumed = *copied.as_ref().unwrap_or(&0);
                    drain(&mut conn, size.saturating_sub(consumed));
                    let result = copied.and_then(|copied| {
                        if copied != size {
                            return Err(std::io::Error::other(format!(
                                "short transfer: {copied} of {size} bytes"
                            )));
                        }
                        file.set_permissions(std::fs::Permissions::from_mode(mode))
                    });
                    // Through `fchown` on the descriptor already open, not a
                    // `chown` subprocess re-resolving the path. Best-effort:
                    // success depends on holding CAP_CHOWN over the backing file,
                    // which inside a virtiofs share depends on the host user
                    // namespace existing at all - and failing the put on it would
                    // report a copy that has already landed as an error.
                    if result.is_ok() && !root {
                        // SAFETY: `file` is a live descriptor we own for this call.
                        if unsafe { libc::fchown(file.as_raw_fd(), WORKLOAD_UID, WORKLOAD_GID) }
                            != 0
                        {
                            eprintln!(
                                "terra-agent: warning: could not give {path} to uid {WORKLOAD_UID}: {}",
                                std::io::Error::last_os_error()
                            );
                        }
                    }
                    result
                }
            };
            let rep = match written {
                Ok(()) => FileReply::Put,
                Err(e) => FileReply::Err(e.to_string()),
            };
            reply(&mut conn, &rep);
        }
        FileRequest::Get { path } => {
            if !path.starts_with('/') {
                return refuse(&mut conn, "guest path must be absolute".into());
            }
            // A plain open, deliberately: the put side's no-symlink open is not
            // wanted here, because reading follows a link to a file whose
            // contents the guest already chooses, so a workload gains no more
            // than it could have written into the file itself. And it costs the
            // ordinary case - the guest rootfs is full of honest symlinks
            // (`/etc/os-release -> ../usr/lib/os-release` in the image terra
            // ships, the example in `terra put --help`); what the *host* does
            // with the answer is where the guarantee lives (see
            // `sys::create_no_symlinks` and `copy::to_safe_mode`).
            let opened = std::fs::File::open(&path).and_then(|f| {
                let meta = f.metadata()?;
                if meta.is_dir() {
                    return Err(std::io::Error::other(
                        "is a directory (tar it through the shell, or use a mount)",
                    ));
                }
                Ok((f, meta.permissions().mode() & 0o7777, meta.len()))
            });
            match opened {
                Err(e) => refuse(&mut conn, e.to_string()),
                Ok((mut file, mode, size)) => {
                    // `copy` sends whatever the file holds now; a file that
                    // grew since the `stat` is truncated to the promise rather
                    // than overrunning it.
                    reply(&mut conn, &FileReply::Get { mode, size });
                    let _ = std::io::copy(&mut std::io::Read::take(&mut file, size), &mut conn);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;

    /// Run one request against [`serve_file_op`] over a socketpair, sending
    /// `body` after the frame; returns the reply and whatever bytes follow it.
    fn do_op(req: &FileRequest, body: &[u8]) -> (FileReply, Vec<u8>) {
        let (mut client, server) = UnixStream::pair().unwrap();
        let agent = std::thread::spawn(move || serve_file_op(server, true));
        client.write_all(&terra_agent::frame(req).unwrap()).unwrap();
        client.write_all(body).unwrap();
        let rep: FileReply = terra_agent::read_frame(&mut client).unwrap();
        let mut rest = Vec::new();
        client.read_to_end(&mut rest).unwrap(); // agent drops the conn at op end
        agent.join().unwrap();
        (rep, rest)
    }

    fn scratch(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("terra-agent-cp-{}-{name}", std::process::id()))
    }

    #[test]
    fn put_then_get_round_trips_bytes_and_mode() {
        let path = scratch("roundtrip.bin");
        let payload = b"#!/bin/sh\necho hi\n";

        let (rep, _) = do_op(
            &FileRequest::Put {
                path: path.to_string_lossy().into_owned(),
                mode: 0o751,
                size: payload.len() as u64,
            },
            payload,
        );
        assert_eq!(rep, FileReply::Put);
        assert_eq!(std::fs::read(&path).unwrap(), payload);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
            0o751
        );

        let (rep, bytes) = do_op(
            &FileRequest::Get {
                path: path.to_string_lossy().into_owned(),
            },
            &[],
        );
        // The exec bit travels back out, and the length ahead of the bytes so
        // the host reads exactly this file and stops rather than letting the
        // guest decide how much disk to fill.
        assert_eq!(
            rep,
            FileReply::Get {
                mode: 0o751,
                size: payload.len() as u64
            }
        );
        assert_eq!(bytes, payload);

        let _ = std::fs::remove_file(&path);
    }

    /// The put path runs as init - root in the guest - on a path the *workload*
    /// can have prepared: its own home, `/tmp`, a share, a volume. A symlink
    /// planted at the destination turned an ordinary `terra put` into a root write
    /// to wherever it pointed, and the mode and owner were applied by path after
    /// it. `/sbin/ip -> /bin/busybox` is the shape that matters: a binary PID 1
    /// goes on to exec as root.
    #[test]
    fn put_refuses_a_symlinked_destination() {
        let target = scratch("nofollow-target");
        let link = scratch("nofollow-link");
        std::fs::write(&target, b"original").unwrap();
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let (rep, _) = do_op(
            &FileRequest::Put {
                path: link.to_string_lossy().into_owned(),
                mode: 0o755,
                size: 5,
            },
            b"EVIL!",
        );
        assert!(
            matches!(rep, FileReply::Err(_)),
            "a symlinked destination must be refused"
        );
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"original",
            "the link was followed and its target overwritten"
        );

        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_file(&target);
    }

    /// The variant that leaf-only `O_NOFOLLOW` misses, and the one that actually
    /// escalates: the symlink is a *parent* of the destination, not the
    /// destination. `~/out -> /` turns an ordinary
    /// `terra dev put x /home/terri/out/y` into a root write at `/y`, which is
    /// then handed to the workload user. Both spellings must be refused -
    /// including the one where nothing needs creating, so `create_dir_all` is
    /// never even reached.
    #[test]
    fn put_refuses_a_symlinked_parent_directory() {
        let real = scratch("parent-real");
        let link = scratch("parent-link");
        let _ = std::fs::remove_dir_all(&real);
        let _ = std::fs::remove_file(&link);
        std::fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();

        // (a) the whole parent chain already exists - no directory creation at
        //     all, so only the open itself can refuse this.
        let direct = link.join("landed.txt");
        let (rep, _) = do_op(
            &FileRequest::Put {
                path: direct.to_string_lossy().into_owned(),
                mode: 0o644,
                size: 5,
            },
            b"EVIL!",
        );
        assert!(
            matches!(rep, FileReply::Err(_)),
            "a symlinked parent must be refused"
        );
        assert!(
            !real.join("landed.txt").exists(),
            "the write landed on the far side of the link"
        );

        // (b) …and with an intermediate directory missing, where `create_dir_all`
        //     would otherwise happily mkdir through the link first.
        let nested = link.join("sub/landed.txt");
        let (rep, _) = do_op(
            &FileRequest::Put {
                path: nested.to_string_lossy().into_owned(),
                mode: 0o644,
                size: 5,
            },
            b"EVIL!",
        );
        assert!(
            matches!(rep, FileReply::Err(_)),
            "a symlinked parent must be refused"
        );
        assert!(
            !real.join("sub").exists(),
            "directories were created through it"
        );

        // An ordinary nested put through real directories still works.
        let ok = real.join("fine/ok.txt");
        let (rep, _) = do_op(
            &FileRequest::Put {
                path: ok.to_string_lossy().into_owned(),
                mode: 0o644,
                size: 2,
            },
            b"hi",
        );
        assert_eq!(rep, FileReply::Put);
        assert_eq!(std::fs::read(&ok).unwrap(), b"hi");

        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_dir_all(&real);
    }

    #[test]
    fn put_creates_missing_parent_directories() {
        let dir = scratch("nested");
        let path = dir.join("a/b/file.txt");
        let (rep, _) = do_op(
            &FileRequest::Put {
                path: path.to_string_lossy().into_owned(),
                mode: 0o644,
                size: 2,
            },
            b"ok",
        );
        assert_eq!(rep, FileReply::Put);
        assert_eq!(std::fs::read(&path).unwrap(), b"ok");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn errors_come_back_as_replies() {
        // A relative path is refused before any transfer.
        let (rep, _) = do_op(
            &FileRequest::Put {
                path: "relative.txt".into(),
                mode: 0o644,
                size: 0,
            },
            &[],
        );
        let FileReply::Err(err) = rep else {
            panic!("expected an error: {rep:?}")
        };
        assert!(err.contains("absolute"));

        // A missing file on get reports rather than hangs.
        let (rep, bytes) = do_op(
            &FileRequest::Get {
                path: scratch("missing").to_string_lossy().into_owned(),
            },
            &[],
        );
        assert!(matches!(rep, FileReply::Err(_)), "{rep:?}");
        assert!(bytes.is_empty());

        // Directories are refused with the workaround in the message.
        let (rep, _) = do_op(&FileRequest::Get { path: "/".into() }, &[]);
        let FileReply::Err(err) = rep else {
            panic!("expected an error: {rep:?}")
        };
        assert!(err.contains("directory"));
    }
}
