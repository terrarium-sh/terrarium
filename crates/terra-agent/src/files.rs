//! The agent's file port: one file transfer operation per connection.

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use terra_shared::contract::{
    FileReply, FileRequest, MAX_FILE_BYTES, WORKLOAD_ID, encode_frame, read_frame,
};

struct PreparedPut {
    file: std::fs::File,
    parent: std::fs::File,
    temp_name: std::ffi::OsString,
    destination_name: std::ffi::OsString,
}

fn generate_random_temp_name() -> std::io::Result<std::ffi::OsString> {
    let mut random = [0u8; 16];
    rustix::rand::getrandom(&mut random, rustix::rand::GetRandomFlags::empty())?;
    let mut name = String::with_capacity(32);
    for byte in random {
        let _ = write!(name, "{byte:02x}");
    }
    Ok(std::ffi::OsString::from(format!(".terra-put-{name}")))
}

fn create_put_temp(path: &Path) -> std::io::Result<PreparedPut> {
    use rustix::fs::{Mode, OFlags};
    let parent_path = path
        .parent()
        .ok_or_else(|| std::io::Error::other("destination has no parent directory"))?;
    let destination = path
        .file_name()
        .ok_or_else(|| std::io::Error::other("destination has no file name"))?
        .to_owned();
    let parent = terra_shared::no_symlinks::open_no_symlinks(
        parent_path,
        terra_shared::no_symlinks::OpenMode::ReadDirectory,
    )?;
    let temp = generate_random_temp_name()?;
    let file = rustix::fs::openat(
        &parent,
        &temp,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o600),
    )?;
    Ok(PreparedPut {
        file: file.into(),
        parent,
        temp_name: temp,
        destination_name: destination,
    })
}

fn prepare_put(path: &Path, workload_is_root: bool) -> std::io::Result<PreparedPut> {
    match create_put_temp(path) {
        Ok(prepared) => Ok(prepared),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = path.parent().unwrap_or(path);
            ensure_directory(parent, !workload_is_root)?;
            create_put_temp(path)
        }
        Err(error) => Err(error),
    }
}

pub(crate) fn ensure_directory(path: &Path, give_to_workload: bool) -> std::io::Result<()> {
    use rustix::fs::{Mode, OFlags};
    match terra_shared::no_symlinks::open_no_symlinks(
        path,
        terra_shared::no_symlinks::OpenMode::ReadDirectory,
    ) {
        Ok(_) => return Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let mut missing = Vec::new();
    let mut parent = 'ancestors: {
        for ancestor in path.ancestors() {
            match terra_shared::no_symlinks::open_no_symlinks(
                ancestor,
                terra_shared::no_symlinks::OpenMode::ReadDirectory,
            ) {
                Ok(handle) => break 'ancestors handle,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    missing.push(ancestor.to_owned());
                }
                Err(error) => return Err(error),
            }
        }
        return Err(std::io::Error::other("no existing parent directory"));
    };
    for dir in missing.into_iter().rev() {
        let name = dir
            .file_name()
            .ok_or_else(|| std::io::Error::other("missing parent has no name"))?;
        rustix::fs::mkdirat(&parent, name, Mode::from_raw_mode(0o755)).or_else(|error| {
            (error == rustix::io::Errno::EXIST)
                .then_some(())
                .ok_or(error)
        })?;
        parent = rustix::fs::openat(
            &parent,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW,
            Mode::empty(),
        )?
        .into();
        if give_to_workload {
            rustix::fs::fchown(
                &parent,
                Some(rustix::process::Uid::from_raw(WORKLOAD_ID)),
                Some(rustix::process::Gid::from_raw(WORKLOAD_ID)),
            )?;
        }
    }
    Ok(())
}

fn open_regular_file(path: &str) -> std::io::Result<(std::fs::File, u32, u64)> {
    let file = terra_shared::no_symlinks::open_no_symlinks(
        Path::new(path),
        terra_shared::no_symlinks::OpenMode::ReadNonblocking,
    )?;
    let meta = file.metadata()?;
    if meta.is_dir() {
        return Err(std::io::Error::other(
            "is a directory (tar it through the shell, or use a mount)",
        ));
    }
    if !meta.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    if meta.len() > MAX_FILE_BYTES {
        return Err(std::io::Error::other(format!(
            "file is larger than the {MAX_FILE_BYTES}-byte limit"
        )));
    }
    Ok((file, meta.permissions().mode() & 0o7777, meta.len()))
}

fn discard_bytes(conn: &mut impl Read, size: u64) {
    let _ = std::io::copy(&mut conn.take(size), &mut std::io::sink());
}

fn send_reply(conn: &mut impl Write, reply: &FileReply) {
    if let Ok(frame) = encode_frame(reply) {
        let _ = conn.write_all(&frame);
    }
}

fn receive_put(
    conn: &mut (impl Read + Write),
    path: &str,
    mode: u32,
    size: u64,
    workload_is_root: bool,
) -> std::io::Result<()> {
    if size > MAX_FILE_BYTES {
        return Err(std::io::Error::other(format!(
            "file is larger than the {MAX_FILE_BYTES}-byte limit"
        )));
    }

    let destination = Path::new(path);
    let PreparedPut {
        mut file,
        parent,
        temp_name,
        destination_name,
    } = match prepare_put(destination, workload_is_root) {
        Ok(prepared) => prepared,
        Err(error) => {
            discard_bytes(conn, size);
            return Err(error);
        }
    };

    let (copied, remaining) = {
        let mut limited = std::io::Read::take(&mut *conn, size);
        let copied = std::io::copy(&mut limited, &mut file);
        (copied, limited.limit())
    };
    discard_bytes(conn, remaining);

    let result = copied.and_then(|copied| {
        if copied != size {
            return Err(std::io::Error::other(format!(
                "short transfer: {copied} of {size} bytes"
            )));
        }
        if !workload_is_root {
            rustix::fs::fchown(
                &file,
                Some(rustix::process::Uid::from_raw(WORKLOAD_ID)),
                Some(rustix::process::Gid::from_raw(WORKLOAD_ID)),
            )
            .map_err(std::io::Error::from)?;
        }
        file.set_permissions(std::fs::Permissions::from_mode(mode & 0o777))?;
        drop(file);
        rustix::fs::renameat(&parent, &temp_name, &parent, &destination_name)
            .map_err(std::io::Error::from)
    });
    let _ = rustix::fs::unlinkat(&parent, &temp_name, rustix::fs::AtFlags::empty());
    result
}

/// Handles one file operation, handing PUT files to the workload user unless `workload_is_root` is set.
pub fn serve_file_op(mut conn: impl Read + Write, workload_is_root: bool) {
    let Ok(Some(req)) = read_frame::<FileRequest>(&mut conn) else {
        return;
    };
    match req {
        FileRequest::Put { path, mode, size } => {
            let reply = match receive_put(&mut conn, &path, mode, size, workload_is_root) {
                Ok(()) => FileReply::Put,
                Err(error) => FileReply::Err(error.to_string()),
            };
            send_reply(&mut conn, &reply);
        }
        FileRequest::Get { path } => match open_regular_file(&path) {
            Err(error) => send_reply(&mut conn, &FileReply::Err(error.to_string())),
            Ok((mut file, mode, size)) => {
                send_reply(&mut conn, &FileReply::Get { mode, size });
                let _ = std::io::copy(&mut std::io::Read::take(&mut file, size), &mut conn);
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    fn run_file_operation(req: &FileRequest, body: &[u8]) -> (FileReply, Vec<u8>) {
        let mut input = terra_shared::contract::encode_frame(req).unwrap();
        input.extend_from_slice(body);
        let mut conn = TestConn {
            input: std::io::Cursor::new(input),
            output: Vec::new(),
        };
        serve_file_op(&mut conn, true);
        let mut output = std::io::Cursor::new(conn.output);
        let rep: FileReply = terra_shared::contract::read_frame(&mut output)
            .unwrap()
            .unwrap();
        let mut rest = Vec::new();
        std::io::Read::read_to_end(&mut output, &mut rest).unwrap();
        (rep, rest)
    }

    struct TestConn {
        input: std::io::Cursor<Vec<u8>>,
        output: Vec<u8>,
    }

    impl std::io::Read for TestConn {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let read = std::io::Read::read(&mut self.input, buf)?;
            if read == 0 {
                Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
            } else {
                Ok(read)
            }
        }
    }

    impl std::io::Write for TestConn {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.output.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn create_scratch_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("terra-agent-cp-{}-{name}", std::process::id()))
    }

    #[test]
    fn put_then_get_round_trips_bytes_and_mode_without_special_bits() {
        let path = create_scratch_path("roundtrip.bin");
        let payload = b"#!/bin/sh\necho hi\n";

        let (rep, _) = run_file_operation(
            &FileRequest::Put {
                path: path.to_string_lossy().into_owned(),
                mode: 0o6751,
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

        let (rep, bytes) = run_file_operation(
            &FileRequest::Get {
                path: path.to_string_lossy().into_owned(),
            },
            &[],
        );
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

    /// Replacing a symlink must not write through to its target.
    #[test]
    fn put_replaces_a_symlink_without_following_it() {
        let target = create_scratch_path("nofollow-target");
        let link = create_scratch_path("nofollow-link");
        std::fs::write(&target, b"original").unwrap();
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let (rep, _) = run_file_operation(
            &FileRequest::Put {
                path: link.to_string_lossy().into_owned(),
                mode: 0o755,
                size: 5,
            },
            b"EVIL!",
        );
        assert_eq!(rep, FileReply::Put);
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"original",
            "the symlink target was overwritten"
        );
        assert_eq!(std::fs::read(&link).unwrap(), b"EVIL!");

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
        let real = create_scratch_path("parent-real");
        let link = create_scratch_path("parent-link");
        let _ = std::fs::remove_dir_all(&real);
        let _ = std::fs::remove_file(&link);
        std::fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let direct = link.join("landed.txt");
        let (rep, _) = run_file_operation(
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

        let nested = link.join("sub/landed.txt");
        let (rep, _) = run_file_operation(
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

        let ok = real.join("fine/ok.txt");
        let (rep, _) = run_file_operation(
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

    /// Replacing a hard-linked destination must not overwrite the linked inode.
    #[test]
    fn put_replaces_a_hard_link_without_overwriting_the_inode() {
        let target = create_scratch_path("hardlink-target");
        let dest = create_scratch_path("hardlink-dest");
        let _ = std::fs::remove_file(&target);
        let _ = std::fs::remove_file(&dest);
        std::fs::write(&target, b"original").unwrap();
        std::fs::hard_link(&target, &dest).unwrap();

        let (rep, _) = run_file_operation(
            &FileRequest::Put {
                path: dest.to_string_lossy().into_owned(),
                mode: 0o644,
                size: 5,
            },
            b"EVIL!",
        );
        assert_eq!(rep, FileReply::Put);
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"original",
            "the linked inode was overwritten"
        );
        assert_eq!(std::fs::read(&dest).unwrap(), b"EVIL!");

        std::fs::remove_file(&dest).unwrap();
        let (rep, _) = run_file_operation(
            &FileRequest::Put {
                path: target.to_string_lossy().into_owned(),
                mode: 0o644,
                size: 2,
            },
            b"ok",
        );
        assert_eq!(rep, FileReply::Put);
        assert_eq!(std::fs::read(&target).unwrap(), b"ok");
    }

    #[test]
    fn short_put_keeps_the_original_destination() {
        let path = create_scratch_path("short.bin");
        std::fs::write(&path, b"original").unwrap();

        let (rep, _) = run_file_operation(
            &FileRequest::Put {
                path: path.to_string_lossy().into_owned(),
                mode: 0o644,
                size: 8,
            },
            b"short",
        );
        assert!(matches!(rep, FileReply::Err(_)), "{rep:?}");
        assert_eq!(std::fs::read(&path).unwrap(), b"original");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn put_creates_missing_parent_directories() {
        let dir = create_scratch_path("nested");
        let path = dir.join("a/b/file.txt");
        let (rep, _) = run_file_operation(
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
    fn random_temp_suffix_has_fixed_hex_shape() {
        let name = generate_random_temp_name().unwrap().into_string().unwrap();
        let suffix = name.strip_prefix(".terra-put-").unwrap();
        assert_eq!(suffix.len(), 32);
        assert!(suffix.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }

    #[test]
    fn errors_come_back_as_replies() {
        let (rep, bytes) = run_file_operation(
            &FileRequest::Get {
                path: create_scratch_path("missing")
                    .to_string_lossy()
                    .into_owned(),
            },
            &[],
        );
        assert!(matches!(rep, FileReply::Err(_)), "{rep:?}");
        assert!(bytes.is_empty());

        let (rep, _) = run_file_operation(&FileRequest::Get { path: "/".into() }, &[]);
        let FileReply::Err(err) = rep else {
            panic!("expected an error: {rep:?}")
        };
        assert!(err.contains("directory"));

        let (rep, _) = run_file_operation(
            &FileRequest::Get {
                path: "/dev/null".into(),
            },
            &[],
        );
        assert!(matches!(rep, FileReply::Err(_)), "{rep:?}");
    }
}
