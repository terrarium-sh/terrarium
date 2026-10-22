#![no_main]

//! Random guest create, rename, symlink and link sequences against a real share must leave
//! everything outside it untouched, checked after every operation so a change undone later
//! still fails.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use terra_runtime::test_support::FuzzShare;
use wasmtime::component::Component;

/// Compiled in this process: a prebuilt artifact would not match the sanitizer build.
const FS_COMPONENT: &[u8] =
    include_bytes!("../../components/target/wasm-components/release/terra_fs_component.wasm");

const NAMES: [&[u8]; 10] = [
    b"a",
    b"b",
    b"c",
    b"..",
    b".",
    b"a/b",
    b"outside",
    b"secret",
    b"directory",
    b"share",
];
const TARGETS: [&[u8]; 7] = [
    b"a",
    b"..",
    b"../..",
    b"../outside",
    b"../outside/secret",
    b"/",
    b"/etc",
];
const MAX_OPERATIONS: usize = 64;

#[derive(Arbitrary, Debug)]
enum Operation {
    Lookup {
        parent: u8,
        name: u8,
    },
    Mkdir {
        parent: u8,
        name: u8,
    },
    Create {
        parent: u8,
        name: u8,
    },
    Rename {
        parent: u8,
        name: u8,
        new_parent: u8,
        new_name: u8,
    },
    Symlink {
        parent: u8,
        name: u8,
        target: u8,
    },
    Link {
        node: u8,
        parent: u8,
        name: u8,
    },
    Unlink {
        parent: u8,
        name: u8,
    },
    Rmdir {
        parent: u8,
        name: u8,
    },
}

fn compiled_fs_component() -> &'static Result<(wasmtime::Engine, Component), String> {
    static COMPILED: OnceLock<Result<(wasmtime::Engine, Component), String>> = OnceLock::new();
    COMPILED.get_or_init(|| {
        let engine =
            terra_runtime::engine::device_engine().map_err(|error| format!("{error:#}"))?;
        let component =
            Component::new(&engine, FS_COMPONENT).map_err(|error| format!("{error:#}"))?;
        Ok((engine, component))
    })
}

fn pick<'a>(choices: &[&'a [u8]], index: u8) -> &'a [u8] {
    choices[usize::from(index) % choices.len()]
}

fn terminated(parts: &[&[u8]]) -> Vec<u8> {
    parts
        .iter()
        .flat_map(|part| [*part, b"\0"])
        .flatten()
        .copied()
        .collect()
}

/// Everything under `base` but the share's contents, without following links: names, inode,
/// link count, mode (with the file type), owner, mtime, and file bytes or link target.
fn snapshot(base: &Path, share: &Path) -> Vec<(PathBuf, String)> {
    let mut entries = Vec::new();
    let mut pending = vec![base.to_path_buf()];
    while let Some(path) = pending.pop() {
        let detail = match std::fs::symlink_metadata(&path) {
            Err(error) => format!("unreadable {:?}", error.kind()),
            Ok(_) if path == share => "share".to_owned(),
            Ok(metadata) => {
                let content = if metadata.file_type().is_symlink() {
                    format!(
                        "{:?}",
                        std::fs::read_link(&path).map_err(|error| error.kind())
                    )
                } else if metadata.is_dir() {
                    match std::fs::read_dir(&path) {
                        Ok(children) => {
                            pending.extend(children.flatten().map(|child| child.path()));
                            String::new()
                        }
                        Err(error) => format!("unlistable {:?}", error.kind()),
                    }
                } else {
                    format!("{:?}", std::fs::read(&path).map_err(|error| error.kind()))
                };
                format!(
                    "ino={} nlink={} mode={:o} owner={}:{} mtime={}.{} {content}",
                    metadata.ino(),
                    metadata.nlink(),
                    metadata.mode(),
                    metadata.uid(),
                    metadata.gid(),
                    metadata.mtime(),
                    metadata.mtime_nsec()
                )
            }
        };
        entries.push((path, detail));
    }
    entries.sort();
    entries
}

fuzz_target!(|operations: Vec<Operation>| {
    static RUN: AtomicU64 = AtomicU64::new(0);
    let base = std::env::temp_dir().join(format!(
        "terra-share-fuzz-{}-{}",
        std::process::id(),
        RUN.fetch_add(1, Ordering::Relaxed)
    ));
    let share_path = base.join("share");
    let outside = base.join("outside");
    assert!(std::fs::create_dir_all(&share_path).is_ok());
    assert!(std::fs::create_dir_all(outside.join("directory")).is_ok());
    assert!(std::fs::write(outside.join("secret"), b"secret").is_ok());
    let before = snapshot(&base, &share_path);
    let compiled = compiled_fs_component();
    assert!(compiled.is_ok(), "{:?}", compiled.as_ref().err());
    let Ok((engine, component)) = compiled else {
        return;
    };
    let mounted = FuzzShare::mount(engine, component, &share_path);
    assert!(mounted.is_ok(), "{:?}", mounted.err());
    let Ok(mut share) = mounted else {
        return;
    };
    let mut nodes = vec![1_u64];
    for operation in operations.iter().take(MAX_OPERATIONS) {
        let node = |index: u8| nodes[usize::from(index) % nodes.len()];
        let (opcode, parent, body) = match *operation {
            Operation::Lookup { parent, name } => {
                (1, node(parent), terminated(&[pick(&NAMES, name)]))
            }
            Operation::Mkdir { parent, name } => {
                let mut body = 0o755_u32.to_le_bytes().to_vec();
                body.extend([0; 4]);
                body.extend(terminated(&[pick(&NAMES, name)]));
                (9, node(parent), body)
            }
            Operation::Create { parent, name } => {
                let mut body = (0o100_u32 | 2).to_le_bytes().to_vec();
                body.extend(0o644_u32.to_le_bytes());
                body.extend([0; 8]);
                body.extend(terminated(&[pick(&NAMES, name)]));
                (35, node(parent), body)
            }
            Operation::Rename {
                parent,
                name,
                new_parent,
                new_name,
            } => {
                let mut body = node(new_parent).to_le_bytes().to_vec();
                body.extend(terminated(&[pick(&NAMES, name), pick(&NAMES, new_name)]));
                (12, node(parent), body)
            }
            Operation::Symlink {
                parent,
                name,
                target,
            } => (
                6,
                node(parent),
                terminated(&[pick(&NAMES, name), pick(&TARGETS, target)]),
            ),
            Operation::Link {
                node: linked,
                parent,
                name,
            } => {
                let mut body = node(linked).to_le_bytes().to_vec();
                body.extend(terminated(&[pick(&NAMES, name)]));
                (13, node(parent), body)
            }
            Operation::Unlink { parent, name } => {
                (10, node(parent), terminated(&[pick(&NAMES, name)]))
            }
            Operation::Rmdir { parent, name } => {
                (11, node(parent), terminated(&[pick(&NAMES, name)]))
            }
        };
        let reply = share.request(opcode, parent, &body);
        assert!(reply.is_ok(), "{:?}", reply.err());
        let Ok(reply) = reply else {
            return;
        };
        assert_eq!(snapshot(&base, &share_path), before, "after {operation:?}");
        let is_entry = matches!(opcode, 1 | 6 | 9 | 13 | 35);
        if is_entry
            && reply.get(4..8) == Some(&[0; 4])
            && let Some(Ok(entry)) = reply.get(16..24).map(<[u8; 8]>::try_from)
        {
            nodes.push(u64::from_le_bytes(entry));
        }
    }
    let closed = share.close();
    assert!(closed.is_ok(), "{:?}", closed.err());
    assert_eq!(snapshot(&base, &share_path), before);
    let _ = std::fs::remove_dir_all(&base);
});
