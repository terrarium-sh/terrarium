use super::io::PreparedIo;
use super::{
    MAX_DIRECTORIES, MAX_READ, OpenDirectory, State, attr_out, clear_node_path, clear_runtime,
    create_flags, directory, dirents, entry, flush_body, handle, host, host_error,
    increment_lookup, mark_unused_if_unheld, name, names, node, node_id, open, open_flags,
    read_file, rename_mode, repoint_node, sized_out, statfs, store_handle, symlink_parts,
    timestamp, u32_at, u64_at, wasi_error, wire, write_file,
};
use futures::FutureExt;
use wire::Request;

pub(super) fn execute_immediate(
    state: &mut State,
    request: &Request<'_>,
) -> Option<Result<Vec<u8>, i32>> {
    Some(match request.opcode {
        wire::INIT => wire::init(request.body).inspect(|body| {
            clear_runtime(state);
            state.events_enabled = u32_at(body, 32).unwrap_or(0) & wire::FILE_EVENTS != 0;
        }),
        wire::CANCEL_EVENTS => Ok(Vec::new()),
        wire::RELEASE => release_file(state, request),
        wire::RELEASEDIR => Ok(release_directory(state, request)),
        wire::FLUSH => flush_body(request.body).map(|()| Vec::new()),
        21..=24 | 31..=33 | 43 | 46 | 50 => Err(95),
        wire::GETATTR
        | wire::LOOKUP
        | wire::READLINK
        | wire::SETATTR
        | wire::MKDIR
        | wire::CREATE
        | wire::UNLINK
        | wire::RMDIR
        | wire::RENAME
        | wire::RENAME2
        | wire::LINK
        | wire::SYMLINK
        | wire::OPEN
        | wire::OPENDIR
        | wire::READDIR
        | wire::STATFS
        | wire::READ
        | wire::WRITE
        | wire::FSYNC
        | wire::FSYNCDIR => {
            return None;
        }
        _ => Err(wire::ENOSYS),
    })
}

#[derive(Clone, Copy)]
pub(super) struct RequestState(pub u64);

impl RequestState {
    pub fn with<T>(self, operation: impl FnOnce(&mut State) -> Result<T, i32>) -> Result<T, i32> {
        let mut state = super::STATE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if super::generation().ok() != Some(self.0) {
            return Err(5);
        }
        operation(state.as_mut().ok_or(5)?)
    }
}

async fn execute(state: RequestState, request: &Request<'_>) -> Result<Vec<u8>, i32> {
    match request.opcode {
        wire::GETATTR => Ok(attr_out(
            &request_node(state, request.node)?
                .stat()
                .await
                .map_err(host_error)?,
        )),
        wire::LOOKUP => lookup_entry(state, request).await,
        wire::READLINK => request_node(state, request.node)?
            .readlink()
            .await
            .map_err(host_error),
        wire::SETATTR => set_attributes(state, request).await,
        wire::MKDIR => create_directory(state, request).await,
        wire::CREATE => create_file(state, request).await,
        wire::UNLINK | wire::RMDIR => remove_entry(state, request).await,
        wire::RENAME | wire::RENAME2 => rename_entry(state, request).await,
        wire::LINK => link_entry(state, request).await,
        wire::SYMLINK => create_symlink(state, request).await,
        wire::OPEN => open_file(state, request).await,
        wire::OPENDIR => open_directory(state, request).await,
        wire::READDIR => read_directory(state, request).await,
        wire::STATFS => Ok(statfs(
            &request_node(state, request.node)?
                .statfs()
                .await
                .map_err(host_error)?,
        )),
        _ => Err(wire::ENOSYS),
    }
}

fn request_node(state: RequestState, id: u64) -> Result<host::Node, i32> {
    state.with(|state| node(state, id).cloned().map_err(|_| 2))
}

async fn insert_entry(state: RequestState, child: host::Node) -> Result<Vec<u8>, i32> {
    let stat = child.stat().await.map_err(host_error)?;
    let inode = state.with(|state| node_id(state, child, &stat))?;
    Ok(entry(&stat, inode))
}

async fn lookup_entry(state: RequestState, request: &Request<'_>) -> Result<Vec<u8>, i32> {
    let name = name(request.body)?;
    let parent = request_node(state, request.node)?;
    let child = host::lookup(&parent, name).await.map_err(host_error)?;
    insert_entry(state, child).await
}

async fn set_attributes(state: RequestState, request: &Request<'_>) -> Result<Vec<u8>, i32> {
    let valid = u32_at(request.body, 0)?;
    let size = u64_at(request.body, 16)?;
    let atime = timestamp(u64_at(request.body, 32)?, u32_at(request.body, 56)?);
    let mtime = timestamp(u64_at(request.body, 40)?, u32_at(request.body, 60)?);
    let mode = u32_at(request.body, 68)?;
    let uid = u32_at(request.body, 76)?;
    let gid = u32_at(request.body, 80)?;
    let node = request_node(state, request.node)?;
    node.setattr(
        (valid & 1 != 0).then_some(mode),
        (valid & 8 != 0).then_some(size),
        (valid & 16 != 0).then_some(atime),
        (valid & 32 != 0).then_some(mtime),
        (valid & 2 != 0).then_some(uid),
        (valid & 4 != 0).then_some(gid),
    )
    .await
    .map_err(host_error)?;
    Ok(attr_out(&node.stat().await.map_err(host_error)?))
}

async fn create_directory(state: RequestState, request: &Request<'_>) -> Result<Vec<u8>, i32> {
    let mode = u32_at(request.body, 0)?;
    let name = name(request.body.get(8..).unwrap_or_default())?;
    let child = host::mkdir(&request_node(state, request.node)?, name, mode)
        .await
        .map_err(host_error)?;
    insert_entry(state, child).await
}

async fn create_file(state: RequestState, request: &Request<'_>) -> Result<Vec<u8>, i32> {
    let flags = u32_at(request.body, 0)?;
    let mode = u32_at(request.body, 4)?;
    let name = name(request.body.get(16..).unwrap_or_default())?;
    let parent = request_node(state, request.node)?;
    let (child, descriptor) = host::create(&parent, name, create_flags(flags)?, mode)
        .await
        .map_err(host_error)?;
    let stat = child.stat().await.map_err(host_error)?;
    let inode = state.with(|state| node_id(state, child, &stat))?;
    let handle = state.with(|state| store_handle(state, inode, descriptor, flags & 3 != 0))?;
    let mut out = entry(&stat, inode);
    out.extend_from_slice(&open(handle));
    Ok(out)
}

async fn remove_entry(state: RequestState, request: &Request<'_>) -> Result<Vec<u8>, i32> {
    let name = name(request.body)?;
    let parent = request_node(state, request.node)?;
    let removed_stat = match host::lookup(&parent, name.clone()).await {
        Ok(removed) => removed.stat().await.ok(),
        Err(_) => None,
    };
    host::unlink(&parent, name, request.opcode == wire::RMDIR)
        .await
        .map_err(host_error)?;
    if let Some(stat) = removed_stat {
        state.with(|state| {
            clear_node_path(state, &stat);
            Ok(())
        })?;
    }
    Ok(Vec::new())
}

async fn rename_entry(state: RequestState, request: &Request<'_>) -> Result<Vec<u8>, i32> {
    let new_parent_id = u64_at(request.body, 0)?;
    let offset = if request.opcode == wire::RENAME2 {
        16
    } else {
        8
    };
    let (old_name, new_name) = names(request.body.get(offset..).unwrap_or_default())?;
    let flags = if request.opcode == wire::RENAME2 {
        u32_at(request.body, 8)?
    } else {
        0
    };
    let mode = rename_mode(flags)?;
    let old_parent = request_node(state, request.node)?;
    let new_parent = request_node(state, new_parent_id)?;
    let new_parent_descriptor = new_parent.clone_descriptor().map_err(host_error)?;
    let replaced_stat = match host::lookup(&new_parent, new_name.clone()).await {
        Ok(replaced) => replaced.stat().await.ok(),
        Err(_) => None,
    };
    let renamed = host::lookup(&old_parent, old_name.clone())
        .await
        .map_err(host_error)?;
    let stat = renamed.stat().await.map_err(host_error)?;
    host::rename(&old_parent, old_name, &new_parent, new_name.clone(), mode)
        .await
        .map_err(host_error)?;
    state.with(|state| {
        repoint_node(state, &stat, new_parent_descriptor, new_name);
        Ok(())
    })?;
    if let Some(replaced_stat) = replaced_stat
        && (replaced_stat.dev, replaced_stat.ino) != (stat.dev, stat.ino)
    {
        state.with(|state| {
            clear_node_path(state, &replaced_stat);
            Ok(())
        })?;
    }
    Ok(Vec::new())
}

async fn link_entry(state: RequestState, request: &Request<'_>) -> Result<Vec<u8>, i32> {
    let old_inode = u64_at(request.body, 0)?;
    let name = name(request.body.get(8..).unwrap_or_default())?;
    let old = request_node(state, old_inode)?;
    host::link(&old, &request_node(state, request.node)?, name)
        .await
        .map_err(host_error)?;
    let stat = old.stat().await.map_err(host_error)?;
    state.with(|state| {
        increment_lookup(state, old_inode);
        Ok(())
    })?;
    Ok(entry(&stat, old_inode))
}

async fn create_symlink(state: RequestState, request: &Request<'_>) -> Result<Vec<u8>, i32> {
    let (name, target) = symlink_parts(request.body)?;
    let child = host::symlink(&request_node(state, request.node)?, name, target)
        .await
        .map_err(host_error)?;
    insert_entry(state, child).await
}

async fn open_file(state: RequestState, request: &Request<'_>) -> Result<Vec<u8>, i32> {
    let (flags, writable) = open_flags(u32_at(request.body, 0)?)?;
    let descriptor = request_node(state, request.node)?
        .open(flags)
        .await
        .map_err(host_error)?;
    state.with(|state| store_handle(state, request.node, descriptor, writable).map(open))
}

async fn open_directory(state: RequestState, request: &Request<'_>) -> Result<Vec<u8>, i32> {
    let (directory, descriptor) = request_node(state, request.node)?
        .open_directory()
        .await
        .map_err(host_error)?;
    state.with(|state| {
        if state.directories.len() == MAX_DIRECTORIES {
            return Err(24);
        }
        let handle = state.next_handle;
        state.next_handle = state.next_handle.wrapping_add(1).max(2);
        state.directories.push((
            handle,
            OpenDirectory {
                node: request.node,
                directory: std::sync::Arc::new(futures::lock::Mutex::new(directory)),
                descriptor,
            },
        ));
        state.unused_nodes.remove(&request.node);
        Ok(open(handle))
    })
}

fn release_file(state: &mut State, request: &Request<'_>) -> Result<Vec<u8>, i32> {
    let mut release_error = None;
    if let (Ok(id), Ok(flags), Ok(_owner)) = (
        u64_at(request.body, 0),
        u32_at(request.body, 12),
        u64_at(request.body, 16),
    ) {
        if flags & 2 != 0
            && let Ok(handle) = handle(state, id)
            && node(state, handle.node).is_ok()
        {
            release_error = Some(95);
        }
        let released_node = state
            .handles
            .iter()
            .find(|known| known.id == id)
            .map(|handle| handle.node);
        state.handles.retain(|known| known.id != id);
        if let Some(node) = released_node {
            mark_unused_if_unheld(state, node);
        }
    }
    release_error.map_or_else(|| Ok(Vec::new()), Err)
}

fn release_directory(state: &mut State, request: &Request<'_>) -> Vec<u8> {
    if let Ok(handle) = u64_at(request.body, 0) {
        let released_node = state
            .directories
            .iter()
            .find(|(known, _)| *known == handle)
            .map(|(_, directory)| directory.node);
        state.directories.retain(|(known, _)| *known != handle);
        if let Some(node) = released_node {
            mark_unused_if_unheld(state, node);
        }
    }
    Vec::new()
}

async fn read_directory(state: RequestState, request: &Request<'_>) -> Result<Vec<u8>, i32> {
    let handle = u64_at(request.body, 0)?;
    let cookie = u64_at(request.body, 8)?;
    let size = u32_at(request.body, 16)?;
    let directory =
        state.with(|state| Ok(directory(state, handle).map_err(|_| 2)?.directory.clone()))?;
    let entries = directory
        .lock()
        .await
        .readdir(cookie, 256, size)
        .await
        .map_err(host_error)?;
    Ok(dirents(entries, usize::try_from(size).unwrap_or(0)))
}

pub(super) fn prepare_io(
    state: &State,
    request: &Request<'_>,
    generation: u64,
) -> Result<PreparedIo, i32> {
    match request.opcode {
        wire::READ | wire::WRITE | wire::FSYNC | wire::FSYNCDIR => prepare_file_io(state, request),
        _ => {
            let identity = file_identity(state, request.node)?;
            let body = request.body.to_vec();
            let opcode = request.opcode;
            let node = request.node;
            let unique = request.unique;
            Ok(PreparedIo {
                identity,
                work: async move {
                    let request = Request {
                        opcode,
                        node,
                        unique,
                        body: &body,
                    };
                    let result = execute(RequestState(generation), &request).await;
                    if opcode == wire::LOOKUP
                        && let Ok(response) = &result
                    {
                        RequestState(generation).with(|state| {
                            super::remember_lookup(state, &request, response);
                            Ok(())
                        })?;
                    }
                    result
                }
                .boxed_local(),
            })
        }
    }
}

fn prepare_file_io(state: &State, request: &Request<'_>) -> Result<PreparedIo, i32> {
    let id = u64_at(request.body, 0)?;
    if request.opcode == wire::FSYNCDIR {
        let directory = directory(state, id).map_err(|_| 9)?;
        let descriptor = directory.descriptor.as_ref().ok_or(95)?.clone();
        return Ok(PreparedIo {
            identity: file_identity(state, directory.node)?,
            work: async move {
                descriptor.sync().await.map_err(wasi_error)?;
                Ok(Vec::new())
            }
            .boxed_local(),
        });
    }
    let handle = handle(state, id).map_err(|_| 9)?;
    let descriptor = handle.descriptor.clone();
    let work = match request.opcode {
        wire::READ => {
            let offset = u64_at(request.body, 8)?;
            let size = usize::try_from(u32_at(request.body, 16)?)
                .unwrap_or(MAX_READ)
                .min(MAX_READ);
            async move { read_file(&descriptor, offset, size).await }.boxed_local()
        }
        wire::WRITE => {
            let offset = u64_at(request.body, 8)?;
            let size = u32_at(request.body, 16)?;
            let bytes = request.body.get(40..).ok_or(wire::EINVAL)?;
            if bytes.len() != usize::try_from(size).map_err(|_| wire::EINVAL)? {
                return Err(wire::EINVAL);
            }
            if !handle.writable {
                return Err(9);
            }
            let bytes = bytes.to_vec();
            async move {
                write_file(&descriptor, offset, bytes).await?;
                Ok(sized_out(size))
            }
            .boxed_local()
        }
        wire::FSYNC => async move {
            descriptor.sync_data().await.map_err(|_| 5)?;
            Ok(Vec::new())
        }
        .boxed_local(),
        _ => return Err(wire::ENOSYS),
    };
    Ok(PreparedIo {
        identity: file_identity(state, handle.node)?,
        work,
    })
}

fn file_identity(state: &State, node: u64) -> Result<(u64, u64), i32> {
    let record = state.nodes.get(&node).ok_or(9)?;
    Ok((record.dev, record.ino))
}
