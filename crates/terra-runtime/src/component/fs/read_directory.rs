use std::sync::Arc;

use futures_util::stream;
use tokio::sync::{mpsc, oneshot};
use tokio::task::spawn_blocking;
use wasmtime::component::{FutureReader, Resource, StreamReader};
use wasmtime_wasi::{
    filesystem::Descriptor,
    p3::bindings::filesystem::types::{self, DirectoryEntry, ErrorCode},
};
use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_SHARING_VIOLATION};

use super::FsHost;
use crate::component::relay;

pub(super) fn add_windows_read_directory<T: Send + 'static>(
    interface: &mut wasmtime::component::LinkerInstance<'_, T>,
    host: for<'a> fn(&'a mut T) -> &'a mut FsHost,
) -> wasmtime::Result<()> {
    interface.func_wrap(
        "[method]descriptor.read-directory",
        move |mut store, (descriptor,): (Resource<Descriptor>,)| -> wasmtime::Result<_> {
            let directory = host(store.data_mut())
                .directory(&descriptor)
                .map(|directory| directory.dir);
            let (completion_tx, completion_rx) = oneshot::channel();
            let stream = match directory {
                Ok(directory) => {
                    StreamReader::new(&mut store, read_entries(directory, completion_tx))?
                }
                Err(error) => {
                    let _ = completion_tx.send(Err(error));
                    StreamReader::new(&mut store, std::iter::empty())?
                }
            };
            let completion = FutureReader::new(&mut store, async move {
                Ok::<_, wasmtime::Error>(completion_rx.await.unwrap_or(Ok(())))
            })?;
            Ok(((stream, completion),))
        },
    )
}

/// Streams the entries from a blocking reader; the completion reports how the read ended.
fn read_entries(
    directory: Arc<std::fs::File>,
    completion: oneshot::Sender<Result<(), ErrorCode>>,
) -> relay::Stream<DirectoryEntry> {
    let (sender, entries) = mpsc::channel(1);
    let task = spawn_blocking(move || {
        let entries = terra_platform::filesystem::share::windows::read_base_dir(&directory)?;
        for entry in entries {
            if let Some(entry) = map_directory_entry(entry)?
                && sender.blocking_send(entry).is_err()
            {
                break;
            }
        }
        drop(directory);
        Ok(())
    });
    relay::Stream::new(stream::unfold(
        Some((entries, task, completion)),
        |state| async move {
            let (mut entries, task, completion) = state?;
            if let Some(entry) = entries.recv().await {
                return Some((entry, Some((entries, task, completion))));
            }
            let _ = completion.send(task.await.unwrap_or(Err(ErrorCode::Io)));
            None
        },
    ))
}

fn map_directory_entry(
    entry: std::io::Result<std::fs::DirEntry>,
) -> Result<Option<DirectoryEntry>, ErrorCode> {
    let entry = match entry {
        Ok(entry) => entry,
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(code) if u32::try_from(code).is_ok_and(|code| code == ERROR_ACCESS_DENIED || code == ERROR_SHARING_VIOLATION)
            ) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error.into()),
    };
    let metadata = entry.metadata()?;
    let name = entry
        .file_name()
        .into_string()
        .map_err(|_| ErrorCode::IllegalByteSequence)?;
    let type_ = if metadata.is_dir() {
        types::DescriptorType::Directory
    } else if metadata.is_file() {
        types::DescriptorType::RegularFile
    } else if metadata.file_type().is_symlink() {
        types::DescriptorType::SymbolicLink
    } else {
        types::DescriptorType::Other(None)
    };
    Ok(Some(DirectoryEntry { type_, name }))
}
