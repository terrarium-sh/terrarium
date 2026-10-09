use std::future::Future as _;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use tokio::sync::{mpsc, oneshot};
use tokio::task::{JoinHandle, spawn_blocking};
use wasmtime::StoreContextMut;
use wasmtime::component::{
    Destination, FutureReader, Resource, StreamProducer, StreamReader, StreamResult,
};
use wasmtime_wasi::{
    filesystem::Descriptor,
    p3::bindings::filesystem::types::{self, DirectoryEntry, ErrorCode},
};
use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_SHARING_VIOLATION};

use super::FsHost;

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
                    StreamReader::new(&mut store, DirectoryProducer::new(directory, completion_tx))?
                }
                Err(error) => {
                    let _ = completion_tx.send(Err(error));
                    StreamReader::new(&mut store, std::iter::empty())?
                }
            };
            let completion = FutureReader::new(&mut store, completion_rx)?;
            Ok(((stream, completion),))
        },
    )
}

struct DirectoryProducer {
    entries: mpsc::Receiver<DirectoryEntry>,
    task: JoinHandle<Result<(), ErrorCode>>,
    completion: Option<oneshot::Sender<Result<(), ErrorCode>>>,
}

impl DirectoryProducer {
    fn new(
        directory: Arc<std::fs::File>,
        completion: oneshot::Sender<Result<(), ErrorCode>>,
    ) -> Self {
        let (sender, entries) = mpsc::channel(1);
        let task = spawn_blocking(move || {
            let entries = terra_platform::filesystem::read_base_dir(&directory)?;
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
        Self {
            entries,
            task,
            completion: Some(completion),
        }
    }

    fn close(&mut self, result: Result<(), ErrorCode>) {
        self.entries.close();
        self.task.abort();
        if let Some(completion) = self.completion.take() {
            let _ = completion.send(result);
        }
    }
}

impl<D> StreamProducer<D> for DirectoryProducer {
    type Item = DirectoryEntry;
    type Buffer = Option<DirectoryEntry>;

    fn poll_produce<'a>(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        mut store: StoreContextMut<'a, D>,
        mut destination: Destination<'a, Self::Item, Self::Buffer>,
        finish: bool,
    ) -> Poll<wasmtime::Result<StreamResult>> {
        if destination.remaining(&mut store) == Some(0) {
            return Poll::Ready(Ok(StreamResult::Completed));
        }
        let producer = self.get_mut();
        match producer.entries.poll_recv(context) {
            Poll::Ready(Some(entry)) => {
                destination.set_buffer(Some(entry));
                Poll::Ready(Ok(StreamResult::Completed))
            }
            Poll::Ready(None) => {
                let result = match ready!(Pin::new(&mut producer.task).poll(context)) {
                    Ok(result) => result,
                    Err(_) => Err(ErrorCode::Io),
                };
                producer.close(result);
                Poll::Ready(Ok(StreamResult::Dropped))
            }
            Poll::Pending if finish => Poll::Ready(Ok(StreamResult::Cancelled)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for DirectoryProducer {
    fn drop(&mut self) {
        if self.completion.is_some() {
            self.close(Ok(()));
        }
    }
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
