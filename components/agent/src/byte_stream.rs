use crate::{terra::vsock::role_stream, wit_stream};
use futures_io::{AsyncRead, AsyncWrite};
use futures_util::{
    Sink, SinkExt as _, Stream, TryStreamExt as _, sink, stream, stream::IntoAsyncRead,
};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll, ready},
};
use terra_protocol::mux::MAX_STREAM_FRAME_BYTES;
use wit_bindgen::rt::async_support::{StreamReader, StreamResult, StreamWriter};

/// yamux writes each frame's header and body separately and flushes after every frame, so writes
/// gather here and cross to the host once per flush.
const WRITE_BUFFER_BYTES: usize = 64 << 10;

type Chunks = Pin<Box<dyn Stream<Item = io::Result<Vec<u8>>>>>;
type ChunkSink = Pin<Box<dyn Sink<Vec<u8>, Error = io::Error>>>;

/// A component `stream<u8>` pair as `AsyncRead` + `AsyncWrite`.
pub(crate) struct ByteStream {
    input: IntoAsyncRead<Chunks>,
    output: Option<ChunkSink>,
    unsent: Vec<u8>,
}

impl ByteStream {
    pub(crate) fn new(input: StreamReader<u8>, output: StreamWriter<u8>) -> Self {
        Self {
            input: read_chunks(input).into_async_read(),
            output: Some(write_chunks(output)),
            unsent: Vec::new(),
        }
    }

    /// Waits for the frontend to connect the agent role; `None` once the frontend retired.
    pub(crate) async fn accept_carrier() -> Option<Self> {
        let (output, host_output) = wit_stream::new();
        let input = role_stream::accept(host_output).await?;
        Some(Self::new(input, output))
    }
}

fn read_chunks(reader: StreamReader<u8>) -> Chunks {
    Box::pin(stream::unfold(reader, |mut reader| async move {
        loop {
            let (result, bytes) = reader
                .read(Vec::with_capacity(MAX_STREAM_FRAME_BYTES))
                .await;
            if !bytes.is_empty() {
                return Some((Ok(bytes), reader));
            }
            if !matches!(result, StreamResult::Complete(_)) {
                return None;
            }
        }
    }))
}

fn write_chunks(writer: StreamWriter<u8>) -> ChunkSink {
    Box::pin(sink::unfold(
        writer,
        |mut writer, bytes: Vec<u8>| async move {
            if writer.write_all(bytes).await.is_empty() {
                Ok(writer)
            } else {
                Err(closed())
            }
        },
    ))
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "component stream closed")
}

impl AsyncRead for ByteStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.input).poll_read(context, bytes)
    }
}

impl AsyncWrite for ByteStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.output.is_none() {
            return Poll::Ready(Err(closed()));
        }
        if self.unsent.len() >= WRITE_BUFFER_BYTES {
            ready!(self.as_mut().poll_flush(context))?;
        }
        let count = bytes.len().min(WRITE_BUFFER_BYTES - self.unsent.len());
        self.unsent.extend_from_slice(&bytes[..count]);
        Poll::Ready(Ok(count))
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Self { output, unsent, .. } = self.get_mut();
        let Some(output) = output.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        if !unsent.is_empty() {
            ready!(output.poll_ready_unpin(context))?;
            output.start_send_unpin(std::mem::take(unsent))?;
        }
        output.poll_flush_unpin(context)
    }

    /// Sends what is buffered, then drops the writer so the reading side sees the end of the stream.
    fn poll_close(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.as_mut().poll_flush(context))?;
        if let Some(output) = self.output.as_mut() {
            ready!(output.poll_close_unpin(context))?;
        }
        self.output = None;
        Poll::Ready(Ok(()))
    }
}
