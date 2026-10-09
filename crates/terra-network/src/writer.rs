use std::io::{self, IoSlice};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

pub(crate) const MAX_WRITE_BATCH_FRAMES: usize = 8;

pub(crate) async fn write_queued_frames<T>(
    write: &mut (impl AsyncWrite + Unpin),
    incoming: &mut mpsc::Receiver<T>,
    mut encode: impl FnMut(T) -> io::Result<Vec<u8>>,
) -> io::Result<()> {
    let mut frames = Vec::with_capacity(MAX_WRITE_BATCH_FRAMES);
    while let Some(first) = incoming.recv().await {
        frames.push(encode(first)?);
        while frames.len() < MAX_WRITE_BATCH_FRAMES {
            let Ok(next) = incoming.try_recv() else {
                break;
            };
            frames.push(encode(next)?);
        }
        if frames.len() == 1 || !write.is_write_vectored() {
            for frame in &frames {
                write.write_all(frame).await?;
            }
        } else {
            let mut slices: [_; MAX_WRITE_BATCH_FRAMES] = std::array::from_fn(|index| {
                IoSlice::new(frames.get(index).map_or(&[], Vec::as_slice))
            });
            let mut remaining = &mut slices[..frames.len()];
            while !remaining.is_empty() {
                let written = write.write_vectored(remaining).await?;
                if written == 0 {
                    return Err(io::ErrorKind::WriteZero.into());
                }
                IoSlice::advance_slices(&mut remaining, written);
            }
        }
        frames.clear();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::AsyncReadExt;

    struct RecordingWriter {
        bytes: Vec<u8>,
        max_write: usize,
        is_vectored: bool,
        vectored_calls: Vec<usize>,
        error: Option<io::ErrorKind>,
    }

    impl RecordingWriter {
        fn new(is_vectored: bool, max_write: usize) -> Self {
            Self {
                bytes: Vec::new(),
                max_write,
                is_vectored,
                vectored_calls: Vec::new(),
                error: None,
            }
        }
    }

    impl AsyncWrite for RecordingWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            if let Some(error) = self.error {
                return Poll::Ready(Err(error.into()));
            }
            let length = bytes.len().min(self.max_write);
            self.bytes.extend_from_slice(&bytes[..length]);
            Poll::Ready(Ok(length))
        }

        fn is_write_vectored(&self) -> bool {
            self.is_vectored
        }

        fn poll_write_vectored(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            slices: &[IoSlice<'_>],
        ) -> Poll<io::Result<usize>> {
            assert!(self.is_vectored);
            self.vectored_calls.push(slices.len());
            if let Some(error) = self.error {
                return Poll::Ready(Err(error.into()));
            }
            let mut length = 0;
            for slice in slices {
                let written = slice.len().min(self.max_write - length);
                self.bytes.extend_from_slice(&slice[..written]);
                length += written;
                if length == self.max_write {
                    break;
                }
            }
            Poll::Ready(Ok(length))
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn bounded_batches_preserve_fifo_across_partial_vectored_and_scalar_writes() {
        for is_vectored in [false, true] {
            for max_write in [3, usize::MAX] {
                let chunks = [
                    b"ab".as_slice(),
                    b"cde",
                    b"f",
                    b"ghij",
                    b"kl",
                    b"mno",
                    b"p",
                    b"qr",
                    b"st",
                ]
                .into_iter()
                .cycle()
                .take(2 * MAX_WRITE_BATCH_FRAMES + 1)
                .map(<[u8]>::to_vec)
                .collect::<Vec<_>>();
                let expected = chunks.concat();
                let (sender, mut incoming) = mpsc::channel(chunks.len());
                for bytes in chunks {
                    sender.try_send(bytes).unwrap();
                }
                drop(sender);
                let mut write = RecordingWriter::new(is_vectored, max_write);
                write_queued_frames(&mut write, &mut incoming, Ok)
                    .await
                    .unwrap();
                assert_eq!(write.bytes, expected);
                assert!(
                    write
                        .vectored_calls
                        .iter()
                        .all(|count| *count <= MAX_WRITE_BATCH_FRAMES)
                );
                if !is_vectored {
                    assert_eq!(write.vectored_calls, [] as [usize; 0]);
                } else if max_write == usize::MAX {
                    assert_eq!(
                        write.vectored_calls,
                        [MAX_WRITE_BATCH_FRAMES, MAX_WRITE_BATCH_FRAMES]
                    );
                } else {
                    assert_eq!(write.vectored_calls.first(), Some(&MAX_WRITE_BATCH_FRAMES));
                    assert!(
                        write
                            .vectored_calls
                            .iter()
                            .any(|count| *count < MAX_WRITE_BATCH_FRAMES)
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn single_frame_does_not_wait_for_another_frame_or_sender_disconnect() {
        let (sender, mut incoming) = mpsc::channel(4);
        sender.try_send(b"first".to_vec()).unwrap();
        let (mut write, mut read) = tokio::io::duplex(16);
        let writer =
            tokio::spawn(async move { write_queued_frames(&mut write, &mut incoming, Ok).await });
        let mut bytes = [0; 5];
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            read.read_exact(&mut bytes),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&bytes, b"first");
        assert!(!writer.is_finished());
        drop(sender);
        writer.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn failed_writes_stop_without_skipping_frames() {
        for is_vectored in [false, true] {
            for error in [None, Some(io::ErrorKind::BrokenPipe)] {
                let (sender, mut incoming) = mpsc::channel(MAX_WRITE_BATCH_FRAMES);
                for byte in 0..MAX_WRITE_BATCH_FRAMES {
                    sender.try_send(vec![u8::try_from(byte).unwrap()]).unwrap();
                }
                drop(sender);
                let mut write = RecordingWriter::new(is_vectored, 0);
                write.error = error;
                let result = write_queued_frames(&mut write, &mut incoming, Ok)
                    .await
                    .unwrap_err();
                assert_eq!(result.kind(), error.unwrap_or(io::ErrorKind::WriteZero));
                assert_eq!(write.bytes, [] as [u8; 0]);
                if is_vectored {
                    assert_eq!(write.vectored_calls, [MAX_WRITE_BATCH_FRAMES]);
                }
            }
        }
    }
}
