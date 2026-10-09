use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::sync::mpsc;
use wasmtime::StoreContextMut;
use wasmtime::component::{
    Destination, Source, StreamConsumer, StreamProducer, StreamResult, VecBuffer,
};

pub const CHUNK_BYTES: usize = 16 * 1024;
pub const QUEUED_CHUNKS: usize = 4;

type Reservation = Pin<
    Box<dyn Future<Output = Result<mpsc::OwnedPermit<Vec<u8>>, mpsc::error::SendError<()>>> + Send>,
>;

pub struct ByteSink {
    sender: mpsc::Sender<Vec<u8>>,
    reservation: Option<Reservation>,
}

pub struct ByteSource {
    pub(crate) receiver: mpsc::Receiver<Vec<u8>>,
}

pub fn create_byte_channel() -> (ByteSink, ByteSource) {
    let (sender, receiver) = mpsc::channel(QUEUED_CHUNKS);
    (
        ByteSink {
            sender,
            reservation: None,
        },
        ByteSource { receiver },
    )
}

impl<D: 'static> StreamConsumer<D> for ByteSink {
    type Item = u8;

    fn poll_consume(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        store: StoreContextMut<D>,
        source: Source<'_, u8>,
        finish: bool,
    ) -> Poll<wasmtime::Result<StreamResult>> {
        if finish {
            self.reservation = None;
            return Poll::Ready(Ok(StreamResult::Cancelled));
        }
        let mut reservation = self
            .reservation
            .take()
            .unwrap_or_else(|| Box::pin(self.sender.clone().reserve_owned()));
        let permit = match reservation.as_mut().poll(context) {
            Poll::Pending => {
                self.reservation = Some(reservation);
                return Poll::Pending;
            }
            Poll::Ready(permit) => permit,
        };
        let Ok(permit) = permit else {
            return Poll::Ready(Ok(StreamResult::Dropped));
        };
        let mut source = source.as_direct(store);
        let available = source.remaining();
        let count = available.len().min(CHUNK_BYTES);
        if count != 0 {
            let bytes = available[..count].to_vec();
            source.mark_read(count);
            permit.send(bytes);
        }
        Poll::Ready(Ok(StreamResult::Completed))
    }
}

impl<D: 'static> StreamProducer<D> for ByteSource {
    type Item = u8;
    type Buffer = VecBuffer<u8>;

    fn poll_produce<'a>(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        _: StoreContextMut<'a, D>,
        mut destination: Destination<'a, u8, Self::Buffer>,
        finish: bool,
    ) -> Poll<wasmtime::Result<StreamResult>> {
        if finish {
            return Poll::Ready(Ok(StreamResult::Cancelled));
        }
        match std::task::ready!(self.receiver.poll_recv(context)) {
            Some(bytes) => {
                destination.set_buffer(bytes.into());
                Poll::Ready(Ok(StreamResult::Completed))
            }
            None => Poll::Ready(Ok(StreamResult::Dropped)),
        }
    }
}
