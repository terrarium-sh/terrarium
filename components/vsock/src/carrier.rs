use crate::{switch, worker};
use futures_io::{AsyncRead, AsyncWrite};
use futures_util::task::AtomicWaker;
use std::{
    collections::VecDeque,
    io,
    pin::Pin,
    task::{Context, Poll},
};
use terra_protocol::mux::MUX_VSOCK_PORT;
use terra_vsock_device::VsockError;

const READ_CHUNK_BYTES: usize = 16 * 1024;

static WAKER: AtomicWaker = AtomicWaker::new();

pub(crate) struct Carrier {
    source: u32,
    generation: u64,
    received: VecDeque<u8>,
}

impl Carrier {
    pub(crate) fn accept() -> Option<Self> {
        let switch = switch();
        let (source, destination) = switch.connections_up_to(1).into_iter().next()?;
        (destination == MUX_VSOCK_PORT && switch.connection_connected(source, destination)).then(
            || Self {
                source,
                generation: switch.generation(),
                received: VecDeque::new(),
            },
        )
    }

    pub(crate) fn is_current(&self) -> bool {
        let switch = switch();
        switch.generation() == self.generation
            && switch.connection_exists(self.source, MUX_VSOCK_PORT)
    }

    fn stale() -> io::Error {
        io::Error::new(io::ErrorKind::ConnectionAborted, "vsock carrier reset")
    }

    fn fill_received(&mut self) -> io::Result<()> {
        let mut switch = switch();
        if switch.generation() != self.generation
            || !switch.connection_exists(self.source, MUX_VSOCK_PORT)
        {
            return Err(Self::stale());
        }
        self.received.extend(
            switch
                .take_upstream_for_up_to(self.source, MUX_VSOCK_PORT, READ_CHUNK_BYTES)
                .into_iter()
                .flat_map(|item| item.data),
        );
        drop(switch);
        if !self.received.is_empty() {
            worker::schedule_receive_queue();
        }
        Ok(())
    }

    fn read_closed(&self) -> bool {
        let switch = switch();
        switch.generation() == self.generation
            && switch.connection_exists(self.source, MUX_VSOCK_PORT)
            && switch.guest_send_closed(self.source, MUX_VSOCK_PORT)
    }
}

pub(crate) fn wake() {
    WAKER.wake();
}

impl Drop for Carrier {
    fn drop(&mut self) {
        let mut switch = switch();
        let reset = switch.generation() == self.generation
            && switch.reset_connection(self.source, MUX_VSOCK_PORT).is_ok();
        drop(switch);
        if reset {
            worker::schedule_receive_queue();
        }
    }
}

impl AsyncRead for Carrier {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        WAKER.register(context.waker());
        if !self.is_current() {
            self.received.clear();
            return Poll::Ready(Err(Self::stale()));
        }
        if self.received.is_empty() {
            if let Err(error) = self.fill_received() {
                return Poll::Ready(Err(error));
            }
            if self.received.is_empty() {
                if !self.is_current() {
                    return Poll::Ready(Err(Self::stale()));
                }
                if self.read_closed() {
                    return Poll::Ready(Ok(0));
                }
                return Poll::Pending;
            }
        }
        let count = bytes.len().min(self.received.len());
        for (destination, byte) in bytes[..count].iter_mut().zip(self.received.drain(..count)) {
            *destination = byte;
        }
        Poll::Ready(Ok(count))
    }
}

impl AsyncWrite for Carrier {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        WAKER.register(context.waker());
        let (result, count, has_new_reply) = {
            let mut switch = switch();
            if switch.generation() != this.generation
                || !switch.connection_exists(this.source, MUX_VSOCK_PORT)
            {
                return Poll::Ready(Err(Self::stale()));
            }
            let count = bytes
                .len()
                .min(READ_CHUNK_BYTES)
                .min(switch.available_send_credit().max(1));
            let pending_replies = switch.pending_reply_count();
            let result = switch.deliver(this.source, MUX_VSOCK_PORT, &bytes[..count]);
            (
                result,
                count,
                switch.pending_reply_count() != pending_replies,
            )
        };
        if has_new_reply {
            worker::schedule_receive_queue();
        }
        match result {
            Ok(()) => Poll::Ready(Ok(count)),
            Err(VsockError::Backpressure) => {
                if this.is_current() {
                    Poll::Pending
                } else {
                    Poll::Ready(Err(Self::stale()))
                }
            }
            Err(VsockError::UnknownConnection | VsockError::TableFull) => {
                Poll::Ready(Err(Self::stale()))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.is_current()
            .then_some(Ok(()))
            .map_or_else(|| Poll::Ready(Err(Self::stale())), Poll::Ready)
    }

    fn poll_close(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        WAKER.register(context.waker());
        let result = {
            let mut switch = switch();
            if switch.generation() != this.generation
                || !switch.connection_exists(this.source, MUX_VSOCK_PORT)
            {
                return Poll::Ready(Err(Self::stale()));
            }
            switch.shutdown(this.source, MUX_VSOCK_PORT)
        };
        match result {
            Ok(()) => {
                worker::schedule_receive_queue();
                Poll::Ready(Ok(()))
            }
            Err(VsockError::Backpressure) => {
                if this.is_current() {
                    Poll::Pending
                } else {
                    Poll::Ready(Err(Self::stale()))
                }
            }
            Err(VsockError::UnknownConnection | VsockError::TableFull) => {
                Poll::Ready(Err(Self::stale()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use terra_vsock_device::{GUEST_CID, HOST_CID, RX_ALLOC, VsockHeader};

    fn packet(op: u16, data: &[u8]) {
        switch().rx(
            &VsockHeader {
                src_cid: GUEST_CID,
                dst_cid: HOST_CID,
                src_port: 100,
                dst_port: MUX_VSOCK_PORT,
                len: u32::try_from(data.len()).unwrap(),
                type_: 1,
                op,
                flags: 0,
                buf_alloc: RX_ALLOC,
                fwd_cnt: 0,
            },
            data,
        );
    }

    fn connect() -> Carrier {
        packet(1, &[]);
        switch().take_replies();
        Carrier::accept().unwrap()
    }

    #[test]
    fn reset_invalidates_buffered_reads_writes_and_cleanup_before_tuple_reuse() {
        let _guard = crate::SWITCH_TEST_LOCK.lock().unwrap();
        switch().restart();
        let mut old = connect();
        packet(5, b"old-buffer");
        let mut context = Context::from_waker(std::task::Waker::noop());
        let mut bytes = [0; 2];
        assert!(matches!(
            Pin::new(&mut old).poll_read(&mut context, &mut bytes),
            Poll::Ready(Ok(2))
        ));
        assert_eq!(&bytes, b"ol");
        switch().restart();
        let mut current = connect();
        packet(5, b"new");
        assert!(matches!(
            Pin::new(&mut old).poll_read(&mut context, &mut bytes),
            Poll::Ready(Err(_))
        ));
        assert!(matches!(
            Pin::new(&mut old).poll_write(&mut context, b"stale"),
            Poll::Ready(Err(_))
        ));
        assert!(matches!(
            Pin::new(&mut old).poll_close(&mut context),
            Poll::Ready(Err(_))
        ));
        drop(old);
        assert!(current.is_current());
        let mut bytes = [0; 3];
        assert!(matches!(
            Pin::new(&mut current).poll_read(&mut context, &mut bytes),
            Poll::Ready(Ok(3))
        ));
        assert_eq!(&bytes, b"new");
        assert!(
            switch()
                .take_replies()
                .iter()
                .all(|reply| reply.header.op == 6)
        );
    }

    #[test]
    fn partial_writes_preserve_frame_bytes_and_stop_at_peer_window() {
        let _guard = crate::SWITCH_TEST_LOCK.lock().unwrap();
        switch().restart();
        let mut carrier = connect();
        let mut context = Context::from_waker(std::task::Waker::noop());
        let bytes = vec![b'x'; READ_CHUNK_BYTES + 12];
        assert!(matches!(
            Pin::new(&mut carrier).poll_write(&mut context, &bytes),
            Poll::Ready(Ok(READ_CHUNK_BYTES))
        ));
        assert_eq!(
            switch().take_replies()[0].payload,
            bytes[..READ_CHUNK_BYTES]
        );
        assert!(matches!(
            Pin::new(&mut carrier).poll_write(&mut context, &bytes[READ_CHUNK_BYTES..]),
            Poll::Ready(Ok(12))
        ));
        assert_eq!(
            switch().take_replies()[0].payload,
            bytes[READ_CHUNK_BYTES..]
        );
        let mut delivered = bytes.len();
        while delivered < RX_ALLOC as usize {
            let Poll::Ready(Ok(count)) = Pin::new(&mut carrier).poll_write(&mut context, &bytes)
            else {
                panic!("remaining credit must permit a partial write");
            };
            assert!(count > 0);
            assert_eq!(switch().take_replies()[0].payload, bytes[..count]);
            delivered += count;
        }
        assert_eq!(delivered, RX_ALLOC as usize);
        assert!(
            Pin::new(&mut carrier)
                .poll_write(&mut context, &bytes)
                .is_pending()
        );
        let requests = switch().take_replies();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].header.op, 7);
    }
}
