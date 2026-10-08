//! Drive per-socket network streams and raw TCP bytes through the production virtqueues.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::time::Duration;

use terra_protocol::application::{Direction, Message, StreamDecoder};
use terra_protocol::vsock::{
    AGENT_PORT, CONTROL_PORT, FLOW_REPLY_BYTES, FLOW_UPSTREAM_BYTES, PUBLICATION_PORT,
};

use super::vsock::GuestVsock;

const WAIT: Duration = Duration::from_secs(5);

/// A guest stream endpoint: guest port and host port.
pub(super) type Stream = (u32, u32);

pub(super) struct GuestStream {
    pub(super) guest: GuestVsock,
    bytes: BTreeMap<Stream, VecDeque<u8>>,
    connected: BTreeSet<Stream>,
    reset: BTreeSet<Stream>,
    finished: BTreeSet<Stream>,
    transmitted: BTreeMap<Stream, u32>,
    forwarded: BTreeMap<Stream, u32>,
    windows: BTreeMap<Stream, u32>,
    credit_requests: BTreeMap<Stream, usize>,
    requests: VecDeque<u32>,
}

fn is_fixed(stream: Stream) -> bool {
    stream == (AGENT_PORT, AGENT_PORT) || stream == (CONTROL_PORT, CONTROL_PORT)
}

fn receive_window(stream: Stream) -> u32 {
    if is_fixed(stream) {
        65536
    } else {
        u32::try_from(FLOW_REPLY_BYTES).unwrap_or(u32::MAX)
    }
}

impl GuestStream {
    pub(super) fn new(guest: GuestVsock) -> Self {
        Self {
            guest,
            bytes: BTreeMap::new(),
            connected: BTreeSet::new(),
            reset: BTreeSet::new(),
            finished: BTreeSet::new(),
            transmitted: BTreeMap::new(),
            forwarded: BTreeMap::new(),
            windows: BTreeMap::new(),
            credit_requests: BTreeMap::new(),
            requests: VecDeque::new(),
        }
    }

    async fn poll(&mut self) -> wasmtime::Result<()> {
        for packet in self.guest.receive()? {
            let stream = (packet.guest_port, packet.port);
            if packet.op != 3 {
                self.forwarded.insert(stream, packet.forwarded);
                self.windows.insert(stream, packet.window);
            }
            match packet.op {
                1 => {
                    wasmtime::ensure!(
                        packet.guest_port == PUBLICATION_PORT,
                        "the host opens only publication streams"
                    );
                    self.requests.push_back(packet.port);
                }
                2 => {
                    self.connected.insert(stream);
                }
                3 => {
                    self.reset.insert(stream);
                }
                4 => {
                    if packet.flags & 2 != 0 {
                        self.finished.insert(stream);
                    }
                }
                5 => {
                    let buffered = self.bytes.entry(stream).or_default();
                    wasmtime::ensure!(
                        buffered.len() + packet.payload.len() <= receive_window(stream) as usize,
                        "network self-test guest receive bound"
                    );
                    buffered.extend(packet.payload);
                }
                6 => {}
                7 => {
                    *self.credit_requests.entry(stream).or_default() += 1;
                    self.guest
                        .acknowledge(packet.guest_port, packet.port, 0)
                        .await?;
                }
                _ => wasmtime::bail!("network self-test unexpected transport operation"),
            }
        }
        Ok(())
    }

    /// Poll the receive queue until `is_ready` holds; an `Err` from `is_ready` aborts the wait.
    async fn wait_until(
        &mut self,
        mut is_ready: impl FnMut(&Self) -> wasmtime::Result<bool>,
    ) -> wasmtime::Result<()> {
        tokio::time::timeout(WAIT, async {
            loop {
                self.poll().await?;
                if is_ready(self)? {
                    return Ok(());
                }
                self.guest.wait_for_receive_work().await?;
            }
        })
        .await?
    }

    fn forget(&mut self, stream: Stream) {
        self.bytes.remove(&stream);
        self.credit_requests.remove(&stream);
        self.connected.remove(&stream);
        self.reset.remove(&stream);
        self.finished.remove(&stream);
        self.transmitted.insert(stream, 0);
        self.forwarded.insert(stream, 0);
    }

    pub(super) async fn connect(&mut self, stream: Stream) -> wasmtime::Result<()> {
        let window = receive_window(stream);
        self.guest.set_receive_window(stream.0, stream.1, window);
        self.forget(stream);
        self.guest.send(stream.0, stream.1, 1, window, &[]).await?;
        self.wait_until(|this| {
            wasmtime::ensure!(
                !this.reset.contains(&stream),
                "network transport admission reset"
            );
            Ok(this.connected.contains(&stream))
        })
        .await
        .map_err(|error| error.context(format!("connecting vsock stream {stream:?}")))
    }

    /// Accept the next frontend-initiated publication stream.
    pub(super) async fn accept(&mut self) -> wasmtime::Result<Stream> {
        if self.requests.is_empty() {
            self.wait_until(|this| Ok(!this.requests.is_empty()))
                .await
                .map_err(|error| error.context("waiting for a vsock publication stream request"))?;
        }
        let host_port = self.requests.pop_front().ok_or_else(|| {
            wasmtime::Error::msg("network self-test publication request vanished")
        })?;
        let stream = (PUBLICATION_PORT, host_port);
        let window = receive_window(stream);
        self.guest.set_receive_window(stream.0, stream.1, window);
        self.forget(stream);
        self.guest.send(stream.0, stream.1, 2, window, &[]).await?;
        self.connected.insert(stream);
        Ok(stream)
    }

    pub(super) async fn submit_raw(
        &mut self,
        stream: Stream,
        bytes: &[u8],
    ) -> wasmtime::Result<()> {
        let chunk_bytes = if is_fixed(stream) {
            997
        } else {
            FLOW_UPSTREAM_BYTES
        };
        let mut remaining = bytes;
        while !remaining.is_empty() {
            if self.send_credit(stream) == 0 {
                self.wait_until(|this| {
                    wasmtime::ensure!(
                        !this.reset.contains(&stream),
                        "network input transport reset"
                    );
                    Ok(this.send_credit(stream) != 0)
                })
                .await
                .map_err(|error| error.context(format!("vsock stream {stream:?} send credit")))?;
            }
            let count = remaining
                .len()
                .min(chunk_bytes)
                .min(self.send_credit(stream));
            self.guest
                .send(
                    stream.0,
                    stream.1,
                    5,
                    self.guest.receive_window(stream.0, stream.1),
                    &remaining[..count],
                )
                .await?;
            let sent = self.transmitted.entry(stream).or_default();
            *sent = sent.wrapping_add(u32::try_from(count)?);
            remaining = &remaining[count..];
            self.poll().await?;
        }
        Ok(())
    }

    fn send_credit(&self, stream: Stream) -> usize {
        let sent = self.transmitted.get(&stream).copied().unwrap_or(0);
        let forwarded = self.forwarded.get(&stream).copied().unwrap_or(0);
        let window = self.windows.get(&stream).copied().unwrap_or(0);
        window.saturating_sub(sent.wrapping_sub(forwarded)) as usize
    }

    pub(super) async fn send_message(
        &mut self,
        stream: Stream,
        message: &Message,
    ) -> wasmtime::Result<()> {
        let bytes = message.encode()?;
        self.submit_raw(stream, &bytes).await
    }

    pub(super) async fn read_bytes(
        &mut self,
        stream: Stream,
        length: usize,
    ) -> wasmtime::Result<Vec<u8>> {
        let mut drained = Vec::with_capacity(length);
        while drained.len() < length {
            self.wait_until(|this| {
                if this.buffered_bytes(stream) != 0 {
                    return Ok(true);
                }
                wasmtime::ensure!(
                    !this.reset.contains(&stream),
                    "network stream reset before data drain"
                );
                wasmtime::ensure!(
                    !this.finished.contains(&stream),
                    "network stream closed before data drain"
                );
                Ok(false)
            })
            .await
            .map_err(|error| {
                wasmtime::Error::msg(format!(
                    "vsock stream {stream:?} timed out waiting for {length} bytes: {error}"
                ))
            })?;
            let bytes = self.bytes.entry(stream).or_default();
            let count = bytes.len().min(length - drained.len());
            drained.extend(bytes.drain(..count));
            self.guest.acknowledge(stream.0, stream.1, count).await?;
        }
        Ok(drained)
    }

    pub(super) async fn read_message(&mut self, stream: Stream) -> wasmtime::Result<Message> {
        let mut bytes = self
            .read_bytes(stream, terra_protocol::application::HEADER_BYTES)
            .await?;
        let length = usize::try_from(u32::from_le_bytes(bytes[4..8].try_into()?))?;
        wasmtime::ensure!(
            length <= terra_protocol::application::MAX_PAYLOAD_BYTES,
            "network self-test frame bound"
        );
        bytes.extend(self.read_bytes(stream, length).await?);
        let mut decoder = StreamDecoder::default();
        decoder.push(&bytes)?;
        decoder
            .next(Direction::HostToGuest)?
            .ok_or_else(|| wasmtime::Error::msg("network self-test incomplete frame"))
    }

    pub(super) async fn finish_input(&mut self, stream: Stream) -> wasmtime::Result<()> {
        self.guest
            .send_with_flags(
                stream.0,
                stream.1,
                4,
                2,
                self.guest.receive_window(stream.0, stream.1),
                &[],
            )
            .await
    }

    pub(super) async fn reset(&mut self, stream: Stream) -> wasmtime::Result<()> {
        self.guest.send(stream.0, stream.1, 3, 0, &[]).await
    }

    pub(super) async fn require_eof(&mut self, stream: Stream) -> wasmtime::Result<()> {
        self.wait_until(|this| {
            if this.finished.contains(&stream) {
                return Ok(true);
            }
            wasmtime::ensure!(
                !this.reset.contains(&stream),
                "network stream reset before EOF"
            );
            Ok(false)
        })
        .await
        .map_err(|error| error.context(format!("vsock stream {stream:?} EOF")))?;
        wasmtime::ensure!(
            self.buffered_bytes(stream) == 0,
            "network FIN follows all expected raw bytes"
        );
        Ok(())
    }

    pub(super) async fn require_reset(&mut self, stream: Stream) -> wasmtime::Result<()> {
        self.wait_until(|this| Ok(this.reset.contains(&stream)))
            .await
            .map_err(|error| error.context(format!("vsock stream {stream:?} reset")))
    }

    pub(super) async fn wait_buffered(
        &mut self,
        stream: Stream,
        length: usize,
    ) -> wasmtime::Result<()> {
        self.wait_until(|this| {
            wasmtime::ensure!(!this.reset.contains(&stream), "stalled flow reset");
            Ok(this.buffered_bytes(stream) >= length)
        })
        .await
        .map_err(|error| {
            error.context(format!(
                "vsock stream {stream:?} waiting for {length} buffered bytes"
            ))
        })
    }

    pub(super) fn is_reset(&self, stream: Stream) -> bool {
        self.reset.contains(&stream)
    }

    pub(super) fn credit_requests(&self, stream: Stream) -> usize {
        self.credit_requests.get(&stream).copied().unwrap_or(0)
    }

    pub(super) fn buffered_bytes(&self, stream: Stream) -> usize {
        self.bytes.get(&stream).map_or(0, VecDeque::len)
    }
}
