use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::task::Waker;

use smoltcp::iface::{Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp::{Socket, SocketBuffer};
use smoltcp::wire::IpListenEndpoint;

const FLOW_BUFFER_BYTES: usize = super::TCP_BUFFER_BYTES;
const PUMP_BYTES: usize = super::TCP_CHUNK_BYTES;
const FIRST_SOURCE_PORT: u16 = 49_152;

pub enum Error {
    Full,
    Unknown,
    Backpressure,
}

struct Flow {
    grant: u32,
    socket: SocketHandle,
    source_port: u16,
    host_to_guest: VecDeque<Vec<u8>>,
    host_to_guest_bytes: usize,
    guest_to_host: VecDeque<Vec<u8>>,
    guest_to_host_bytes: usize,
    host_eof: bool,
}

pub struct PublishedTable {
    flows: Vec<Flow>,
    next_source_port: u16,
}

impl PublishedTable {
    pub const fn new() -> Self {
        Self {
            flows: Vec::new(),
            next_source_port: FIRST_SOURCE_PORT,
        }
    }

    pub fn accept(
        &mut self,
        grant: u32,
        guest_ip: Ipv4Addr,
        guest_port: u16,
        gateway_ip: Ipv4Addr,
        interface: &mut Interface,
        sockets: &mut SocketSet<'_>,
    ) -> Result<(), Error> {
        if self.flows.iter().any(|flow| flow.grant == grant) {
            return Err(Error::Backpressure);
        }
        let source_port = self.next_available_source_port()?;
        let mut socket = Socket::new(
            SocketBuffer::new(vec![0; FLOW_BUFFER_BYTES]),
            SocketBuffer::new(vec![0; FLOW_BUFFER_BYTES]),
        );
        socket
            .connect(
                interface.context(),
                (guest_ip, guest_port),
                IpListenEndpoint {
                    addr: Some(gateway_ip.into()),
                    port: source_port,
                },
            )
            .map_err(|_| Error::Backpressure)?;
        self.flows.push(Flow {
            grant,
            socket: sockets.add(socket),
            source_port,
            host_to_guest: VecDeque::new(),
            host_to_guest_bytes: 0,
            guest_to_host: VecDeque::new(),
            guest_to_host_bytes: 0,
            host_eof: false,
        });
        Ok(())
    }

    pub fn register_send_waker(
        &self,
        grant: u32,
        sockets: &mut SocketSet<'_>,
        waker: &Waker,
    ) -> Result<(), Error> {
        let flow = &self.flows[self.flow_index(grant)?];
        sockets
            .get_mut::<Socket>(flow.socket)
            .register_send_waker(waker);
        Ok(())
    }

    pub fn deliver(&mut self, grant: u32, data: &[u8]) -> Result<(), Error> {
        let flow = self.flow_mut(grant)?;
        if flow.host_eof
            || data.len() > FLOW_BUFFER_BYTES
            || flow.host_to_guest_bytes.saturating_add(data.len()) > FLOW_BUFFER_BYTES
        {
            return Err(Error::Backpressure);
        }
        flow.host_to_guest_bytes += data.len();
        flow.host_to_guest.push_back(data.to_vec());
        Ok(())
    }

    pub fn host_eof(&mut self, grant: u32) -> Result<(), Error> {
        self.flow_mut(grant)?.host_eof = true;
        Ok(())
    }

    pub fn abort(&mut self, grant: u32, sockets: &mut SocketSet<'_>) -> Result<(), Error> {
        let index = self.flow_index(grant)?;
        let handle = self.flows[index].socket;
        sockets.get_mut::<Socket>(handle).abort();
        sockets.remove(handle);
        self.flows.swap_remove(index);
        Ok(())
    }

    pub fn take_upstream(&mut self, grant: u32, max_bytes: usize) -> Result<Vec<Vec<u8>>, Error> {
        let flow = self.flow_mut(grant)?;
        let mut result = Vec::new();
        let mut total: usize = 0;
        while let Some(data) = flow.guest_to_host.front() {
            if total.saturating_add(data.len()) > max_bytes {
                break;
            }
            let Some(data) = flow.guest_to_host.pop_front() else {
                break;
            };
            total += data.len();
            flow.guest_to_host_bytes -= data.len();
            result.push(data);
        }
        Ok(result)
    }

    pub fn restore_upstream(&mut self, grant: u32, data: Vec<u8>) -> Result<(), Error> {
        let flow = self.flow_mut(grant)?;
        if flow.guest_to_host_bytes.saturating_add(data.len()) > FLOW_BUFFER_BYTES {
            return Err(Error::Backpressure);
        }
        flow.guest_to_host_bytes += data.len();
        flow.guest_to_host.push_front(data);
        Ok(())
    }

    pub fn is_terminal(&self, grant: u32, sockets: &SocketSet<'_>) -> Result<bool, Error> {
        let index = self.flow_index(grant)?;
        let flow = &self.flows[index];
        Ok(!sockets.get::<Socket>(flow.socket).is_open()
            && flow.host_to_guest.is_empty()
            && flow.guest_to_host.is_empty())
    }

    pub fn guest_eof(&self, grant: u32, sockets: &SocketSet<'_>) -> Result<bool, Error> {
        let index = self.flow_index(grant)?;
        let flow = &self.flows[index];
        let socket = sockets.get::<Socket>(flow.socket);
        Ok(!socket.may_recv()
            && (socket.may_send() || !socket.is_open())
            && flow.guest_to_host.is_empty())
    }

    pub fn pump(&mut self, sockets: &mut SocketSet<'_>) {
        for flow in &mut self.flows {
            let socket = sockets.get_mut::<Socket>(flow.socket);
            while socket.can_send() {
                let Some(data) = flow.host_to_guest.front() else {
                    break;
                };
                let Ok(sent) = socket.send_slice(data) else {
                    break;
                };
                if sent == data.len() {
                    let Some(data) = flow.host_to_guest.pop_front() else {
                        break;
                    };
                    flow.host_to_guest_bytes -= data.len();
                } else {
                    let Some(data) = flow.host_to_guest.front_mut() else {
                        break;
                    };
                    data.drain(..sent);
                    flow.host_to_guest_bytes -= sent;
                    break;
                }
            }
            if flow.host_eof && flow.host_to_guest.is_empty() && socket.may_send() {
                socket.close();
            }
            let mut buffer = [0; PUMP_BYTES];
            while socket.can_recv() && flow.guest_to_host_bytes < FLOW_BUFFER_BYTES {
                let remaining = FLOW_BUFFER_BYTES - flow.guest_to_host_bytes;
                let Ok(read) = socket.recv_slice(&mut buffer[..remaining.min(PUMP_BYTES)]) else {
                    break;
                };
                if read == 0 {
                    break;
                }
                flow.guest_to_host_bytes += read;
                flow.guest_to_host.push_back(buffer[..read].to_vec());
            }
        }
    }

    fn flow_index(&self, grant: u32) -> Result<usize, Error> {
        self.flows
            .iter()
            .position(|flow| flow.grant == grant)
            .ok_or(Error::Unknown)
    }

    fn flow_mut(&mut self, grant: u32) -> Result<&mut Flow, Error> {
        let index = self.flow_index(grant)?;
        Ok(&mut self.flows[index])
    }

    fn next_available_source_port(&mut self) -> Result<u16, Error> {
        for _ in FIRST_SOURCE_PORT..=u16::MAX {
            let source_port = self.next_source_port;
            self.next_source_port = self.next_source_port.wrapping_add(1).max(FIRST_SOURCE_PORT);
            if self
                .flows
                .iter()
                .all(|flow| flow.source_port != source_port)
            {
                return Ok(source_port);
            }
        }
        Err(Error::Full)
    }
}

impl Default for PublishedTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_native_grant_cannot_buffer_or_close_data() {
        let mut table = PublishedTable::new();
        assert!(matches!(table.deliver(7, &[1]), Err(Error::Unknown)));
        assert!(matches!(table.host_eof(7), Err(Error::Unknown)));
        assert!(matches!(table.take_upstream(7, 1), Err(Error::Unknown)));
    }

    #[test]
    fn full_host_queue_keeps_the_connection_open_for_a_retry() {
        let mut table = PublishedTable::new();
        let mut sockets = SocketSet::new(vec![]);
        let socket = sockets.add(Socket::new(
            SocketBuffer::new(vec![0; FLOW_BUFFER_BYTES]),
            SocketBuffer::new(vec![0; FLOW_BUFFER_BYTES]),
        ));
        table.flows.push(Flow {
            grant: 7,
            socket,
            source_port: FIRST_SOURCE_PORT,
            host_to_guest: VecDeque::from([vec![0; FLOW_BUFFER_BYTES]]),
            host_to_guest_bytes: FLOW_BUFFER_BYTES,
            guest_to_host: VecDeque::new(),
            guest_to_host_bytes: 0,
            host_eof: false,
        });

        assert!(matches!(
            table.deliver(7, b"later"),
            Err(Error::Backpressure)
        ));
        assert!(!table.flows[0].host_eof);
        assert_eq!(table.flows[0].host_to_guest_bytes, FLOW_BUFFER_BYTES);
    }

    #[test]
    fn closed_socket_keeps_queued_guest_response() {
        let mut table = PublishedTable::new();
        let mut sockets = SocketSet::new(vec![]);
        let socket = sockets.add(Socket::new(
            SocketBuffer::new(vec![0; FLOW_BUFFER_BYTES]),
            SocketBuffer::new(vec![0; FLOW_BUFFER_BYTES]),
        ));
        table.flows.push(Flow {
            grant: 7,
            socket,
            source_port: FIRST_SOURCE_PORT,
            host_to_guest: VecDeque::new(),
            host_to_guest_bytes: 0,
            guest_to_host: VecDeque::from([b"response".to_vec()]),
            guest_to_host_bytes: b"response".len(),
            host_eof: true,
        });

        table.pump(&mut sockets);

        assert!(matches!(table.guest_eof(7, &sockets), Ok(false)));
        assert!(matches!(
            table.take_upstream(7, FLOW_BUFFER_BYTES),
            Ok(data) if data == [b"response"]
        ));
        assert!(matches!(table.guest_eof(7, &sockets), Ok(true)));
        assert!(matches!(table.is_terminal(7, &sockets), Ok(true)));
    }

    #[test]
    fn source_port_wrap_skips_a_live_connection() {
        let mut table = PublishedTable::new();
        let mut sockets = SocketSet::new(vec![]);
        let socket = sockets.add(Socket::new(
            SocketBuffer::new(vec![0; FLOW_BUFFER_BYTES]),
            SocketBuffer::new(vec![0; FLOW_BUFFER_BYTES]),
        ));
        table.flows.push(Flow {
            grant: 7,
            socket,
            source_port: FIRST_SOURCE_PORT,
            host_to_guest: VecDeque::new(),
            host_to_guest_bytes: 0,
            guest_to_host: VecDeque::new(),
            guest_to_host_bytes: 0,
            host_eof: false,
        });
        table.next_source_port = u16::MAX;

        assert!(matches!(table.next_available_source_port(), Ok(u16::MAX)));
        assert!(matches!(
            table.next_available_source_port(),
            Ok(port) if port == FIRST_SOURCE_PORT + 1
        ));
    }
}
