mod dns;
mod peer;
mod tcp;
#[cfg(test)]
mod tests;
mod udp;

use self::peer::{authorize_peer, is_host_loopback, validate_peer};
use self::tcp::bind_tcp_listener;
use self::udp::bind_udp;
use crate::config::{Config, Ready};
use crate::{Error, ResourceKind};
use std::collections::{BTreeMap, BTreeSet};
use std::future::{Future, poll_fn};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use terra_policy::BoxPolicy;
use terra_protocol::network::{ListenerGrant, Open, Opened};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt};

pub struct Broker {
    policy: Arc<BoxPolicy>,
    listeners: BTreeMap<ListenerGrant, Arc<TcpListener>>,
    udp_listeners: BTreeMap<ListenerGrant, Arc<UdpSocket>>,
    max_resources: usize,
}

/// State every stream handler shares.
struct Shared {
    policy: Arc<BoxPolicy>,
    listeners: BTreeMap<ListenerGrant, Arc<TcpListener>>,
    udp_listeners: BTreeMap<ListenerGrant, Arc<UdpSocket>>,
    resources: Arc<Semaphore>,
    dns_requests: Arc<Semaphore>,
    resolvers: Arc<Semaphore>,
    grant_owners: Arc<GrantOwners>,
}

/// The listener grants held by one pending accept or one published UDP owner each.
#[derive(Default)]
struct GrantOwners {
    owned: Mutex<BTreeSet<ListenerGrant>>,
    released: Notify,
}

impl GrantOwners {
    /// Waits for the current owner instead of failing: a client reopening a grant it just dropped
    /// races that drop on another stream, so `Busy` would lose the grant for good.
    async fn claim(self: &Arc<Self>, grant: ListenerGrant) -> GrantOwner {
        loop {
            let released = self.released.notified();
            tokio::pin!(released);
            released.as_mut().enable();
            if self
                .owned
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(grant)
            {
                return GrantOwner {
                    owners: self.clone(),
                    grant,
                };
            }
            released.await;
        }
    }
}

struct GrantOwner {
    owners: Arc<GrantOwners>,
    grant: ListenerGrant,
}

impl Drop for GrantOwner {
    fn drop(&mut self) {
        self.owners
            .owned
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.grant);
        self.owners.released.notify_waiters();
    }
}

/// An admitted stream, ready for its `Opened` reply and its relay.
enum Prepared {
    Tcp {
        tcp: TcpStream,
        peer: SocketAddr,
        permit: OwnedSemaphorePermit,
    },
    Udp {
        udp: udp::UdpResource,
        permit: OwnedSemaphorePermit,
        grant: Option<GrantOwner>,
    },
    Resolved(Vec<IpAddr>),
}

impl Broker {
    pub fn bind(config: &Config) -> io::Result<Self> {
        if config.listeners.len() > crate::MAX_LISTENERS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "too many published listeners",
            ));
        }
        let policy = Arc::new(
            BoxPolicy::new(&config.policy, config.gateways)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?,
        );
        let mut listeners = BTreeMap::new();
        let mut udp_listeners = BTreeMap::new();
        for grant in &config.listeners {
            if grant.grant == 0
                || !is_host_loopback(grant.address.ip())
                || grant.address.port() == 0
                || listeners.contains_key(&grant.grant)
                || udp_listeners.contains_key(&grant.grant)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid published listener grant",
                ));
            }
            let binding = match grant.transport {
                ResourceKind::Tcp => bind_tcp_listener(grant.address).map(|socket| {
                    listeners.insert(grant.grant, socket);
                }),
                ResourceKind::Udp => bind_udp(grant.address).map(|socket| {
                    udp_listeners.insert(grant.grant, socket);
                }),
            };
            if let Err(error) = binding {
                if grant.address.is_ipv6()
                    && config.listeners.iter().any(|other| {
                        other.address.is_ipv4()
                            && other.address.port() == grant.address.port()
                            && other.transport == grant.transport
                    })
                {
                    continue;
                }
                return Err(error);
            }
        }
        Ok(Self {
            policy,
            listeners,
            udp_listeners,
            max_resources: crate::MAX_RESOURCES,
        })
    }

    #[must_use]
    pub fn ready(&self) -> Ready {
        Ready {
            host_service_ports: self.policy.host_service_ports().to_vec(),
        }
    }

    /// Serves one yamux connection until the client closes it; each stream is one operation.
    pub async fn serve(
        self,
        channel: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    ) -> io::Result<()> {
        let shared = Arc::new(Shared {
            policy: self.policy,
            listeners: self.listeners,
            udp_listeners: self.udp_listeners,
            resources: Arc::new(Semaphore::new(self.max_resources)),
            dns_requests: Arc::new(Semaphore::new(crate::MAX_DNS_REQUESTS)),
            resolvers: Arc::new(Semaphore::new(crate::MAX_RESOLVERS)),
            grant_owners: Arc::default(),
        });
        let mut connection = crate::mux::connect(channel, yamux::Mode::Server);
        let mut handlers = JoinSet::new();
        loop {
            tokio::select! {
                inbound = poll_fn(|cx| connection.poll_next_inbound(cx)) => match inbound {
                    Some(Ok(stream)) => {
                        handlers.spawn(handle_stream(shared.clone(), stream.compat()));
                    }
                    None | Some(Err(yamux::ConnectionError::Closed)) => return Ok(()),
                    Some(Err(yamux::ConnectionError::Io(error))) if is_channel_gone(&error) => return Ok(()),
                    Some(Err(error)) => return Err(io::Error::other(error)),
                },
                Some(_) = handlers.join_next(), if !handlers.is_empty() => {}
            }
        }
    }
}

fn is_channel_gone(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset | io::ErrorKind::UnexpectedEof
    )
}

async fn handle_stream(shared: Arc<Shared>, mut stream: Compat<yamux::Stream>) {
    let Ok(Some(open)) = crate::frames::read_frame::<Open>(&mut stream).await else {
        return;
    };
    let Some(prepared) = until_client_leaves(&mut stream, shared.prepare(open)).await else {
        return;
    };
    let reply = prepared
        .as_ref()
        .map(Prepared::opened)
        .map_err(|error| *error);
    if crate::frames::write_frame(&mut stream, &reply)
        .await
        .is_err()
    {
        return;
    }
    match prepared {
        Ok(Prepared::Tcp { tcp, permit, .. }) => {
            tcp::relay(stream, tcp).await;
            drop(permit);
        }
        Ok(Prepared::Udp { udp, permit, grant }) => {
            udp::serve(stream, udp, shared.policy.clone()).await;
            drop((permit, grant));
        }
        Ok(Prepared::Resolved(_)) | Err(_) => {}
    }
}

/// Runs `work` unless the client resets or writes before the `Opened` reply, which abandons it.
async fn until_client_leaves<T>(
    stream: &mut (impl AsyncRead + Unpin),
    work: impl Future<Output = T>,
) -> Option<T> {
    let mut unexpected = [0; 1];
    tokio::select! {
        output = work => Some(output),
        _ = stream.read(&mut unexpected) => None,
    }
}

impl Prepared {
    fn opened(&self) -> Opened {
        match self {
            Self::Tcp { peer, .. } => Opened::Tcp { peer: *peer },
            Self::Udp { .. } => Opened::Udp,
            Self::Resolved(addresses) => Opened::Resolved(addresses.clone()),
        }
    }
}

impl Shared {
    fn claim_resource(&self) -> Result<OwnedSemaphorePermit, Error> {
        self.resources
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::LimitExceeded)
    }

    async fn prepare(&self, open: Open) -> Result<Prepared, Error> {
        match open {
            Open::Tcp {
                peer,
                inline_urgent,
            } => {
                validate_peer(peer)?;
                if !authorize_peer(&self.policy, peer) {
                    return Err(Error::AccessDenied);
                }
                let permit = self.claim_resource()?;
                let tcp = tcp::connect(peer, inline_urgent).await?;
                Ok(Prepared::Tcp { tcp, peer, permit })
            }
            Open::Accept(grant) => {
                let listener = self.listeners.get(&grant).ok_or(Error::AccessDenied)?;
                let _owner = self.grant_owners.claim(grant).await;
                let permit = self.claim_resource()?;
                let (tcp, peer) = tcp::accept(listener).await?;
                Ok(Prepared::Tcp { tcp, peer, permit })
            }
            Open::Udp => Ok(Prepared::Udp {
                permit: self.claim_resource()?,
                udp: udp::open()?,
                grant: None,
            }),
            Open::PublishedUdp(grant) => {
                let socket = self.udp_listeners.get(&grant).ok_or(Error::AccessDenied)?;
                let owner = self.grant_owners.claim(grant).await;
                Ok(Prepared::Udp {
                    permit: self.claim_resource()?,
                    udp: udp::open_published(socket.clone(), grant)?,
                    grant: Some(owner),
                })
            }
            Open::Resolve(name) => {
                if name.len() > terra_policy::MAX_NAME_BYTES {
                    return Err(Error::InvalidArgument);
                }
                let _request = self
                    .dns_requests
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| Error::LimitExceeded)?;
                dns::resolve(&name, &self.policy, self.resolvers.clone())
                    .await
                    .map(Prepared::Resolved)
            }
        }
    }
}
