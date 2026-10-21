mod dns;
mod peer;
mod tcp;
#[cfg(test)]
mod tests;
mod udp;

pub use self::peer::embeds_ipv4;
use self::peer::validate_peer;
use self::tcp::bind_tcp_listener_socket;
use self::udp::adopt_udp;
pub(crate) use self::udp::bind_udp_socket;
use crate::config::{Config, PublishedListener, Ready};
use crate::{Error, ResourceKind, SocketSource};
use std::collections::{BTreeMap, BTreeSet};
use std::future::{Future, poll_fn};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use terra_policy::BoxPolicy;
use terra_protocol::network::{ListenerGrant, Open, Opened};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt};

pub struct Broker {
    policy: Arc<BoxPolicy>,
    sockets: SocketSource,
    listeners: BTreeMap<ListenerGrant, Arc<TcpListener>>,
    udp_listeners: BTreeMap<ListenerGrant, Arc<udp::OffloadSocket>>,
    max_resources: usize,
}

/// State every stream handler shares.
struct Shared {
    policy: Arc<BoxPolicy>,
    sockets: SocketSource,
    listeners: BTreeMap<ListenerGrant, Arc<TcpListener>>,
    udp_listeners: BTreeMap<ListenerGrant, Arc<udp::OffloadSocket>>,
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

/// Binds the configured published listeners natively, in `config.listeners` order, for the
/// trusted side to hand to a broker it then confines. An IPv6 listener that cannot bind beside an
/// IPv4 listener on the same port and transport is dropped from `config`.
pub fn bind_listeners(config: &mut Config) -> io::Result<Vec<socket2::Socket>> {
    validate_listener_grants(config)?;
    let mut sockets = Vec::with_capacity(config.listeners.len());
    let mut bound = Vec::with_capacity(config.listeners.len());
    for grant in &config.listeners {
        let binding = match grant.transport {
            ResourceKind::Tcp => bind_tcp_listener_socket(grant.address),
            ResourceKind::Udp => bind_udp_socket(grant.address),
        };
        match binding {
            Ok(socket) => {
                sockets.push(socket);
                bound.push(grant.clone());
            }
            Err(_) if is_best_effort_ipv6(config, grant) => {}
            Err(error) => return Err(error),
        }
    }
    config.listeners = bound;
    Ok(sockets)
}

fn is_best_effort_ipv6(config: &Config, grant: &PublishedListener) -> bool {
    grant.address.is_ipv6()
        && config.listeners.iter().any(|other| {
            other.address.is_ipv4()
                && other.address.port() == grant.address.port()
                && other.transport == grant.transport
        })
}

fn validate_listener_grants(config: &Config) -> io::Result<()> {
    if config.listeners.len() > crate::MAX_LISTENERS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "too many published listeners",
        ));
    }
    let mut grants = BTreeSet::new();
    for grant in &config.listeners {
        if grant.grant == 0
            || !terra_policy::is_host_loopback(grant.address.ip())
            || grant.address.port() == 0
            || !grants.insert(grant.grant)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid published listener grant",
            ));
        }
    }
    Ok(())
}

/// A handed-over listener must be bound to its grant's address with its grant's transport.
fn adopt_listener(
    grant: &PublishedListener,
    socket: socket2::Socket,
    listeners: &mut BTreeMap<ListenerGrant, Arc<TcpListener>>,
    udp_listeners: &mut BTreeMap<ListenerGrant, Arc<udp::OffloadSocket>>,
) -> io::Result<()> {
    let expected_kind = match grant.transport {
        ResourceKind::Tcp => socket2::Type::STREAM,
        ResourceKind::Udp => socket2::Type::DGRAM,
    };
    if socket.local_addr()?.as_socket() != Some(grant.address) || socket.r#type()? != expected_kind
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "handed-over listener does not match its grant",
        ));
    }
    match grant.transport {
        ResourceKind::Tcp => {
            socket.set_nonblocking(true)?;
            let listener = TcpListener::from_std(std::net::TcpListener::from(socket))?;
            listeners.insert(grant.grant, Arc::new(listener));
        }
        ResourceKind::Udp => {
            udp_listeners.insert(grant.grant, adopt_udp(socket)?);
        }
    }
    Ok(())
}

impl Broker {
    /// Binds the published listeners and serves outbound traffic from this process.
    pub fn bind(config: &Config) -> io::Result<Self> {
        let mut config = config.clone();
        let listeners = bind_listeners(&mut config)?;
        Self::new(&config, listeners, SocketSource::Native)
    }

    /// Takes `listeners` from [`bind_listeners`] in `config.listeners` order, so the broker
    /// never binds a listener itself.
    pub fn new(
        config: &Config,
        listeners: Vec<socket2::Socket>,
        sockets: SocketSource,
    ) -> io::Result<Self> {
        validate_listener_grants(config)?;
        if listeners.len() != config.listeners.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "handed-over listeners do not match their grants",
            ));
        }
        let policy = Arc::new(
            BoxPolicy::new(&config.policy, crate::config::GATEWAY_ADDRESSES)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?,
        );
        let mut tcp_listeners = BTreeMap::new();
        let mut udp_listeners = BTreeMap::new();
        for (grant, socket) in config.listeners.iter().zip(listeners) {
            adopt_listener(grant, socket, &mut tcp_listeners, &mut udp_listeners)?;
        }
        Ok(Self {
            policy,
            sockets,
            listeners: tcp_listeners,
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
            sockets: self.sockets,
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
            Open::Tcp { peer, options } => {
                validate_peer(peer)?;
                if !self.policy.authorizes(peer) {
                    return Err(Error::AccessDenied);
                }
                let permit = self.claim_resource()?;
                let tcp = tcp::connect(&self.sockets, peer, options).await?;
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
                udp: udp::open(&self.sockets)?,
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
                let _request = self
                    .dns_requests
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| Error::LimitExceeded)?;
                dns::resolve(&name, &self.policy, self.resolvers.clone(), &self.sockets)
                    .await
                    .map(Prepared::Resolved)
            }
        }
    }
}
