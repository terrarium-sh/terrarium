# Vsock frontend component

`terra-vsock-frontend-component` handles the stock virtio-vsock device and
restricted network broker in one Wasm store. Its ordinary Rust libraries
[device-transport](../device-transport/src/lib.rs) and
[vsock-device](../vsock-device/src/lib.rs) validate MMIO, split rings, packets,
connection identities, credits, and aggregate budgets.

Guest CID 3 connects to host CID 2: agent port 6000, control port 6001, one
stream per TCP socket on port 6002, and one stream per UDP socket on port 6003.
TCP and UDP complete a bounded opening handshake before carrying raw TCP
bytes or framed UDP datagrams and asynchronous errors. The agent's userspace
control connection carries version/readiness and DNS. Accepted published TCP
connections open frontend-initiated streams to the guest listener on port 6004.
Each published UDP listener family owns at most one publication stream carrying
datagram frames; the broker permits replies only to recent inbound peers.
After a stream closes or resets, the listener retires its old flow and grant;
the next host datagram opens a fresh stream and peer grant without periodic retry.
The frontend calls the existing broker operations directly; there is no native
network role pipe or separate network Wasm store.

Each UDP socket owns one unconnected broker socket. Each destination requires
broker authorization; a denied send preserves the socket for another
destination. Only guest-visible host-service address translations remain in
the frontend; inbound peer authorization and expiry belong to the broker.

The agent stays in a separate store behind one fixed stream. The frontend
imports bounded guest memory, its interrupt, the restricted broker, the
monotonic clock, and the agent stream. It receives no agent filesystem or
session services. Local-only mode denies network endpoints. Broker loss
retires and disables network connections while the agent remains available;
a physical device reset disconnects every connection.

The device reserves agent and control budgets separately from the configured
combined TCP/UDP/publication limit, at most 1024 sockets. Each flow has a 48 KiB
input window and an 80 KiB output bound; all device payload queues total at most
49248 KiB upstream and 82304 KiB in replies. Control allows 16 concurrent DNS
queries. Async broker operations and readiness resume bounded work; TCP
payloads have no guest read/write RPCs or per-chunk IDs. TCP/UDP opening,
control startup, and publication headers have a 30-second deadline.

See [frontend.wit](wit/frontend.wit), [the network transport](../../README.dev.md#network-transport),
and [the authority inventory](../../docs/component-authority.md).
