# Vsock device library

`terra-vsock-device` validates virtio-vsock packet headers and owns bounded
connection, queue, credit, half-close, and retirement state for one device.
Guest CID 3 initiates streams to host CID 2:

| Endpoint | Guest source | Host destination | Receive window | Reply/credit bound |
| --- | --- | --- | --- | --- |
| Agent | 6000 | 6000 | 64 KiB | 256 KiB |
| Control | 6001 | 6001 | 32 KiB | 128 KiB |
| TCP | Nonzero, excluding 6000/6001/6004 | 6002 | 48 KiB per flow | 80 KiB per flow |
| UDP | Nonzero, excluding 6000/6001/6004 | 6003 | 48 KiB per flow | 80 KiB per flow |
| Publication (frontend initiated) | 6004 | `0x100000..0x200000` | 48 KiB per flow | 80 KiB per flow |

TCP, UDP, and publication share the frontend's configured admission limit,
at most 128 sockets. Retiring flows keep their slot until the frontend releases
their binding and queued reset. Flow input windows total at most 6 MiB;
flow replies and outstanding send credits total at most 10 MiB. Agent and control
reserves are separate. Guest-initiated publication requests are refused.
TCP publication consumes one stream per accepted host connection; UDP
publication consumes one stream per listener family.
Input queues reserve their receive window as a byte FIFO. Reply queues also cap
items at 128 per connection; rejected tuples retain at most
32 empty resets. These payload limits exclude bounded queue/header metadata
and buffers owned by the caller.

A `ConnectionId` binds endpoint kind, guest source port, and a fresh transport
generation. Host operations reject stale generations. Replies rotate agent,
control, and flow classes; flows rotate within their class. Half-close
preserves accepted input, and host FIN follows queued output. Network failure
retires network connections; physical reset retires every connection.

The library has no Wasm store, worker, or host imports. The combined frontend
owns descriptor access, network authorization, and broker resources. See
[packet.rs](src/packet.rs), [switch.rs](src/switch.rs), [tests.rs](src/tests.rs),
and [the network transport](../../README.dev.md#network-transport).
