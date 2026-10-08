# Agent component

`terra-agent-component` bridges the guest's fixed agent stream to authorized
local clients and lifecycle controls. It forwards the configured boot plan and
stop signal and multiplexes client streams with Yamux. Its fixed pipe connects
to the combined device/network frontend; network payloads stay in that frontend.

The agent has its own Wasm store with fixed agent-service streams and clocks.
The host validates the boot plan and adds the host clock and random seed. Session and filesystem operations pass through host-authorized
client streams; the component receives no direct filesystem interface or
guest-memory, device-interrupt or network-broker imports. See [the worker](src/worker.rs),
[the byte-stream adapter](src/byte_stream.rs), [agent.wit](wit/agent.wit), and the native
[agent host adapter](../../crates/terra-runtime/src/component/agent/host.rs).
