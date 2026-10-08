//! Agent role component bindings.

wasmtime::component::bindgen!({
    world: "role",
    path: "../../components/agent/wit",
    exports: { default: async },
    imports: {
        default: trappable,
        "terra:agent/host-service.[method]client.input": store | trappable,
        "terra:agent/host-service.listener": store | trappable,
        "terra:agent/host-service.plan": store | trappable,
        "terra:agent/host-service.stop": store | trappable,
    },
    with: {
        "terra:vsock/role-stream@0.1.0": crate::component::vsock::streams::role_stream,
    },
});

pub(crate) use Role as AgentBindings;
pub use exports::terra::agent::api::Event as AgentEvent;
pub(crate) use terra as wit;
