//! Plans guest boot memory without host capabilities.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

#[allow(unsafe_code, clippy::same_length_and_capacity)]
mod bindings {
    wit_bindgen::generate!({ world: "boot-component", path: "wit" });
}
use bindings::exports;
use exports::terra::boot::boot::{Architecture, Error, Machine, Plan};

mod boot;

struct Component;

impl exports::terra::boot::boot::Guest for Component {
    fn stage(
        machine: Machine,
        kernel_prefix: Vec<u8>,
        kernel_size: u64,
        kernel_command_line: String,
    ) -> Result<Plan, Error> {
        let planner = match machine.architecture {
            Architecture::X86 => boot::plan_x86,
            Architecture::Arm => boot::plan_arm,
        };
        planner(
            &kernel_prefix,
            kernel_size,
            machine.ram_bytes,
            machine.vcpus,
            &kernel_command_line,
            &machine.devices,
        )
    }
}

#[allow(unsafe_code)]
mod component_exports {
    use super::{Component, bindings};
    bindings::export!(Component with_types_in bindings);
}
