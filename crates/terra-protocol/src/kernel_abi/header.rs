//! The C header the guest kernel's terra sockets include, rendered from this crate's constants.

use std::fmt::{Display, Write as _};

use crate::{application, socket, vsock};

#[must_use]
pub fn render() -> String {
    let mut header = String::from(
        "/* SPDX-License-Identifier: GPL-2.0-only */\n\
         /* Rendered from crates/terra-protocol by `make kernel-abi`; do not edit. */\n\
         #ifndef _LINUX_TERRA_ABI_H\n\
         #define _LINUX_TERRA_ABI_H\n\n",
    );
    let mut define = |name: &str, value: &dyn Display| {
        let _ = writeln!(header, "#define {name} {value}");
    };
    macro_rules! define_constants {
        ($($module:ident::$name:ident),* $(,)?) => {
            $(define(concat!("TERRA_", stringify!($name)), &$module::$name);)*
        };
    }
    define_constants!(
        application::HEADER_BYTES,
        application::ENDPOINT_BYTES,
        application::ENDPOINT_IPV4,
        application::ENDPOINT_IPV6,
        application::ENDPOINT_PORT_OFFSET,
        application::ENDPOINT_ADDRESS_OFFSET,
        application::STATUS_BYTES,
        application::TCP_OPEN_FIELDS_BYTES,
        application::TCP_OPEN_FRAME_BYTES,
        application::TCP_OPEN_INLINE_URGENT_FLAG,
        application::TCP_OPEN_KEEPALIVE_FLAG,
        application::UDP_FRAME_OVERHEAD_BYTES,
        application::MAX_UDP_RUN_BYTES,
        application::MAX_DATAGRAM_SEGMENTS,
        application::MAX_FRAME_BYTES,
        application::MAX_KEEPALIVE_SECS,
        application::MAX_KEEPALIVE_PROBES,
        application::OPEN_TIMEOUT_SECS,
        application::MAX_NETWORK_DATAGRAM_BYTES,
        vsock::HOST_CID,
        vsock::GUEST_CID,
        vsock::AGENT_PORT,
        vsock::TCP_PORT,
        vsock::UDP_PORT,
        vsock::PUBLICATION_PORT,
        vsock::FLOW_REPLY_BYTES,
    );
    for (name, code) in application::OPCODES {
        define(
            &format!("TERRA_OP_{}", screaming_snake(name)),
            &format_args!("{code:#x}"),
        );
    }
    let errnos = std::iter::once("0")
        .chain(
            (1_u16..)
                .map_while(socket::Error::decode)
                .map(socket::Error::errno_name),
        )
        .collect::<Vec<_>>()
        .join(", ");
    define("TERRA_ERRNOS", &format_args!("{{ {errnos} }}"));
    header.push_str("\n#endif\n");
    header
}

fn screaming_snake(camel: &str) -> String {
    let mut snake = String::new();
    for (index, character) in camel.char_indices() {
        if index > 0 && character.is_ascii_uppercase() {
            snake.push('_');
        }
        snake.push(character.to_ascii_uppercase());
    }
    snake
}

#[cfg(test)]
mod tests {
    /// FNV-1a, whose output, unlike std's hasher, never changes between Rust releases.
    fn fingerprint(bytes: &[u8]) -> u64 {
        bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
            (hash ^ u64::from(*byte)).wrapping_mul(0x0100_0000_01b3)
        })
    }

    /// Changing what the header carries without a [`crate::kernel_abi::VERSION`] bump would let an image
    /// built for the old ABI pass its marker check.
    #[test]
    fn header_changes_come_with_a_version_bump() {
        assert_eq!(
            (
                crate::kernel_abi::VERSION,
                fingerprint(super::render().as_bytes())
            ),
            (1, 0xeff9_5a97_0be6_2bcd),
            "the kernel ABI header changed: bump kernel_abi::VERSION, then pin the new pair"
        );
    }

    /// The kernel includes the checked-in copy, so a protocol change must re-render it.
    #[test]
    fn checked_in_header_matches_the_protocol() {
        let checked_in = include_str!("../../../../kernel/overlay/include/linux/terra_abi.h");
        assert!(
            super::render() == checked_in,
            "kernel/overlay/include/linux/terra_abi.h is stale; run `make kernel-abi`"
        );
    }
}
