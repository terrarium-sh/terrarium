//! The C header the guest kernel's terra sockets include, rendered from this crate's constants.

use std::fmt::{Display, Write as _};

use crate::{application, network, socket, vsock};

/// Where the rendered header is checked in, relative to the repository root.
pub const HEADER_PATH: &str = "kernel/overlay/include/linux/terra_abi.h";

/// The guest kernel ABI the image markers name: the frames, ports, and socket semantics the
/// kernel shares with the host. Bump it on any change to them.
pub const VERSION: u16 = 1;

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
    define("TERRA_HEADER_BYTES", &application::HEADER_BYTES);
    define("TERRA_ENDPOINT_BYTES", &application::ENDPOINT_BYTES);
    define("TERRA_ENDPOINT_IPV4", &application::ENDPOINT_IPV4);
    define("TERRA_ENDPOINT_IPV6", &application::ENDPOINT_IPV6);
    define(
        "TERRA_ENDPOINT_PORT_OFFSET",
        &application::ENDPOINT_PORT_OFFSET,
    );
    define(
        "TERRA_ENDPOINT_ADDRESS_OFFSET",
        &application::ENDPOINT_ADDRESS_OFFSET,
    );
    define("TERRA_STATUS_BYTES", &application::STATUS_BYTES);
    define(
        "TERRA_TCP_OPEN_FIELDS_BYTES",
        &application::TCP_OPEN_FIELDS_BYTES,
    );
    define(
        "TERRA_TCP_OPEN_INLINE_URGENT",
        &application::TCP_OPEN_INLINE_URGENT_FLAG,
    );
    define(
        "TERRA_TCP_OPEN_KEEPALIVE",
        &application::TCP_OPEN_KEEPALIVE_FLAG,
    );
    define(
        "TERRA_UDP_SEGMENT_FIELD_BYTES",
        &application::UDP_SEGMENT_FIELD_BYTES,
    );
    define(
        "TERRA_UDP_MAX_SEGMENTS",
        &application::MAX_DATAGRAM_SEGMENTS,
    );
    define("TERRA_UDP_CARRIER_BYTES", &application::MAX_FRAME_BYTES);
    define("TERRA_MAX_KEEPALIVE_SECS", &application::MAX_KEEPALIVE_SECS);
    define(
        "TERRA_MAX_KEEPALIVE_PROBES",
        &application::MAX_KEEPALIVE_PROBES,
    );
    define("TERRA_UDP_DATAGRAM", &network::MAX_NETWORK_DATAGRAM_BYTES);
    define("TERRA_OPEN_TIMEOUT_SECS", &application::OPEN_TIMEOUT_SECS);
    define("TERRA_TCP_PORT", &vsock::TCP_PORT);
    define("TERRA_UDP_PORT", &vsock::UDP_PORT);
    for (name, code) in application::OPCODES {
        define(
            &format!("TERRA_OP_{}", screaming_snake(name)),
            &format_args!("{code:#x}"),
        );
    }
    let errnos = std::iter::once("0")
        .chain(
            (1..)
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

    /// Changing what the header carries without a [`super::VERSION`] bump would let an image
    /// built for the old ABI pass its marker check.
    #[test]
    fn header_changes_come_with_a_version_bump() {
        assert_eq!(
            (super::VERSION, fingerprint(super::render().as_bytes())),
            (1, 0xdde2_4019_e3c0_b3b9),
            "the kernel ABI header changed: bump kernel_abi::VERSION, then pin the new pair"
        );
    }

    /// The kernel includes the checked-in copy, so a protocol change must re-render it.
    #[test]
    fn checked_in_header_matches_the_protocol() {
        let checked_in = include_str!("../../../kernel/overlay/include/linux/terra_abi.h");
        assert!(
            super::render() == checked_in,
            "{} is stale; run `make kernel-abi`",
            super::HEADER_PATH
        );
    }
}
