//! The guest kernel ABI version. The header renderer lives in a submodule so editing it does not
//! rebuild the packaged kernel.

mod header;

pub use header::render;

/// The guest kernel ABI the image markers name: the frames, ports, and socket semantics the
/// kernel shares with the host. Bump it on any change to them.
pub const VERSION: u16 = 1;
