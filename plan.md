# Migration: carve `terra-shared` out of `terra-agent`

The shared surface between host and guest is the wire contract (`contract`:
`frames` + `plan`) and the one filesystem primitive `no_symlinks`. Today both
live in `terra-agent`'s library, so `terra` depends on the agent crate for
code that is not the agent. Move the library to a new package `terra-shared`
and let `terra-agent` be a pure guest binary.

## Steps

**1. New crate `crates/terra-shared/`**

- `Cargo.toml`: package `terra-shared` (lib name auto-derives as
  `terra_shared`, matching the `terra-agent`/`terra_agent` convention),
  `[lints] workspace = true`.
  - deps: `serde`, `serde_json`, `anyhow` (workspace)
  - `[target.'cfg(target_os = "linux")'.dependencies]`: `libc`
    (`no_symlinks` is Linux-only; the lib also builds for macOS/Windows)
  - keep the `unsafe_code` scoping comment, now pointing at its own
    `no_symlinks.rs`
- Move via `git mv`, structure unchanged so no path rewriting beyond the
  crate name:
  - `src/lib.rs` <- terra-agent's lib root (reword the doc: the crate is the
    whole shared surface now; drop the `guest/` line)
  - `src/contract.rs` + `src/contract/{frames,plan}.rs` — unchanged,
    including the `pub use frames::*` / `plan::*` re-exports (all call sites
    use top-level `terra_agent::X` names, so only the crate prefix changes)
  - `src/no_symlinks.rs`

**2. `terra-agent` shrinks to a pure guest binary**

- Cargo.toml: delete the `[lib]` section and the "Two crate roots" comment.
  deps become `anyhow` + `terra-shared = { path = "../terra-shared" }` plus
  the Linux-target `libc`, `pty-process`, `vt100` (serde/serde_json dropped —
  verified unused in `guest/`).
- Adapt the unsafe_code comment (binary-only now).

**3. Workspace + terra**

- root `Cargo.toml`: `members` += `crates/terra-shared`
- `crates/terra/Cargo.toml`: dependency `terra-agent` -> `terra-shared`

**4. Rename references**

- `sed` `terra_agent::` -> `terra_shared::` across the 13 files (8 in
  `crates/terra/src`, 5 in `crates/terra-agent/src/guest`).
- No other occurrence in the repo: README.dev.md / Makefile / kernel config
  references are the guest *binary* path `/terra-agent`, untouched.

**5. Verify**

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test -p terra --lib`
- `cargo test -p terra-shared --lib` (the lib tests move with the files)
- Cargo.lock regenerates; the agent binary target name is untouched, so
  `make dist` / boot flow is unaffected.

## Assumptions

- Package name `terra-shared`, lib `terra_shared`.
- Keep the `contract` submodule layering (call sites never use the
  `contract::` path, so it is free structure).