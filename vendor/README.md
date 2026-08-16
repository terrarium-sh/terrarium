# vendored submodules

Three git submodules, all pristine — terrarium carries no source of its own in
any of them. Init them with `git submodule update --init`, **not** `--recursive`:
`vendor/smolvm` has its own libkrun/libkrunfw/sdk submodules on ssh URLs that
nothing here builds from.

`vendor/libkrunfw/` — upstream
[libkrunfw](https://github.com/containers/libkrunfw). The top-level Makefile
builds its patched-and-configured Linux 6.12.91 kernel (`vmlinux`), which terra
embeds and boots as an external kernel — so libkrun never `dlopen`s
`libkrunfw.so`.

`vendor/libkrun/` — mainline and unmodified, compiled as an rlib into the static
`terra` binary. No patch, no `libkrun.a`, no symbol weakening.

`vendor/smolvm/` — [cryi/smolvm](https://github.com/cryi/smolvm), for one crate
of it: `crates/smolvm-network`, the host-side virtio-net gateway whose egress
extensions terra depends on (port-gated allow rules, static DNS records,
host-loopback forwarding). It is the code that actually enforces what a sandbox
may reach, so it is here — readable and patchable in the same review as the
policy that configures it,
[`crates/terra/src/network.rs`](../crates/terra/src/network.rs). The whole
monorepo comes along; only that crate is compiled.

The two egress-floor fixes terra's audit found (multicast, and the floor applied
to DNS-learned addresses) are upstream as of `d2573ac`, so this submodule carries
no local changes either. `a_dns_answer_cannot_publish_the_host_sentinel` and
`the_floor_covers_multicast` live upstream beside them; terra's own
`the_floor_covers_multicast_in_every_mode` asserts the same through the built
policy, so a submodule bump that lost them fails a test rather than a review.

The musl C toolchain used to build terra is provided by `zig`
(`scripts/zig-musl-*`); no cross-gcc install is required.

## Bumping libkrun / libkrunfw / smolvm

Each is `git -C vendor/<name> checkout <new-rev>` plus staging the gitlink, then:

- **libkrun:** fix any FFI drift in
  [`crates/terra/src/libkrun_ext.rs`](../crates/terra/src/libkrun_ext.rs) (the C
  ABI is stable within a major). Keep libkrunfw's ABI major matched to it.
- **libkrunfw:** update `KERNEL_VERSION` in the Makefile to match
  `vendor/libkrunfw/Makefile`.
- **smolvm:** nothing extra — but `cargo test --workspace` is not optional here.
  This is the code that decides what a sandbox may reach, and terra's egress
  tests are what catch a floor that quietly narrowed.
- Then `make clean && make build`, `make verify`, and the boot suite
  (`eli tests/e2e/run.lua`) — its egress and ownership assertions are what
  actually catch a behavioural change.
