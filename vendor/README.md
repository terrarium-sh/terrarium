# Vendored sources

This directory holds source checked into the tree. Every other build input is
downloaded and verified from the pins in [`pins.mk`](../pins.mk).

Create the source checkout with:

```sh
git submodule update --init --recursive
```

## bubblewrap

[`bubblewrap`](bubblewrap) is a Git submodule pinned to upstream v0.13.0.
Linux builds compile the embedded launcher directly from this checkout with
static libcap and the Zig musl toolchain.

When updating it, change the submodule pointer, `BUBBLEWRAP_VERSION`, and
`BUBBLEWRAP_COMMIT` in [`pins.mk`](../pins.mk) together. `make check-bubblewrap`
verifies the version and checkout commit; extracted release sources also build
without Git metadata. `make source-dist` includes the submodule's complete
source tree.

## Downloaded sources

The build downloads the Linux source tarball pinned in `pins.mk`, checks its
SHA-256, applies Terra's patches and configuration, then embeds `vmlinux`.
Downloaded kernel and filesystem build inputs are pinned and
checksum-verified by the build scripts. The musl C toolchain comes from Zig
through `scripts/toolchain/zig-musl-*`.

For a kernel update, update `KERNEL_VERSION`, `KERNEL_URL`, and
`KERNEL_SHA256` in `pins.mk` together, keep the kernel configuration checks
passing, and rebuild the embedded assets. Then run `make verify`,
`make test-component-boot`, and `make test-component-vmm` on a host with
`/dev/kvm`.
