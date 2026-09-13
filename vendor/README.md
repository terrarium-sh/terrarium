# Vendored sources

The build downloads the Linux source tarball pinned in [`pins.mk`](../pins.mk),
checks its SHA-256, applies Terra's patches and configuration, then embeds the
resulting `vmlinux`. No vendored source checkout or firmware library is a build
or runtime dependency.

For a kernel update, update `KERNEL_VERSION`, `KERNEL_URL`, and `KERNEL_SHA256`
in `pins.mk` together. Preserve the required configuration checks, rebuild the
embedded assets, then run `make verify`, `make test-component-boot`, and
`make test-component-vmm` on a host with `/dev/kvm`.

The musl C toolchain comes from Zig through `scripts/zig-musl-*`. Downloaded
kernel and filesystem build inputs are pinned and checksum-verified by the
build scripts.
