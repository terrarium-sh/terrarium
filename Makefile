# One fully-static `terra` binary embeds a minimal Terra guest kernel and
# trusted AOT device components.
#
# musl C toolchain is provided by zig (scripts/zig-musl-*), so no cross-gcc need
# be installed.

CARGO ?= cargo
CARGO_LOCKED := $(CARGO) --locked
COMPONENT_TOOLCHAIN := $(shell sed -n 's/^channel = "\(.*\)"/\1/p' components/rust-toolchain.toml)
WASM_TOOLS_VERSION := 1.248.0
CARGO_FUZZ_VERSION := 0.13.1
CARGO_AUDIT_VERSION := 0.22.0
WIT_BINDGEN_VERSION := 0.61.1
ZIG_VERSION := 0.16.0
# Host CPU, and therefore guest CPU: a box runs on the same hardware the host
# does, so the kernel, rootfs, and agent are built for $(ARCH). Darwin's `uname
# -m` calls it `arm64`; the guest naming (Linux kernel, Alpine) is `aarch64`.
ARCH ?= $(shell uname -m | sed 's/^arm64$$/aarch64/')
MUSL := $(ARCH)-unknown-linux-musl
NATIVE := $(ARCH)-unknown-linux-gnu
# `ARCH` names the Linux guest. `TERRA_TARGET` names the native host executable
# and the Wasmtime AOT artifacts it embeds. Linux keeps the static-musl release
# default; macOS and Windows pass their native Rust target explicitly.
TERRA_TARGET ?= $(MUSL)
# `mke2fs` runs while producing the guest image, so it targets the Linux build
# machine rather than the guest. This lets an x86_64 Linux builder prepare the
# aarch64 guest payload used by macOS and Windows ARM64 releases.
BUILD_ARCH ?= $(shell uname -m)
MKE2FS_CC_x86_64 := scripts/zig-musl-cc
MKE2FS_CC_aarch64 := scripts/zig-musl-cc-aarch64
MKE2FS_CC := $(MKE2FS_CC_$(BUILD_ARCH))
BUILD := build
DIST := dist
SOURCE_DIST := $(BUILD)/terra-source.tar.gz
ALPINE_SOURCE_DIST := $(BUILD)/alpine-corresponding-source.tar.gz

# Versions, URLs and sha256s of everything downloaded and baked into the binary
# — the guest kernel, e2fsprogs, the Alpine rootfs and doas. Kept in its own file
# so a bump is a reviewable diff of provenance and nothing else; the recipes that
# consume it are below. Needs $(ARCH), hence included here.
# NOTE: the CI cache key hashes this file — keep it listed there.
include pins.mk

KERNEL_GZ := $(BUILD)/vmlinux.gz
E2FSPROGS_SRC := $(BUILD)/e2fsprogs-$(E2FSPROGS_VERSION)
MKE2FS := $(BUILD)/mke2fs
RESIZE2FS := $(BUILD)/resize2fs

# The guest root filesystem is prebaked here, at build time, on Linux — where we
# have mke2fs and user namespaces — and shipped inside the binary as bytes. That
# is what makes terra host-portable: creating a box is `write image; set_len`,
# with no filesystem tooling on the host at all. The guest (always Alpine Linux)
# grows the fs to the configured size on first boot.
ROOTFS_TREE := $(BUILD)/rootfs-tree
ROOTFS_IMG := $(BUILD)/rootfs.img.gz
VOLUME_IMG := $(BUILD)/volume.img.gz
VOLUME_IMG_MIB := 4
# Big enough for the base tree, small enough to ship; the guest resizes up.
ROOTFS_IMG_MIB := 16

# A recipe that dies partway through — Ctrl-C, ENOSPC, the OOM killer — must not
# leave its target behind. Three of the guest images below are written straight
# to `$@` by a `gzip` redirect, so without this a truncated `rootfs.img.gz` sits
# there newer than its prerequisites, `make` calls it up to date, and the next
# build embeds it via `include_bytes!` and ships a guest that cannot boot. The
# kernel recipe already wrote through a `.tmp`; this covers the rest, and every
# recipe added later, for one line.
.DELETE_ON_ERROR:

COMPONENTS := block vsock network fs mem boot vmm policy
COMPONENT_TARGETS := $(addprefix component-,$(COMPONENTS))
COMPONENT_AOT_TARGETS := $(addsuffix -aot,$(COMPONENT_TARGETS))
COMPONENT_MANIFESTS := components/device-transport/Cargo.toml $(addprefix components/,$(addsuffix /Cargo.toml,$(COMPONENTS)))

.PHONY: $(COMPONENT_TARGETS) $(COMPONENT_AOT_TARGETS) guest-assets check-guest-assets host-build host-dist source-dist verify-wit build verify verify-components verify-workspace dist man clean test-component-boot test-component-vmm test-install check-zig

# Pin changes invalidate every embedded guest payload.
PINS := $(ARCH) $(KERNEL_VERSION) $(KERNEL_SHA256) $(E2FSPROGS_VERSION) $(E2FSPROGS_SHA256) \
        $(ALPINE_VERSION) $(ALPINE_SHA256) $(DOAS_SHA256) $(DOAS_SHIM_SHA256)
PIN_STAMP := $(BUILD)/.pins

.PHONY: FORCE
FORCE:
$(PIN_STAMP): FORCE
	@mkdir -p $(BUILD)
	@echo '$(PINS)' | cmp -s - $@ || { echo '$(PINS)' > $@; echo "pins changed -> guest images will rebuild"; }

KERNEL_ARCH_x86_64 := x86
KERNEL_ARCH_aarch64 := arm64
KERNEL_ARCH := $(KERNEL_ARCH_$(ARCH))
KERNEL_TARBALL := $(BUILD)/linux-$(KERNEL_VERSION).tar.xz
KERNEL_SOURCE := $(BUILD)/linux-$(KERNEL_VERSION)
KERNEL_OUTPUT := $(BUILD)/kernel-$(ARCH)
KERNEL_FRAGMENTS := kernel/terra.config kernel/$(ARCH).config
KERNEL_PATCHES := $(sort $(wildcard kernel/patches/*.patch))
KERNEL_INPUTS := $(BUILD)/.kernel-inputs
KERNEL_PATCH_STAMP := $(KERNEL_SOURCE)/.terra-patches
KERNEL_JOBS ?= $(shell nproc)
KERNEL_CC_x86_64 := gcc
KERNEL_CC_aarch64 := aarch64-linux-gnu-gcc
KERNEL_CC ?= $(KERNEL_CC_$(ARCH))
KERNEL_CROSS_aarch64 := aarch64-linux-gnu-
KERNEL_MAKE := scripts/kernel-container.sh $(MAKE) --no-print-directory -C $(KERNEL_SOURCE) O=$(abspath $(KERNEL_OUTPUT)) \
	ARCH=$(KERNEL_ARCH) CC="$(KERNEL_CC)" CROSS_COMPILE=$(KERNEL_CROSS_$(ARCH)) KBUILD_BUILD_USER=terra KBUILD_BUILD_HOST=terra \
	KBUILD_BUILD_VERSION=1 KBUILD_BUILD_TIMESTAMP='2026-09-09 00:00:00 UTC'
KERNEL_BINARY_x86_64 := vmlinux
KERNEL_BINARY_aarch64 := arch/arm64/boot/Image
KERNEL_BINARY := $(KERNEL_BINARY_$(ARCH))

$(KERNEL_INPUTS): FORCE
	@mkdir -p $(BUILD)
	@{ echo '$(ARCH) $(KERNEL_VERSION) $(KERNEL_SHA256)'; cat $(KERNEL_FRAGMENTS) $(KERNEL_PATCHES) kernel/Containerfile scripts/kernel-container.sh | sha256sum; } > $@.tmp
	@cmp -s $@.tmp $@ || cp $@.tmp $@
	@rm -f $@.tmp

ifneq ($(strip $(KERNEL_ARCHIVE_URL)),)
KERNEL_ARCHIVE := $(BUILD)/kernel-download-$(ARCH)-$(KERNEL_ARCHIVE_SHA256).tar.gz
$(KERNEL_ARCHIVE):
	mkdir -p $(BUILD)
	curl -fsSL '$(KERNEL_ARCHIVE_URL)' -o $@.tmp
	echo '$(KERNEL_ARCHIVE_SHA256)  $@.tmp' | sha256sum -c -
	mv $@.tmp $@
endif

ifneq ($(strip $(KERNEL_ARCHIVE)),)
ifeq ($(strip $(KERNEL_ARCHIVE_SHA256)),)
$(error KERNEL_ARCHIVE_SHA256 is required for a prebuilt kernel)
endif
$(KERNEL_GZ): $(KERNEL_ARCHIVE) $(KERNEL_INPUTS) scripts/kernel-artifact.py scripts/check-kernel-config.py
	python3 scripts/kernel-artifact.py import $(KERNEL_ARCHIVE) $(KERNEL_ARCHIVE_SHA256) $(KERNEL_INPUTS) $(BUILD)/vmlinux $(KERNEL_OUTPUT)/.config
	python3 scripts/check-kernel-config.py $(KERNEL_OUTPUT)/.config $(KERNEL_FRAGMENTS)
else
$(KERNEL_TARBALL):
	mkdir -p $(BUILD)
	curl -fsSL $(KERNEL_URL) -o $@.tmp
	echo '$(KERNEL_SHA256)  $@.tmp' | sha256sum -c -
	mv $@.tmp $@

$(KERNEL_SOURCE)/Makefile: $(KERNEL_TARBALL) $(KERNEL_INPUTS)
	echo '$(KERNEL_SHA256)  $(KERNEL_TARBALL)' | sha256sum -c -
	rm -rf $(KERNEL_SOURCE) $(KERNEL_OUTPUT)
	tar -xf $(KERNEL_TARBALL) -C $(BUILD)
	touch $@

$(KERNEL_PATCH_STAMP): $(KERNEL_SOURCE)/Makefile $(KERNEL_PATCHES)
	set -e; for patch in $(abspath $(KERNEL_PATCHES)); do git -C $(KERNEL_SOURCE) apply --check $$patch && git -C $(KERNEL_SOURCE) apply $$patch; done
	sha256sum $(KERNEL_PATCHES) </dev/null > $@

$(KERNEL_OUTPUT)/.config: $(KERNEL_PATCH_STAMP) $(KERNEL_INPUTS) $(KERNEL_FRAGMENTS)
	mkdir -p $(KERNEL_OUTPUT)
	cat $(KERNEL_FRAGMENTS) > $(KERNEL_OUTPUT)/seed.config
	$(KERNEL_MAKE) KCONFIG_ALLCONFIG=$(abspath $(KERNEL_OUTPUT)/seed.config) allnoconfig
	python3 scripts/check-kernel-config.py $@ $(KERNEL_FRAGMENTS)

$(KERNEL_GZ): $(KERNEL_OUTPUT)/.config $(KERNEL_INPUTS) scripts/check-kernel-config.py
	python3 scripts/check-kernel-config.py $(KERNEL_OUTPUT)/.config $(KERNEL_FRAGMENTS)
	$(KERNEL_MAKE) -j$(KERNEL_JOBS) $(notdir $(KERNEL_BINARY))
	scripts/kernel-container.sh $(if $(filter x86_64,$(ARCH)),objcopy --strip-all,cp) $(KERNEL_OUTPUT)/$(KERNEL_BINARY) $(BUILD)/vmlinux
	gzip -9nc $(BUILD)/vmlinux > $@.tmp && mv $@.tmp $@
endif

.PHONY: kernel kernel-export
kernel: $(KERNEL_GZ)
kernel-export: $(KERNEL_GZ)
	python3 scripts/kernel-artifact.py export $(KERNEL_GZ) $(KERNEL_OUTPUT)/.config $(KERNEL_INPUTS) $(BUILD)/terra-kernel-$(ARCH).tar.gz
	sha256sum $(BUILD)/terra-kernel-$(ARCH).tar.gz > $(BUILD)/terra-kernel-$(ARCH).tar.gz.sha256

## The sha256 of an embedded blob, written beside it. Included as text by
## include_str! and used as the blob's cache identity (see
## vm::image::blob_name), so nothing hashes the blob at compile or boot time.
## No trailing newline: the digest is concat!'d into a cache file name.
$(BUILD)/%.sha256: $(BUILD)/%
	sha256sum $< | cut -d' ' -f1 | tr -d '\n' > $@

## Static mke2fs — a *build-time* tool only: it bakes the prebaked images below.
## It is not shipped in the binary; the guest grows those images with resize2fs.
$(MKE2FS): $(PIN_STAMP)
	$(MAKE) check-zig
	mkdir -p $(BUILD)
	curl -fsSL $(E2FSPROGS_URL) -o $(BUILD)/e2fsprogs.tar.gz
	echo "$(E2FSPROGS_SHA256)  $(BUILD)/e2fsprogs.tar.gz" | sha256sum -c -
	rm -rf $(E2FSPROGS_SRC)
	tar -xzf $(BUILD)/e2fsprogs.tar.gz -C $(BUILD)
	cd $(E2FSPROGS_SRC) && CC=$(abspath $(MKE2FS_CC)) ./configure \
		--host=$(BUILD_ARCH)-linux-musl --disable-nls --disable-uuidd --disable-fuse2fs \
		--disable-e2initrd-helper --disable-testio-debug LDFLAGS="-static" >/dev/null
	CC=$(abspath $(MKE2FS_CC)) $(MAKE) -C $(E2FSPROGS_SRC) libs
	CC=$(abspath $(MKE2FS_CC)) $(MAKE) -C $(E2FSPROGS_SRC)/misc mke2fs
	cp $(E2FSPROGS_SRC)/misc/mke2fs $(MKE2FS)
	strip $(MKE2FS)

# resize2fs runs inside the guest; cross builds must not reuse the host mke2fs binary's tree.
ifeq ($(ARCH),$(BUILD_ARCH))
$(RESIZE2FS): $(MKE2FS)
	CC=$(abspath $(MKE2FS_CC)) $(MAKE) -C $(E2FSPROGS_SRC)/resize resize2fs
	cp $(E2FSPROGS_SRC)/resize/resize2fs $@
	strip $@
else
GUEST_E2FSPROGS_SRC := $(BUILD)/e2fsprogs-guest-$(ARCH)
$(RESIZE2FS): $(MKE2FS)
	mkdir -p $(GUEST_E2FSPROGS_SRC)
	tar -xzf $(BUILD)/e2fsprogs.tar.gz --strip-components=1 -C $(GUEST_E2FSPROGS_SRC)
	cd $(GUEST_E2FSPROGS_SRC) && CC=$(abspath $(MKE2FS_CC_$(ARCH))) AR=$(abspath scripts/zig-musl-ar) ./configure \
		--host=$(ARCH)-linux-musl --disable-nls --disable-uuidd --disable-fuse2fs \
		--disable-e2initrd-helper --disable-testio-debug LDFLAGS="-static -s" >/dev/null
	$(MAKE) -C $(GUEST_E2FSPROGS_SRC) libs
	$(MAKE) -C $(GUEST_E2FSPROGS_SRC)/resize resize2fs
	cp $(GUEST_E2FSPROGS_SRC)/resize/resize2fs $@
endif

## Prebaked guest root filesystem, gzipped into the binary. Built root-owned via
## a user namespace, with a pinned 4 KiB block size (mke2fs would otherwise pick
## 1 KiB for an image this small, and the block size cannot change on resize).
##
## If `unshare` here dies with "write failed /proc/self/uid_map: Operation not
## permitted", the host restricts unprivileged user namespaces: Ubuntu 24.04 and
## derivatives ship kernel.apparmor_restrict_unprivileged_userns=1, which lets
## the namespace be created but leaves no capabilities in it. `sudo sysctl -w
## kernel.apparmor_restrict_unprivileged_userns=0` is the fix; CI does the same.
## fakeroot is not an alternative — $(MKE2FS) is static, so there is no dynamic
## linker for its LD_PRELOAD to hook.
$(ROOTFS_IMG): $(MKE2FS) $(PIN_STAMP)
	mkdir -p $(ROOTFS_TREE)
	curl -fsSL $(ALPINE_URL) -o $(BUILD)/alpine-minirootfs.tar.gz
	echo "$(ALPINE_SHA256)  $(BUILD)/alpine-minirootfs.tar.gz" | sha256sum -c -
	# -p keeps the archive's modes (notably /tmp's 1777); without it tar applies
	# the caller's umask and a non-root workload cannot write /tmp.
	rm -rf $(ROOTFS_TREE) && mkdir -p $(ROOTFS_TREE)
	tar -p --no-same-owner -xzf $(BUILD)/alpine-minirootfs.tar.gz -C $(ROOTFS_TREE)
	# doas (setuid) + the sudo shim; -p keeps the setuid bit, and building the
	# image in a user namespace makes it setuid *root*.
	curl -fsSL $(ALPINE_PKG_URL)/$(DOAS_APK) -o $(BUILD)/$(DOAS_APK)
	echo "$(DOAS_SHA256)  $(BUILD)/$(DOAS_APK)" | sha256sum -c -
	curl -fsSL $(ALPINE_PKG_URL)/$(DOAS_SHIM_APK) -o $(BUILD)/$(DOAS_SHIM_APK)
	echo "$(DOAS_SHIM_SHA256)  $(BUILD)/$(DOAS_SHIM_APK)" | sha256sum -c -
	tar -pxzf $(BUILD)/$(DOAS_APK) -C $(ROOTFS_TREE) usr etc
	tar -pxzf $(BUILD)/$(DOAS_SHIM_APK) -C $(ROOTFS_TREE) usr
	rm -f $(BUILD)/rootfs.img
	truncate -s $(ROOTFS_IMG_MIB)M $(BUILD)/rootfs.img
	unshare -U -r $(MKE2FS) -F -q -t ext4 -b 4096 -d $(ROOTFS_TREE) $(BUILD)/rootfs.img
	gzip -9 -c $(BUILD)/rootfs.img > $(ROOTFS_IMG)

## Prebaked *empty* filesystem for scratch volumes. Volumes are prebaked so a
## host with no mkfs can still create one.
$(VOLUME_IMG): $(MKE2FS) $(PIN_STAMP)
	rm -f $(BUILD)/volume.img
	truncate -s $(VOLUME_IMG_MIB)M $(BUILD)/volume.img
	$(MKE2FS) -F -q -t ext4 -b 4096 $(BUILD)/volume.img
	gzip -9 -c $(BUILD)/volume.img > $(VOLUME_IMG)

## Guest agent binary. Cargo decides whether the binary changed; FORCE keeps its
## dependency graph checked without rebaking the boot image unnecessarily.
AGENT_BIN := target/$(MUSL)/release/terra-agent
$(AGENT_BIN): FORCE
	$(CARGO_LOCKED) build --release -p terra-agent --target $(MUSL)

# Built-in drivers let the kernel boot directly from this small read-only disk.
BOOT_TREE := $(BUILD)/boot-tree
BOOT_IMG := $(BUILD)/boot.img.gz
BOOT_IMG_MIB := 8
# The two blobs whose sha256 the binary embeds as their cache identity (the
# `%.sha256` rule above; TERRA_*_SHA256 in .cargo/config.toml).
BLOB_SHAS := $(KERNEL_GZ).sha256 $(BOOT_IMG).sha256
$(BOOT_IMG): $(MKE2FS) $(RESIZE2FS) $(AGENT_BIN) $(PIN_STAMP) Makefile
	rm -rf $(BOOT_TREE)
	# /dev is where the kernel auto-mounts devtmpfs (CONFIG_DEVTMPFS_MOUNT), which
	# is what gives init a console and the disk nodes; /proc, /sys and /mnt are
	# mounted over by the agent. They must exist: the root is read-only.
	mkdir -p $(BOOT_TREE)/dev $(BOOT_TREE)/proc $(BOOT_TREE)/sys $(BOOT_TREE)/mnt
	install -m 755 $(AGENT_BIN) $(BOOT_TREE)/terra-agent
	install -m 755 $(RESIZE2FS) $(BOOT_TREE)/terra-resize2fs
	rm -f $(BUILD)/boot.img
	truncate -s $(BOOT_IMG_MIB)M $(BUILD)/boot.img
	unshare -U -r $(MKE2FS) -F -q -t ext4 -b 4096 -d $(BOOT_TREE) $(BUILD)/boot.img
	gzip -9 -c $(BUILD)/boot.img > $(BOOT_IMG)

## Build the static terra binary (embeds vmlinux, prebaked images, and trusted
## component artifacts).
build: $(COMPONENT_AOT_TARGETS) $(KERNEL_GZ) $(ROOTFS_IMG) $(VOLUME_IMG) $(BOOT_IMG) $(BLOB_SHAS)
	$(CARGO_LOCKED) build --release -p terra --target $(TERRA_TARGET)

# Guest payloads are produced on Linux and then embedded by each native host
# build. This keeps macOS and Windows releases free of host mkfs/container
# tooling while preserving one architecture-specific Linux guest per executable.
guest-assets: $(KERNEL_GZ) $(ROOTFS_IMG) $(VOLUME_IMG) $(BOOT_IMG) $(BLOB_SHAS)

# A host build receives these architecture-matched files from a Linux guest
# build. Check them as inputs so a fresh macOS checkout never tries to rebuild
# the guest kernel, rootfs, or Linux agent because artifact mtimes changed.
check-guest-assets:
	@for asset in $(KERNEL_GZ) $(ROOTFS_IMG) $(VOLUME_IMG) $(BOOT_IMG) $(BLOB_SHAS); do test -s $$asset || { echo "missing staged guest asset: $$asset" >&2; exit 1; }; done

host-build: check-guest-assets $(COMPONENT_AOT_TARGETS)
	$(CARGO_LOCKED) build --release -p terra --target $(TERRA_TARGET)

test-component-vmm: dist
	TERRA_BIN=$(abspath $(DIST)/terra) $(CARGO_LOCKED) test -p terra --test boot --test memory -- --ignored

## Components use their pinned nightly wasm toolchain outside the native
## workspace, then the trusted native compiler produces each embedded AOT blob.
BLOCK_COMPONENT_AOT := $(BUILD)/terra-block-component.cwasm
verify-wit:
	python3 scripts/check-wit-links.py

$(COMPONENT_TARGETS): verify-wit

$(COMPONENT_TARGETS): component-%:
	RUSTUP_TOOLCHAIN=$(COMPONENT_TOOLCHAIN) $(CARGO_LOCKED) build --release --target wasm32-wasip3 --manifest-path components/$*/Cargo.toml
	wasm-tools validate --features cm-async components/$*/target/wasm32-wasip3/release/terra_$*_component.wasm

$(COMPONENT_AOT_TARGETS): component-%-aot: component-%
	mkdir -p $(BUILD)
	$(CARGO_LOCKED) run --target $(TERRA_TARGET) -p terra-runtime --features compiler --example precompile-component -- components/$*/target/wasm32-wasip3/release/terra_$*_component.wasm $(BUILD)/terra-$*-component.cwasm $(if $(filter policy,$*),--policy,)

test-component-boot: $(COMPONENT_AOT_TARGETS) $(KERNEL_GZ) $(ROOTFS_IMG) $(BOOT_IMG) $(BLOB_SHAS)
	$(CARGO_LOCKED) test -p terra-platform --lib -- --ignored --nocapture

## Format check, lints, and the test suite. Generating the man pages and
## completions is `man`'s job, not this one's — a test that writes to the
## working tree is a surprise nobody wants from `cargo test`. The boot suite is
## separate:
## `make dist && TERRA_BIN=$PWD/dist/terra cargo test -p terra --test boot -- --ignored`
## (needs /dev/kvm).
verify: verify-components verify-workspace

verify-workspace:
	python3 -B scripts/check-tool-versions.py
	python3 -B scripts/test-kernel-tools.py
	python3 -B scripts/test-alpine-sources.py
	scripts/test-install.sh
	$(CARGO) fmt --all -- --check
	$(CARGO) fmt --manifest-path fuzz/Cargo.toml -- --check
	$(CARGO_LOCKED) clippy --workspace --all-targets --target $(MUSL) -- -D warnings
	$(CARGO_LOCKED) clippy --manifest-path fuzz/Cargo.toml --all-targets -- -D warnings
## The crates deny rustdoc::broken_intra_doc_links, which only fires under
## `cargo doc` — without this step a stale [`link`] survives verify.
	$(CARGO_LOCKED) doc --workspace --no-deps --document-private-items --target $(MUSL)
	$(CARGO_LOCKED) test --workspace --target $(MUSL)
	$(CARGO_LOCKED) test -p terra-runtime --target $(MUSL) --features thread-experiments --test shared_component_memory --test shared_worker_memory

test-install:
	scripts/test-install.sh

verify-components: $(COMPONENT_AOT_TARGETS) $(KERNEL_GZ) $(ROOTFS_IMG) $(VOLUME_IMG) $(BOOT_IMG) $(BLOB_SHAS)
	set -e; for manifest in $(COMPONENT_MANIFESTS); do RUSTUP_TOOLCHAIN=$(COMPONENT_TOOLCHAIN) $(CARGO) fmt --manifest-path $$manifest -- --check; done
	set -e; for manifest in $(COMPONENT_MANIFESTS); do RUSTUP_TOOLCHAIN=$(COMPONENT_TOOLCHAIN) $(CARGO_LOCKED) clippy --target wasm32-wasip3 --manifest-path $$manifest -- -D warnings; done
	set -e; for manifest in $(COMPONENT_MANIFESTS); do RUSTUP_TOOLCHAIN=$(COMPONENT_TOOLCHAIN) $(CARGO_LOCKED) clippy --all-targets --target $(NATIVE) --manifest-path $$manifest -- -D warnings; done
	set -e; for manifest in $(COMPONENT_MANIFESTS); do RUSTUP_TOOLCHAIN=$(COMPONENT_TOOLCHAIN) $(CARGO_LOCKED) test --target $(NATIVE) --manifest-path $$manifest; done

check-zig:
	@test "$$(zig version)" = "$(ZIG_VERSION)" || { echo "need Zig $(ZIG_VERSION), found $$(zig version)" >&2; exit 1; }

## Regenerate man pages + shell completions from the clap CLI. Rendering lives in
## crates/terra/examples/gen-docs.rs so clap_mangen/clap_complete stay
## dev-dependencies, out of the release build's dependency graph.
man:
	$(CARGO_LOCKED) run -p terra --example gen-docs --target $(TERRA_TARGET)

## Assemble dist/terra — the single fully-static, portable binary.
dist: build man

host-dist: host-build man

dist host-dist:
	mkdir -p $(DIST)
	mkdir -p $(DIST)/LICENSES
	# install, not cp: it unlinks first, so a still-running VM holding the old
	# binary (ETXTBSY) never blocks a rebuild.
	install -m 755 target/$(TERRA_TARGET)/release/terra $(DIST)/terra
	install -m 644 LICENSE NOTICE $(DIST)
	install -m 644 packaging/licenses/GPL-2.0.txt packaging/licenses/applevisor-MIT.txt packaging/licenses/uds_windows-MIT.txt packaging/licenses/uds_windows-THIRDPARTYNOTICES.txt $(DIST)/LICENSES
	cp -R packaging/man packaging/completions $(DIST)
	@echo "assembled $(DIST)/terra for $(TERRA_TARGET)"

## Source inputs for the GPL programs embedded in a release. The release
## workflow publishes this archive beside the platform archives.
$(ALPINE_SOURCE_DIST): $(ROOTFS_IMG) scripts/alpine-sources.sh
	scripts/alpine-sources.sh

source-dist: $(KERNEL_TARBALL) $(MKE2FS) $(ROOTFS_IMG) $(ALPINE_SOURCE_DIST)
	git archive --format=tar --prefix=terrarium/ HEAD > $(BUILD)/terra-source.tar
	tar --append --file=$(BUILD)/terra-source.tar --transform='s|^$(BUILD)/|terrarium/$(BUILD)/|' $(KERNEL_TARBALL) $(BUILD)/e2fsprogs.tar.gz $(ALPINE_SOURCE_DIST) $(BUILD)/alpine-minirootfs.tar.gz $(BUILD)/$(DOAS_APK) $(BUILD)/$(DOAS_SHIM_APK)
	gzip -9nc $(BUILD)/terra-source.tar > $(SOURCE_DIST)
	rm -f $(BUILD)/terra-source.tar

clean:
	$(CARGO) clean
	rm -rf $(DIST) $(BUILD)
