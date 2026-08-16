# One fully-static, portable `terra` binary: libkrun is a Cargo dependency
# (mainline, unmodified); the guest kernel is libkrunfw's `vmlinux`, embedded and
# booted as an external kernel — no dlopen, no patch.
#
# musl C toolchain is provided by zig (scripts/zig-musl-*), so no cross-gcc need
# be installed. After a fresh clone: `git submodule update --init` — NOT
# --recursive: vendor/smolvm carries its own libkrun/libkrunfw/sdk submodules on
# ssh URLs, and nothing here builds from them.

CARGO ?= cargo
# Host CPU, and therefore guest CPU: a box runs on the same hardware the host
# does, so the kernel, the rootfs and the agent are all built for $(ARCH). There
# is no cross case to model here — `make cross` builds the *host* binary for
# another platform and is a separate thing. Override only to reproduce another
# arch's images on a machine that can run its binaries.
ARCH ?= $(shell uname -m)
MUSL := $(ARCH)-unknown-linux-musl
LIBKRUNFW_DIR := vendor/libkrunfw
BUILD := build
DIST := dist

# Versions, URLs and sha256s of everything downloaded and baked into the binary
# — the guest kernel, e2fsprogs, the Alpine rootfs and doas. Kept in its own file
# so a bump is a reviewable diff of provenance and nothing else; the recipes that
# consume it are below. Needs $(ARCH) and $(LIBKRUNFW_DIR), hence included here.
# NOTE: the CI cache key hashes this file — keep it listed there.
include pins.mk

KERNEL_GZ := $(BUILD)/vmlinux.gz
# Guest-kernel hardening, appended to libkrunfw's config before the build. Lives
# here rather than as an edit to the submodule's tracked config, so a fresh
# clone builds the same kernel this repo was tested against.
KERNEL_HARDENING := kernel/terrarium-hardening.config

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

# The cargo/musl toolchain (target, linker, rustflags, CC/AR, TERRA_KERNEL_GZ)
# lives in .cargo/config.toml — one source of truth shared by `make`, a bare
# `cargo build`, and rust-analyzer. We only export CC here so the libkrunfw
# kernel sub-build inherits the same zig musl compiler.


# A recipe that dies partway through — Ctrl-C, ENOSPC, the OOM killer — must not
# leave its target behind. Three of the guest images below are written straight
# to `$@` by a `gzip` redirect, so without this a truncated `rootfs.img.gz` sits
# there newer than its prerequisites, `make` calls it up to date, and the next
# build embeds it via `include_bytes!` and ships a guest that cannot boot. The
# kernel recipe already wrote through a `.tmp`; this covers the rest, and every
# recipe added later, for one line.
.DELETE_ON_ERROR:

.PHONY: build verify dist man cross clean

# Every pin from pins.mk, in one string. The guest-image recipes below depend on
# the stamp file this writes, because otherwise they depend on nothing at all: each
# names an output that already exists after the first build, so `make` declares
# it up to date and a bumped $(ALPINE_VERSION) — or a corrected $(KERNEL_SHA256),
# or a new libkrunfw commit — is a silent no-op. That is the wrong failure for a
# security update: the maintainer edits the pin, the build succeeds, and the
# binary still ships the vulnerable guest.
#
# The stamp is rewritten only when the pins actually differ, so its mtime does
# not move for an unrelated edit and a comment does not cost a kernel rebuild.
#
# The libkrunfw pin is read from the submodule's *checked-out* HEAD rather than
# the gitlink in the last commit (`git rev-parse HEAD:vendor/libkrunfw`). The
# normal bump is `git -C vendor/libkrunfw checkout <new>` → `make build` → test →
# commit, and the gitlink does not move until that last step — so reading it would
# leave exactly the window in which the rebuild matters unaware that anything
# changed. Empty (harmlessly) in a tarball export with no `.git`.
PINS := $(KERNEL_VERSION) $(KERNEL_SHA256) $(E2FSPROGS_VERSION) $(E2FSPROGS_SHA256) \
        $(ALPINE_VERSION) $(ALPINE_SHA256) $(DOAS_SHA256) $(DOAS_SHIM_SHA256) \
        $(shell git -C $(LIBKRUNFW_DIR) rev-parse HEAD 2>/dev/null)
PIN_STAMP := $(BUILD)/.pins

.PHONY: FORCE
FORCE:
$(PIN_STAMP): FORCE
	@mkdir -p $(BUILD)
	@echo '$(PINS)' | cmp -s - $@ || { echo '$(PINS)' > $@; echo "pins changed -> guest images will rebuild"; }

## The kernel source tarball, fetched and hash-checked here rather than by
## libkrunfw's own unverified `curl`. Downloading it ourselves is what lets the
## check happen at all: libkrunfw's rule only fires when the file is absent, so a
## cached tarball would never be looked at again.
$(KERNEL_TARBALL):
	mkdir -p $(dir $@)
	curl -fsSL https://cdn.kernel.org/pub/linux/kernel/v6.x/$(KERNEL_VERSION).tar.xz -o $@.tmp
	echo "$(KERNEL_SHA256)  $@.tmp" | sha256sum -c -
	mv $@.tmp $@

## Build the guest vmlinux from libkrunfw sources, stripped and gzipped.
## --strip-all, not just --strip-debug: the loader reads program headers only, so
## the symbol table is 4 MiB the guest never looks at. Gzipped because it ships
## inside the binary — 29.5 MiB of ELF becomes 8.2 MiB, and terra unpacks it once
## into ~/.terra/cache/ rather than per boot.
##
## The config is libkrunfw's plus $(KERNEL_HARDENING): libkrunfw extracts and
## configures the tree first, then the fragment is appended and `olddefconfig`
## resolves it — appended last, so its values win over the ones set above them.
$(KERNEL_GZ): $(KERNEL_TARBALL) $(KERNEL_HARDENING) $(PIN_STAMP)
	echo "$(KERNEL_SHA256)  $(KERNEL_TARBALL)" | sha256sum -c -
	$(MAKE) -C $(LIBKRUNFW_DIR) $(KERNEL_VERSION)
	cat $(KERNEL_HARDENING) >> $(LIBKRUNFW_DIR)/$(KERNEL_VERSION)/.config
	$(MAKE) -C $(LIBKRUNFW_DIR)/$(KERNEL_VERSION) olddefconfig
	$(MAKE) -C $(LIBKRUNFW_DIR) $(KERNEL_VERSION)/vmlinux
	mkdir -p $(BUILD)
	objcopy --strip-all $(LIBKRUNFW_DIR)/$(KERNEL_VERSION)/vmlinux $(BUILD)/vmlinux
	gzip -9nc $(BUILD)/vmlinux > $@.tmp && mv $@.tmp $@

## The sha256 of an embedded blob, written beside it. Included as text by
## include_str! and used as the blob's cache identity (see
## libkrun_ext::blob_name), so nothing hashes the blob at compile or boot time.
## No trailing newline: the digest is concat!'d into a cache file name.
$(BUILD)/%.sha256: $(BUILD)/%
	sha256sum $< | cut -d' ' -f1 | tr -d '\n' > $@

## Static mke2fs — a *build-time* tool only: it bakes the prebaked images below.
## It is not shipped in the binary; the guest grows those images with resize2fs.
$(MKE2FS): $(PIN_STAMP)
	mkdir -p $(BUILD)
	curl -fsSL $(E2FSPROGS_URL) -o $(BUILD)/e2fsprogs.tar.gz
	echo "$(E2FSPROGS_SHA256)  $(BUILD)/e2fsprogs.tar.gz" | sha256sum -c -
	rm -rf $(E2FSPROGS_SRC)
	tar -xzf $(BUILD)/e2fsprogs.tar.gz -C $(BUILD)
	cd $(E2FSPROGS_SRC) && CC=$(abspath scripts/zig-musl-cc) ./configure \
		--host=$(ARCH)-linux-musl --disable-nls --disable-uuidd --disable-fuse2fs \
		--disable-e2initrd-helper --disable-testio-debug LDFLAGS="-static" >/dev/null
	CC=$(abspath scripts/zig-musl-cc) $(MAKE) -C $(E2FSPROGS_SRC) libs
	CC=$(abspath scripts/zig-musl-cc) $(MAKE) -C $(E2FSPROGS_SRC)/misc mke2fs
	cp $(E2FSPROGS_SRC)/misc/mke2fs $(MKE2FS)
	strip $(MKE2FS)

## resize2fs, from the same (already configured) e2fsprogs tree. It ships in the
## binary and is injected into the guest, which grows each image to its
## configured size.
$(RESIZE2FS): $(MKE2FS)
	CC=$(abspath scripts/zig-musl-cc) $(MAKE) -C $(E2FSPROGS_SRC)/resize resize2fs
	cp $(E2FSPROGS_SRC)/resize/resize2fs $@
	strip $@

## Prebaked guest root filesystem, gzipped into the binary. Built root-owned via
## a user namespace, with a pinned 4 KiB block size (mke2fs would otherwise pick
## 1 KiB for an image this small, and the block size cannot change on resize).
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

## Prebaked *empty* filesystem for scratch volumes. Volumes are prebaked for the
## same reason the root is — a host with no mkfs must still be able to create
## one — and because libkrun's disk-format probe truncates an all-zero image by
## one 64 KiB cluster while still advertising its original capacity, which leaves
## the filesystem one cluster longer than the device on the next boot.
$(VOLUME_IMG): $(MKE2FS) $(PIN_STAMP)
	rm -f $(BUILD)/volume.img
	truncate -s $(VOLUME_IMG_MIB)M $(BUILD)/volume.img
	$(MKE2FS) -F -q -t ext4 -b 4096 $(BUILD)/volume.img
	gzip -9 -c $(BUILD)/volume.img > $(VOLUME_IMG)

## Guest agent binary. Phony on purpose: cargo already does the change detection,
## whereas `make` would see an existing file with no prerequisites and silently
## bake a stale agent into the boot volume after any change under crates/terra-agent.
AGENT_BIN := target/$(MUSL)/release/terra-agent
.PHONY: $(AGENT_BIN)
$(AGENT_BIN):
	$(CARGO) build --release -p terra-agent --target $(MUSL)

## Prebaked *boot volume*: a tiny read-only ext4 holding the guest agent,
## resize2fs, and the handful of empty directories stage one mounts over. This is
## what the guest boots — `root=/dev/vda ro init=/terra-agent` — so the boot path
## touches no host directory at all, and the guest kernel has no initramfs support
## (CONFIG_BLK_DEV_INITRD is unset in libkrunfw) to offer as an alternative.
##
## Constant for a given terra build: the same bytes for every box, so it is
## unpacked once into ~/.terra/cache/ and shared, like vmlinux.
BOOT_TREE := $(BUILD)/boot-tree
BOOT_IMG := $(BUILD)/boot.img.gz
BOOT_IMG_MIB := 8
# The two blobs whose sha256 the binary embeds as their cache identity (the
# `%.sha256` rule above; TERRA_*_SHA256 in .cargo/config.toml).
BLOB_SHAS := $(KERNEL_GZ).sha256 $(BOOT_IMG).sha256
$(BOOT_IMG): $(MKE2FS) $(RESIZE2FS) $(AGENT_BIN) $(PIN_STAMP)
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
	gzip -9 -c $(BUILD)/boot.img > $@

## Build the static terra binary (embeds vmlinux and the prebaked images).
build: $(KERNEL_GZ) $(ROOTFS_IMG) $(VOLUME_IMG) $(BOOT_IMG) $(BLOB_SHAS)
	$(CARGO) build --release -p terra --target $(MUSL)

## Format check, lints, and the test suite. Generating the man pages and
## completions is `man`'s job, not this one's — a test that writes to the
## working tree is a surprise nobody wants from `cargo test`. The boot suite is
## separate:
## `make dist && TERRA_BIN=$PWD/dist/terra cargo test -p terra --test boot -- --ignored`
## (needs /dev/kvm).
verify: $(KERNEL_GZ) $(ROOTFS_IMG) $(VOLUME_IMG) $(BOOT_IMG) $(BLOB_SHAS)
	$(CARGO) fmt --all -- --check
	$(CARGO) clippy --workspace --all-targets --target $(MUSL) -- -D warnings
## The crates deny rustdoc::broken_intra_doc_links, which only fires under
## `cargo doc` — without this step a stale [`link`] survives verify.
	$(CARGO) doc --workspace --no-deps --document-private-items --target $(MUSL)
	$(CARGO) test --workspace --target $(MUSL)

## Regenerate man pages + shell completions from the clap CLI. Rendering lives in
## crates/terra/examples/gen-docs.rs so clap_mangen/clap_complete stay
## dev-dependencies, out of the release build's dependency graph.
man:
	$(CARGO) run -p terra --example gen-docs --target $(MUSL)

## Cross-compile the host binary with cargo-zigbuild. The guest agent and the
## prebaked images are whatever $(ARCH) built them for and are NOT rebuilt here —
## a cross-built binary embeds the *building* host's guest set, so it boots a box
## only where the two archs agree. `aarch64-unknown-linux-musl` is deliberately
## absent from the list below for that reason: it builds fine (it is a normal
## `make ARCH=aarch64` target on arm hardware), but cross-building it from x86_64
## would pair an arm host binary with an x86_64 guest, which cannot boot.
##
## Only these targets build today; the rest are blocked upstream in libkrun, not
## in terra (see README, "Platform support"):
##   x86_64-pc-windows-gnu   krun-devices pulls vm-memory with the `rawfd`
##                           feature unconditionally, which compile_error!s on
##                           Windows. One target-gate upstream fixes it.
##   x86_64-apple-darwin     krun-cpuid needs kvm-bindings; libkrun on macOS is
##                           Apple Silicon only.
## Linking an Apple target needs the macOS SDK for the Hypervisor framework;
## point SDKROOT at one (zig cannot synthesise it). Everything up to the final
## link works without it, so `cargo check --target aarch64-apple-darwin` is a
## useful gate on a Linux CI box.
CROSS_TARGETS := x86_64-unknown-linux-musl aarch64-apple-darwin
cross: $(KERNEL_GZ) $(ROOTFS_IMG) $(VOLUME_IMG) $(BOOT_IMG) $(BLOB_SHAS)
	for t in $(CROSS_TARGETS); do \
		echo "--- $$t ---"; \
		$(CARGO) zigbuild --release --target $$t -p terra || exit 1; \
	done

## Assemble dist/terra — the single fully-static, portable binary.
dist: build
	mkdir -p $(DIST)
	# install, not cp: it unlinks first, so a still-running VM holding the old
	# binary (ETXTBSY) never blocks a rebuild.
	install -m 755 target/$(MUSL)/release/terra $(DIST)/terra
	@echo "assembled $(DIST)/terra (fully static — ldd: not a dynamic executable)"

clean:
	$(CARGO) clean
	rm -rf $(DIST) $(BUILD)
	-$(MAKE) -C $(LIBKRUNFW_DIR) clean
