# Every third-party input that gets downloaded and baked into a terra binary:
# its version, where it comes from, and the sha256 it must have. Included by the
# Makefile, which holds the recipes; nothing here runs anything.
#
# It is a separate file so that "what does the shipped guest actually contain"
# is one page to read and one page to diff — a bump is a reviewable change to
# this file alone, and `git log -p pins.mk` is the provenance history of every
# byte of guest that ships.
#
# Two mechanisms depend on it, so nothing here is decorative:
#   * every hash is checked when its input is downloaded or its payload rebuilds.
#   * the Makefile hashes all of these into $(PIN_STAMP); edit any value and the
#     guest images rebuild. Without that a bumped version is a silent no-op, which
#     is the wrong failure for a security update.
#
# Requires $(ARCH) — include it after those are set.

# --- Terra guest kernel: upstream Linux LTS ---------------------------------
KERNEL_VERSION := 6.18.52
KERNEL_SHA256 := 2b69564f7d4fea0c859b1959ba33709ee6e9139bd100e30a853b57159a8221b8
KERNEL_URL := https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$(KERNEL_VERSION).tar.xz

# --- e2fsprogs --------------------------------------------------------------
# Built static with the zig musl toolchain. `mke2fs` bakes the guest images at
# build time; `resize2fs` ships inside the binary and is injected into the guest,
# which grows them to the configured size. Pinned to the release tarball, not the
# git tree: the tarball ships a generated `configure`, so no autoconf is needed.
E2FSPROGS_VERSION := 1.47.4
E2FSPROGS_SHA256 := da274408bebbfd13a5a2fc3cfc66e3ffff17c48534673aa67f88d49b99123b96
E2FSPROGS_URL := https://mirrors.edge.kernel.org/pub/linux/kernel/people/tytso/e2fsprogs/v$(E2FSPROGS_VERSION)/e2fsprogs-$(E2FSPROGS_VERSION).tar.gz

# --- Alpine root filesystem -------------------------------------------------
ALPINE_VERSION := 3.24.1
# Derived, deliberately: the mirror path is the *branch* (v3.24) while the
# tarball is the *point release* (3.24.1), and hardcoding both is how a bump to
# 3.25.0 ends up fetching from the v3.24 branch. $(basename) drops the last
# dot-suffix: 3.24.1 -> 3.24.
ALPINE_BRANCH := v$(basename $(ALPINE_VERSION))
# Alpine's arch names happen to match `uname -m` for both targets, so $(ARCH)
# indexes the download paths directly.
ALPINE_ARCH := $(ARCH)
ALPINE_URL := https://dl-cdn.alpinelinux.org/alpine/$(ALPINE_BRANCH)/releases/$(ALPINE_ARCH)/alpine-minirootfs-$(ALPINE_VERSION)-$(ALPINE_ARCH).tar.gz

# --- doas -------------------------------------------------------------------
# doas + its sudo-compatible shim, baked into the image so a `sudo:` config can
# let the non-root workload run listed commands as root. ~39 KiB installed, and
# both packages grant nothing until terra writes /etc/doas.conf at boot.
#
# Alpine keeps only the current build of a package on the mirror, so a pin here
# goes 404 rather than stale when the branch moves — check
# `$(ALPINE_PKG_URL)/APKINDEX.tar.gz` for the current -rN and rehash both arches.
ALPINE_PKG_URL := https://dl-cdn.alpinelinux.org/alpine/$(ALPINE_BRANCH)/main/$(ALPINE_ARCH)
DOAS_APK := doas-6.8.2-r8.apk
DOAS_SHIM_APK := doas-sudo-shim-0.2.0-r0.apk

# --- Per-arch hashes --------------------------------------------------------
# Every downloaded guest input is arch-specific and so is its hash — including
# the shim, which is a shell script but ships in a per-arch .apk. Suffixed
# variables rather than a conditional, so adding an arch is three lines and
# forgetting one is the error below rather than an empty (silently failing) hash.
ALPINE_SHA256_x86_64 := 41f73e3cf5fa919b8aa5ca6b30dc48f0da2720776d7423e2a7748211456fe081
ALPINE_SHA256_aarch64 := f55a90f69052c5bd6f92cb09a8f47065970830b194c917a006fb94028e721259
DOAS_SHA256_x86_64 := 1b0198d957fee06b484fc0e23783f03213cc97d8003c5f46b8d940d8ca9f57c8
DOAS_SHA256_aarch64 := 7d35ce1a0a76de43f7621e2099e45bfd83e6d8cf667db657633ab1f374d05f72
DOAS_SHIM_SHA256_x86_64 := 74361be22e06e395703ea5bef1f53a8f21a3350a06748ab6eb404c2c916bb35b
DOAS_SHIM_SHA256_aarch64 := 731e5a2b9e564c66c10fa98f5db2dc8f8c55ae31017ec5068744d31116691822

ALPINE_SHA256 := $(ALPINE_SHA256_$(ARCH))
DOAS_SHA256 := $(DOAS_SHA256_$(ARCH))
DOAS_SHIM_SHA256 := $(DOAS_SHIM_SHA256_$(ARCH))
ifeq ($(and $(ALPINE_SHA256),$(DOAS_SHA256),$(DOAS_SHIM_SHA256)),)
$(error unsupported ARCH '$(ARCH)': no pinned guest hashes. Add ALPINE_SHA256_$(ARCH), DOAS_SHA256_$(ARCH) and DOAS_SHIM_SHA256_$(ARCH) to pins.mk)
endif
