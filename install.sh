#!/bin/sh
# Installs the latest terra release (or TERRA_VERSION=x.y.z), verifying its
# release checksum before anything is put in place. When GitHub CLI is present,
# it verifies the release attestation too. On Linux it also installs the
# release's matching seccomp policy bundle at ~/.terra/config/seccomp.
set -eu

prerelease=no
for arg in "$@"; do
  case "$arg" in
    --prerelease) prerelease=yes ;;
    *)
      echo "usage: install.sh [--prerelease]" >&2
      exit 2
      ;;
  esac
done

repo="terrarium-sh/terrarium"
version="${TERRA_VERSION:-latest}"
case "$version" in
  latest | v*) ;;
  *) version="v$version" ;;
esac

os=$(uname -s)
arch=$(uname -m)
bin=/usr/local/bin
if [ "$os" = Darwin ] && [ -d /opt/homebrew/bin ]; then
  bin=/opt/homebrew/bin
fi

policy_target=
case "$os/$arch" in
  Linux/x86_64)
    asset=terra-x86_64-linux
    policy_target=x86_64-unknown-linux-musl
    ;;
  Linux/aarch64 | Linux/arm64)
    asset=terra-aarch64-linux
    policy_target=aarch64-unknown-linux-musl
    ;;
  Darwin/arm64)
    asset=terra-aarch64-macos
    ;;
  Darwin/x86_64)
    if [ "$(sysctl -in sysctl.proc_translated 2>/dev/null || true)" != 1 ]; then
      echo "terrarium: no release for Intel macOS yet" >&2
      exit 1
    fi
    asset=terra-aarch64-macos
    ;;
  *)
    echo "terrarium: no release for $os/$arch yet" >&2
    exit 1
    ;;
esac

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

if [ "$version" = latest ] && [ "$prerelease" = yes ]; then
  # releases/latest/download resolves to the newest stable release only.
  curl -fsSL --proto '=https' --tlsv1.2 \
    "https://api.github.com/repos/$repo/releases?per_page=1" -o "$tmp/releases.json"
  version=$(sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' "$tmp/releases.json" | head -n 1)
  if [ -z "$version" ]; then
    echo "terrarium: could not resolve the newest release" >&2
    exit 1
  fi
fi

if [ "$version" = "latest" ]; then
  base="https://github.com/$repo/releases/latest/download"
else
  base="https://github.com/$repo/releases/download/$version"
fi

curl -fsSL --proto '=https' --tlsv1.2 "$base/SHA256SUMS" -o "$tmp/SHA256SUMS"
gh=$(command -v gh || true)

is_released() {
  awk -v a="$1" '$2 == a { found = 1 } END { exit !found }' "$tmp/SHA256SUMS"
}

fetch_verified() {
  curl -fsSL --proto '=https' --tlsv1.2 "$base/$1" -o "$tmp/$1"
  # The checksum comes from the same release ref as the archive, so a tampered
  # mirror of one alone cannot pass; the mismatch must be said out loud.
  expected=$(awk -v a="$1" '$2 == a { print $1 }' "$tmp/SHA256SUMS")
  if [ -z "$expected" ]; then
    echo "terrarium: $1 is not in this release's SHA256SUMS - refusing to install" >&2
    exit 1
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    got=$(sha256sum < "$tmp/$1" | cut -d' ' -f1)
  else
    got=$(shasum -a 256 < "$tmp/$1" | cut -d' ' -f1)
  fi
  if [ "$got" != "$expected" ]; then
    echo "terrarium: CHECKSUM MISMATCH for $1" >&2
    echo "  expected: $expected" >&2
    echo "  got:      $got" >&2
    echo "nothing was installed" >&2
    exit 1
  fi
  if [ -n "$gh" ] && ! "$gh" attestation verify "$tmp/$1" --repo "$repo" --signer-workflow "$repo/.github/workflows/release.yml"; then
    echo "terrarium: release attestation verification failed" >&2
    exit 1
  fi
}

archive="$asset.tar.gz"
fetch_verified "$archive"
# Terra loads ~/.terra/config/seccomp without checking which executable it was
# built for, so a bundle left from another release would stay in force.
policy=
if [ -n "$policy_target" ] && is_released "terra-seccomp-$policy_target.tar.gz"; then
  fetch_verified "terra-seccomp-$policy_target.tar.gz"
  mkdir "$tmp/policy"
  tar -xzf "$tmp/terra-seccomp-$policy_target.tar.gz" -C "$tmp/policy"
  if ! [ -f "$tmp/policy/manifest.json" ]; then
    echo "terrarium: terra-seccomp-$policy_target.tar.gz does not contain a policy manifest" >&2
    exit 1
  fi
  policy="$tmp/policy"
fi
if [ -z "$gh" ]; then
  echo "terrarium: GitHub CLI is unavailable; checksum verified but attestation was not" >&2
fi

mkdir "$tmp/extract"
tar -xzf "$tmp/$archive" -C "$tmp/extract"
if ! [ -f "$tmp/extract/terra" ]; then
  echo "terrarium: $archive does not contain terra" >&2
  exit 1
fi
mv "$tmp/extract/terra" "$tmp/terra"
chmod +x "$tmp/terra"

if [ -e "$bin/terra" ] && ! [ -f "$bin/terra" ] && ! [ -L "$bin/terra" ]; then
  echo "terrarium: $bin/terra exists but is not a regular file - move it aside first" >&2
  exit 1
fi
if install -d "$bin" 2>/dev/null &&
   install -m 755 "$tmp/terra" "$bin/terra" 2>/dev/null; then
  :
else
  printf 'install to %s needs root privileges - run sudo install? [y/N] ' "$bin"
  read -r answer
  case "$answer" in
    y | Y | yes | Yes)
      sudo=$(command -v sudo || true)
      if [ -z "$sudo" ]; then
        echo "terrarium: sudo is unavailable" >&2
        exit 1
      fi
      "$sudo" install -d "$bin" &&
        "$sudo" install -m 755 "$tmp/terra" "$bin/terra"
      ;;
    *)
      echo "installation was not completed" >&2
      exit 1
      ;;
  esac
fi
echo "installed terra at $bin/terra"

if [ -n "$policy_target" ]; then
  config="$HOME/.terra/config"
  (umask 077 && mkdir -p "$config")
  if [ -n "$policy" ]; then
    rm -rf "$config/.seccomp.new" "$config/seccomp.previous"
    cp -R "$policy" "$config/.seccomp.new"
    if [ -e "$config/seccomp" ]; then
      mv "$config/seccomp" "$config/seccomp.previous"
    fi
    mv "$config/.seccomp.new" "$config/seccomp"
    echo "installed the matching seccomp policy at $config/seccomp"
  elif [ -e "$config/seccomp" ]; then
    rm -rf "$config/seccomp.previous"
    mv "$config/seccomp" "$config/seccomp.previous"
    echo "terrarium: this release has no seccomp policy; moved the old one to $config/seccomp.previous" >&2
  fi
fi
