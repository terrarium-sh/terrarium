#!/bin/sh
# Installs the latest terra release (or TERRA_VERSION=x.y.z), verifying the
# binary against the release's SHA256SUMS before anything is put in place.
set -eu

repo="Berry-Studio/terrarium"
version="${TERRA_VERSION:-latest}"
case "$version" in
  latest | v*) ;;
  *) version="v$version" ;;
esac

os=$(uname -s)
arch=$(uname -m)

case "$os/$arch" in
  Linux/x86_64)
    asset=terra-x86_64-linux
    bin=/usr/local/bin
    ;;
  Linux/aarch64 | Linux/arm64)
    asset=terra-aarch64-linux
    bin=/usr/local/bin
    ;;
  Darwin/arm64)
    asset=terra-aarch64-macos
    if [ -d /opt/homebrew/bin ]; then
      bin=/opt/homebrew/bin
    else
      bin=/usr/local/bin
    fi
    ;;
  Darwin/x86_64)
    if [ "$(sysctl -in sysctl.proc_translated 2>/dev/null || true)" != 1 ]; then
      echo "terrarium: no release for Intel macOS yet" >&2
      exit 1
    fi
    asset=terra-aarch64-macos
    if [ -d /opt/homebrew/bin ]; then
      bin=/opt/homebrew/bin
    else
      bin=/usr/local/bin
    fi
    ;;
  *)
    echo "terrarium: no release for $os/$arch yet" >&2
    exit 1
    ;;
esac

if [ "$version" = "latest" ]; then
  base="https://github.com/$repo/releases/latest/download"
else
  base="https://github.com/$repo/releases/download/$version"
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL "$base/SHA256SUMS" -o "$tmp/SHA256SUMS"
curl -fsSL "$base/$asset" -o "$tmp/terra"

# The checksum comes from the same release ref as the binary, so a tampered
# mirror of one alone cannot pass; the mismatch must be said out loud.
expected=$(awk -v a="$asset" '$2 == a { print $1 }' "$tmp/SHA256SUMS")
if [ -z "$expected" ]; then
  echo "terrarium: $asset is not in this release's SHA256SUMS - refusing to install" >&2
  exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
  got=$(sha256sum < "$tmp/terra" | cut -d' ' -f1)
else
  got=$(shasum -a 256 < "$tmp/terra" | cut -d' ' -f1)
fi
if [ "$got" != "$expected" ]; then
  echo "terrarium: CHECKSUM MISMATCH for $asset" >&2
  echo "  expected: $expected" >&2
  echo "  got:      $got" >&2
  echo "nothing was installed" >&2
  exit 1
fi

chmod +x "$tmp/terra"

if [ -e "$bin/terra" ] && ! [ -f "$bin/terra" ] && ! [ -L "$bin/terra" ]; then
  echo "terrarium: $bin/terra exists but is not a regular file - move it aside first" >&2
  exit 1
fi

if install -d "$bin" 2>/dev/null && install -m 755 "$tmp/terra" "$bin/terra" 2>/dev/null; then
  :
else
  # Escalating behind nobody's back stops here: the checksummed bytes are in
  # $tmp, but what sudo does with them deserves a yes.
  printf 'install to %s needs root privileges - run sudo install? [y/N] ' "$bin"
  read -r answer
  case "$answer" in
    y | Y | yes | Yes) sudo install -d "$bin" && sudo install -m 755 "$tmp/terra" "$bin/terra" ;;
    *)
      echo "nothing was installed" >&2
      exit 1
      ;;
  esac
fi
echo "installed terra at $bin/terra"
