#!/bin/sh
set -eu

os=$(uname -s)
arch=$(uname -m)

case "$os/$arch" in
  Linux/x86_64)
    asset=terra-x86_64-linux
    bin=/usr/local/bin
    ;;
  Darwin/arm64)
    asset=terra-aarch64-macos
    if [ -w /opt/homebrew/bin ]; then
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

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
curl -fsSL "https://github.com/alis-is/terrarium/releases/latest/download/$asset" -o "$tmp"
chmod +x "$tmp"

if mkdir -p "$bin" && mv -f "$tmp" "$bin/terra" 2>/dev/null; then
  :
else
  sudo mv -f "$tmp" "$bin/terra"
fi
echo "installed terra at $bin/terra"
