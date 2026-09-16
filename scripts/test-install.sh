#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin" "$tmp/release"
printf 'terra test binary\n' > "$tmp/release/terra"
tar -czf "$tmp/release/terra-x86_64-linux.tar.gz" -C "$tmp/release" terra
tar -czf "$tmp/release/terra-aarch64-macos.tar.gz" -C "$tmp/release" terra
printf '{"tag_name": "v1.3.0-rc.1"}\n' > "$tmp/release/releases.json"
(
  cd "$tmp/release"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum terra-*.tar.gz
  else
    shasum -a 256 terra-*.tar.gz
  fi > SHA256SUMS
)

cat > "$tmp/bin/uname" <<'EOF'
#!/bin/sh
case "$1" in
  -s) echo "${INSTALL_OS:-Linux}" ;;
  -m) echo "${INSTALL_ARCH:-x86_64}" ;;
esac
EOF
cat > "$tmp/bin/curl" <<'EOF'
#!/bin/sh
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o) output=$2; shift 2 ;;
    *) url=$1; shift ;;
  esac
done
case "$url" in
  https://api.github.com/*) cp "$INSTALL_FIXTURES/releases.json" "$output" ;;
  *) cp "$INSTALL_FIXTURES/${url##*/}" "$output" ;;
esac
EOF
cat > "$tmp/bin/install" <<'EOF'
#!/bin/sh
if [ "$1" = -d ]; then
  exit 0
fi
cp "$3" "$INSTALL_DEST"
EOF
cat > "$tmp/bin/gh" <<'EOF'
#!/bin/sh
test "$1" = attestation && test "$2" = verify && test "${GH_FAIL:-0}" = 0
EOF
chmod +x "$tmp/bin/uname" "$tmp/bin/curl" "$tmp/bin/install" "$tmp/bin/gh"

PATH="$tmp/bin:$PATH" INSTALL_FIXTURES="$tmp/release" INSTALL_DEST="$tmp/installed-terra" \
  TERRA_VERSION=1.2.3 sh "$root/install.sh" >/dev/null
cmp "$tmp/release/terra" "$tmp/installed-terra"

rm -f "$tmp/installed-terra"
PATH="$tmp/bin:$PATH" INSTALL_FIXTURES="$tmp/release" INSTALL_DEST="$tmp/installed-terra" \
  TERRA_VERSION= sh "$root/install.sh" --prerelease >/dev/null
cmp "$tmp/release/terra" "$tmp/installed-terra"

rm -f "$tmp/installed-terra"
if GH_FAIL=1 PATH="$tmp/bin:$PATH" INSTALL_FIXTURES="$tmp/release" INSTALL_DEST="$tmp/installed-terra" \
  TERRA_VERSION=1.2.3 sh "$root/install.sh" >/dev/null 2>&1; then
  echo 'installer accepted a failed attestation' >&2
  exit 1
fi
test ! -e "$tmp/installed-terra"

rm "$tmp/release/terra-x86_64-linux.tar.gz"
PATH="$tmp/bin:$PATH" INSTALL_FIXTURES="$tmp/release" INSTALL_DEST="$tmp/installed-terra" \
  INSTALL_OS=Darwin INSTALL_ARCH=arm64 TERRA_VERSION=1.2.3 sh "$root/install.sh" >/dev/null
cmp "$tmp/release/terra" "$tmp/installed-terra"
