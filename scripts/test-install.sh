#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin" "$tmp/release"
printf 'terra test binary\n' > "$tmp/release/terra"
tar -czf "$tmp/release/terra-x86_64-linux.tar.gz" -C "$tmp/release" terra
(cd "$tmp/release" && sha256sum terra-x86_64-linux.tar.gz > SHA256SUMS)

cat > "$tmp/bin/uname" <<'EOF'
#!/bin/sh
case "$1" in
  -s) echo Linux ;;
  -m) echo x86_64 ;;
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
cp "$INSTALL_FIXTURES/${url##*/}" "$output"
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
if GH_FAIL=1 PATH="$tmp/bin:$PATH" INSTALL_FIXTURES="$tmp/release" INSTALL_DEST="$tmp/installed-terra" \
  TERRA_VERSION=1.2.3 sh "$root/install.sh" >/dev/null 2>&1; then
  echo 'installer accepted a failed attestation' >&2
  exit 1
fi
test ! -e "$tmp/installed-terra"
