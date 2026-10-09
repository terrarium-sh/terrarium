#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin" "$tmp/release"
cat > "$tmp/release/terra" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod +x "$tmp/release/terra"
tar -czf "$tmp/release/terra-x86_64-linux.tar.gz" -C "$tmp/release" terra
tar -czf "$tmp/release/terra-aarch64-linux.tar.gz" -C "$tmp/release" terra
tar -czf "$tmp/release/terra-aarch64-macos.tar.gz" -C "$tmp/release" terra
mkdir "$tmp/policy"
printf '{"target": "x86_64-unknown-linux-musl"}\n' > "$tmp/policy/manifest.json"
printf 'bpf' > "$tmp/policy/vm.seccomp.bpf"
tar -czf "$tmp/release/terra-seccomp-x86_64-unknown-linux-musl.tar.gz" -C "$tmp/policy" manifest.json vm.seccomp.bpf
cp "$tmp/release/terra" "$tmp/original-terra"
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
case "$4" in
  */terra) cp "$3" "$INSTALL_DEST" ;;
  *) exit 1 ;;
esac
EOF
cat > "$tmp/bin/gh" <<'EOF'
#!/bin/sh
test "$1" = attestation && test "$2" = verify && test "${GH_FAIL:-0}" = 0
EOF
chmod +x "$tmp/bin/uname" "$tmp/bin/curl" "$tmp/bin/install" "$tmp/bin/gh"

HOME="$tmp/home" PATH="$tmp/bin:$PATH" INSTALL_FIXTURES="$tmp/release" INSTALL_DEST="$tmp/installed-terra" \
  TERRA_VERSION=1.2.3 sh "$root/install.sh" >/dev/null
cmp "$tmp/original-terra" "$tmp/installed-terra"
cmp "$tmp/policy/manifest.json" "$tmp/home/.terra/config/seccomp/manifest.json"
cmp "$tmp/policy/vm.seccomp.bpf" "$tmp/home/.terra/config/seccomp/vm.seccomp.bpf"
test "$(stat -c %a "$tmp/home/.terra" 2>/dev/null || stat -f %Lp "$tmp/home/.terra")" = 700

printf 'stale' > "$tmp/home/.terra/config/seccomp/vm.seccomp.bpf"
HOME="$tmp/home" PATH="$tmp/bin:$PATH" INSTALL_FIXTURES="$tmp/release" INSTALL_DEST="$tmp/installed-terra" \
  TERRA_VERSION=1.2.3 sh "$root/install.sh" >/dev/null
cmp "$tmp/policy/vm.seccomp.bpf" "$tmp/home/.terra/config/seccomp/vm.seccomp.bpf"
test "$(cat "$tmp/home/.terra/config/seccomp.previous/vm.seccomp.bpf")" = stale

rm -f "$tmp/installed-terra"
HOME="$tmp/home" PATH="$tmp/bin:$PATH" INSTALL_FIXTURES="$tmp/release" INSTALL_DEST="$tmp/installed-terra" \
  INSTALL_ARCH=aarch64 \
  TERRA_VERSION=1.2.3 sh "$root/install.sh" >/dev/null 2>&1
cmp "$tmp/original-terra" "$tmp/installed-terra"
test ! -e "$tmp/home/.terra/config/seccomp"

rm -f "$tmp/installed-terra"
HOME="$tmp/home" PATH="$tmp/bin:$PATH" INSTALL_FIXTURES="$tmp/release" INSTALL_DEST="$tmp/installed-terra" \
  TERRA_VERSION= sh "$root/install.sh" --prerelease >/dev/null
cmp "$tmp/release/terra" "$tmp/installed-terra"

rm -f "$tmp/installed-terra"
if GH_FAIL=1 HOME="$tmp/home" PATH="$tmp/bin:$PATH" INSTALL_FIXTURES="$tmp/release" INSTALL_DEST="$tmp/installed-terra" \
  TERRA_VERSION=1.2.3 sh "$root/install.sh" >/dev/null 2>&1; then
  echo 'installer accepted a failed attestation' >&2
  exit 1
fi
test ! -e "$tmp/installed-terra"

(
  cd "$tmp/release"
  grep -v terra-seccomp SHA256SUMS > SHA256SUMS.without-policy
  mv SHA256SUMS.without-policy SHA256SUMS
)
HOME="$tmp/home" PATH="$tmp/bin:$PATH" INSTALL_FIXTURES="$tmp/release" INSTALL_DEST="$tmp/installed-terra" \
  TERRA_VERSION=1.2.3 sh "$root/install.sh" >/dev/null 2>&1
test ! -e "$tmp/home/.terra/config/seccomp"
cmp "$tmp/policy/manifest.json" "$tmp/home/.terra/config/seccomp.previous/manifest.json"

rm "$tmp/release/terra-x86_64-linux.tar.gz"
HOME="$tmp/home" PATH="$tmp/bin:$PATH" INSTALL_FIXTURES="$tmp/release" INSTALL_DEST="$tmp/installed-terra" \
  INSTALL_OS=Darwin INSTALL_ARCH=arm64 TERRA_VERSION=1.2.3 sh "$root/install.sh" >/dev/null
cmp "$tmp/original-terra" "$tmp/installed-terra"
