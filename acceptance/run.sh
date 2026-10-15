#!/bin/sh
# Checks that terra works on this machine: boots boxes from the acceptance
# recipes in a private home and drives every feature through the terra CLI.
# Needs only terra, curl and tar. Run alone, it fetches the suite of the release
# terra reports, verified against its SHA256SUMS, and runs that release's copy.
set -eu

usage="usage: run.sh [--terra PATH] [--suite DIR]"
repo="terrarium-sh/terrarium"
boxes="probe isolated offline bad-bake"

terra=terra
suite=
while [ $# -gt 0 ]; do
  case "$1" in
    --terra) terra=${2:?$usage}; shift 2 ;;
    --suite) suite=${2:?$usage}; shift 2 ;;
    *) echo "$usage" >&2; exit 2 ;;
  esac
done
case "$terra" in
  */*) terra=$(cd "$(dirname "$terra")" && pwd)/$(basename "$terra") ;;
  *) terra=$(command -v "$terra") || { echo "terra is not on PATH; pass --terra" >&2; exit 2; } ;;
esac
if [ -z "$suite" ] && [ -f "$(dirname "$0")/recipes/probe.yaml" ]; then
  suite=$(dirname "$0")
fi

# A release or git build reports <version>+<hash>; a build outside a git checkout
# reports only the crate version, which names no release.
terra_version() {
  version=$("$terra" --version | cut -d' ' -f2)
  case "$version" in
    *+*) echo "${version%%+*}" ;;
    *) echo dev ;;
  esac
}

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum < "$1" | cut -d' ' -f1
  else
    shasum -a 256 < "$1" | cut -d' ' -f1
  fi
}

# --- Without a suite: hand over to the runner of the release terra reports,
# --- so runner and recipes always match.

if [ -z "$suite" ]; then
  version=$(terra_version)
  if [ "$version" = dev ]; then
    echo "terra is a development build; pass --suite <checkout>/acceptance" >&2
    exit 2
  fi
  download=$(mktemp -d)
  trap 'rm -rf "$download"' EXIT
  base="https://github.com/$repo/releases/download/v$version"
  curl -fsSL --proto '=https' --tlsv1.2 "$base/SHA256SUMS" -o "$download/SHA256SUMS"
  curl -fsSL --proto '=https' --tlsv1.2 "$base/terra-acceptance.tar.gz" -o "$download/suite.tar.gz"
  expected=$(awk '$2 == "terra-acceptance.tar.gz" { print $1 }' "$download/SHA256SUMS")
  if [ -z "$expected" ] || [ "$(sha256 "$download/suite.tar.gz")" != "$expected" ]; then
    echo "terra-acceptance.tar.gz does not match the v$version SHA256SUMS - not running it" >&2
    exit 1
  fi
  mkdir "$download/suite"
  tar -xzf "$download/suite.tar.gz" -C "$download/suite"
  status=0
  sh "$download/suite/run.sh" --terra "$terra" || status=$?
  exit "$status"
fi

# --- A private home and project, removed again unless a step fails.

# /tmp rather than TMPDIR: box control sockets must fit the local-socket path limit.
work=$(mktemp -d /tmp/terra-acceptance.XXXXXX)
project="$work/project"
log="$work/step.log"
step=
mkdir "$work/home"
HOME="$work/home"
export HOME

finish() {
  status=$?
  if [ "$status" -ne 0 ]; then
    echo "FAIL"
    echo "$step failed (exit $status):"
    sed 's/^/    /' "$log" 2>/dev/null || true
  fi
  if [ -d "$project" ]; then
    cd "$project"
    for name in $boxes; do
      "$terra" "$name" rm --force --purge --timeout 5 >/dev/null 2>&1 || true
    done
  fi
  if [ "$status" -eq 0 ]; then
    rm -rf "$work"
  else
    echo "kept $work for inspection"
  fi
  exit "$status"
}
trap finish EXIT
trap 'exit 130' INT TERM HUP

# --- Step helpers. Every command's output goes to the step log, which is
# --- printed when the step fails.

begin() {
  step=$1
  printf '%-58s ' "$1"
  : > "$log"
}

passed() {
  echo ok
}

note() {
  printf '%s\n' "$*" >> "$log"
}

run() {
  "$terra" "$@" >> "$log" 2>&1
}

output() {
  status=0
  "$terra" "$@" > "$work/output" 2>&1 || status=$?
  cat "$work/output" >> "$log"
  cat "$work/output"
  return "$status"
}

exit_status() {
  "$terra" "$@" >> "$log" 2>&1 && echo 0 || echo $?
}

guest_check() {
  script=$1
  shift
  run probe exec --no-tty "$@" -- sh -e "/suite/guest/$script"
}

expect() {
  [ "$1" = "$2" ] || { note "expected '$2', got '$1'"; return 1; }
}

expect_contains() {
  case "$1" in
    *"$2"*) ;;
    *) note "$1"; note "expected output containing '$2'"; return 1 ;;
  esac
}

expect_listed() {
  expect_contains "$(output ls --state "$2" --quiet)" "$1"
}

# --- Steps.

begin "terra runs"
version=$(terra_version 2>> "$log")
passed

mkdir -p "$project/work" "$project/readonly"
cp -R "$suite" "$project/suite"
cd "$project"
printf HOST_SEED > work/host
printf INITIAL > work/host-update
printf READ_ONLY > readonly/seed
printf '#!/bin/sh\necho HOST_EXECUTABLE\n' > work/host-run
chmod 755 work/host-run
allowed_port=$(( $$ % 20000 + 30000 ))
denied_port=$(( allowed_port + 1 ))
for recipe in $boxes; do
  sed -e "s/{allowed_port}/$allowed_port/g" -e "s/{denied_port}/$denied_port/g" \
    "suite/recipes/$recipe.yaml" > "$recipe.yaml"
done

begin "setup bakes the recipe, and again is a no-op"
expect_contains "$(output ./probe.yaml setup)" BAKE_OK
run probe setup
expect_contains "$(output probe show --json --with-env-values)" recipe-value
passed

begin "a detached box runs its hooks, daemons and workload"
run probe -d
guest_check exercise-ready.sh
expect "$(cat work/ready)" recipe-value
expect_listed probe running
passed

begin "exec: user, root, env, workdir, status, streams"
expect "$(output probe exec --no-tty -- id -u)" 1000
expect "$(output probe exec --no-tty --root -- id -u)" 0
run probe exec --no-tty --env PROBE=exec-value --workdir /tmp -- \
  sh -ec 'test "$PROBE" = exec-value; test "$(pwd)" = /tmp'
expect "$(exit_status probe exec --no-tty -- sh -c 'exit 7')" 7
expect "$("$terra" probe exec --no-tty -- sh -c 'echo out; echo err >&2' 2> "$work/stderr")" out
expect "$(cat "$work/stderr")" err
expect_contains "$(output probe exec --tty -- sh -c 'test -t 0; test -t 1; echo TTY_OK')" TTY_OK
passed

begin "the guest runs containers: namespaces, cgroups, overlayfs"
run probe exec --no-tty --root -- sh -c 'echo ROOT_WRITE > /etc/workload-probe'
guest_check namespaces.sh
guest_check overlay.sh --root
passed

begin "shares: read-write, read-only, links"
guest_check shares.sh
run probe exec --no-tty -- sh -ec 'test "$(/work/host-run)" = HOST_EXECUTABLE'
expect "$(cat work/host)" linked
expect "$(cat work/after)" renamed
expect "$(ls -A readonly)" seed
passed

begin "shares: host edits reach the guest as file events"
guest_check watcher-ready.sh --root
printf LIVE_UPDATE > work/host-update
printf CREATED > work/host-created
guest_check file-events-created.sh --root
rm work/host-created
guest_check file-events-deleted.sh --root
guest_check shares-persisted.sh
passed

begin "sync copies files both ways and mirrors deletions"
mkdir -p sync-source/nested
head -c 65536 /dev/urandom > sync-source/nested/binary
printf first > sync-source/value
run probe sync ./sync-source/ :/tmp/synced/
run probe sync :/tmp/synced/ ./sync-back/
cmp sync-source/nested/binary sync-back/nested/binary >> "$log" 2>&1
expect "$(cat sync-back/value)" first
run probe exec --no-tty -- sh -c 'printf extra > /tmp/synced/extra'
run probe sync --delete --checksum ./sync-source/ :/tmp/synced/
run probe exec --no-tty -- sh -c 'test ! -e /tmp/synced/extra'
passed

begin "network: published ports, allowlist, local DNS, denial"
expect "$(curl -fsS --retry 60 --retry-delay 1 --retry-all-errors --max-time 5 \
  "http://127.0.0.1:$allowed_port/" 2>> "$log")" GUEST_NETWORK
expect "$(curl -fsS --max-time 5 "http://127.0.0.1:$denied_port/" 2>> "$log")" DENIED_ROUTE
expect_contains "$(output probe exec --no-tty \
  --env "ALLOWED_PORT=$allowed_port" --env "DENIED_PORT=$denied_port" \
  -- sh -e /suite/guest/network.sh)" NETWORK_OK
passed

begin "network: a box without an allowlist reaches nothing"
run ./isolated.yaml setup
expect_contains "$(output isolated --foreground)" ISOLATED_OK
passed

begin "network: a box with networking off keeps loopback"
run ./offline.yaml setup
run offline -d
expect_contains "$(output offline exec --no-tty -- sh -e /suite/guest/local-only.sh)" LOCAL_ONLY_OK
run offline stop
expect_listed offline stopped
passed

begin "stop runs pre_stop and keeps the box"
run probe stop
expect_listed probe stopped
expect "$(tr '\n' ' ' < work/hooks)" "start stop "
passed

begin "storage: inspect, export, persist, import"
storage=$(output probe storage show --json)
expect_contains "$storage" rootfs.img
expect_contains "$storage" vol-data.img
run probe storage export "$work/storage.terra"
test -s "$work/storage.terra"
run probe storage prune
restarted=$(output probe --foreground --root -- sh -e /suite/guest/storage-restart.sh)
expect_contains "$restarted" RESTART_OK
expect_contains "$restarted" STOP_OK
run probe storage import "$work/storage.terra"
expect_contains "$(output probe --foreground -- \
  sh -ec 'test $(cat /data/value) = PERSISTED; echo RESTORED_OK')" RESTORED_OK
passed

begin "a foreground command's exit status is terra's"
expect "$(exit_status probe --foreground -- sh -c 'exit 7')" 7
passed

begin "logs show host and guest diagnostics"
run probe logs --tail 20
run probe logs --diagnostics --tail 20
passed

begin "a failing bake fails setup and is diagnosable"
if bake=$(output ./bad-bake.yaml setup); then
  note "setup succeeded"
  false
fi
expect_contains "$bake" FAILED_BAKE
expect_contains "$(output bad-bake logs --diagnostics)" "init failed"
passed

begin "rm discards the box, --purge forgets it"
run probe rm
expect_listed probe not_created
run probe rm --purge
case " $(output ls --quiet | tr '\n' ' ') " in
  *" probe "*) note "probe is still listed"; false ;;
esac
passed

echo "terra $version works on this machine"
