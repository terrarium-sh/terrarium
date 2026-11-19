#!/bin/sh
# Checks that terra works on this machine: boots boxes from the acceptance
# recipes in a private home and drives every feature through the terra CLI.
# Needs only terra, curl and tar. Run alone, it fetches the suite of the release
# terra reports, verified against its SHA256SUMS, and runs that release's copy.
set -eu

usage="usage: run.sh [--terra PATH] [--suite DIR]"
repo="terrarium-sh/terrarium"
boxes="probe setup-mounts setup-workdir setup-bad-workdir nested-mounts isolated offline podman wireguard readonly overlay bad-bake rebuild"

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
# A terminal on stdin would make terra prompt instead of refusing, as it does in CI.
exec </dev/null
if [ -z "$suite" ] && [ -f "$(dirname "$0")/recipes/probe.yaml" ]; then
  suite=$(dirname "$0")
fi

# A release or git build reports <version>+<hash>; a build outside a git checkout
# reports only the crate version, which names no release.
terra_version() {
  version_text=$("$terra" --version) || return $?
  version=$(printf '%s\n' "$version_text" | cut -d' ' -f2) || return $?
  case "$version" in
    *+*) echo "${version%%+*}" ;;
    *) echo dev ;;
  esac
}

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    checksum=$(sha256sum < "$1") || return $?
  else
    checksum=$(shasum -a 256 < "$1") || return $?
  fi
  printf '%s\n' "${checksum%% *}"
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
  if [ -z "$expected" ] || ! actual=$(sha256 "$download/suite.tar.gz") || [ "$actual" != "$expected" ]; then
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
work=$(mktemp -d /tmp/terraaXXXXXXXX)
project="$work/project"
log="$work/step.log"
step=
step_started=
results=
suite_started=$(date +%s)
mkdir "$work/h"
HOME="$work/h"
export HOME

finish() {
  status=$?
  if [ "$status" -ne 0 ] && [ -n "$step_started" ]; then
    record FAIL
  fi
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
  if [ -t 1 ]; then
    summary
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
  step_started=$(date +%s)
  printf '%-58s ' "$1"
  : > "$log"
}

passed() {
  echo ok
  record ok
}

record() {
  results="$results$1 $(( $(date +%s) - step_started )) $step
"
  step_started=
}

duration() {
  if [ "$1" -ge 60 ]; then
    printf '%dm%02ds' $(( $1 / 60 )) $(( $1 % 60 ))
  else
    printf '%ds' "$1"
  fi
}

summary() {
  green= red= reset=
  if [ -z "${NO_COLOR:-}" ]; then
    green=$(printf '\033[32m') red=$(printf '\033[31m') reset=$(printf '\033[0m')
  fi
  echo
  printf '%s' "$results" | while read -r result seconds name; do
    if [ "$result" = ok ]; then color=$green; else color=$red; fi
    printf '  %s%-4s%s %6s  %s\n' "$color" "$result" "$reset" "$(duration "$seconds")" "$name"
  done
  failed=$(printf '%s' "$results" | grep -c '^FAIL ' || true)
  ok=$(printf '%s' "$results" | grep -c '^ok ' || true)
  printf '  %s passed, %s failed in %s\n' "$ok" "$failed" "$(duration $(( $(date +%s) - suite_started )))"
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
  cat "$work/output" >> "$log" || return $?
  cat "$work/output" || return $?
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

expect_file() {
  file_text=$(cat "$1" 2>> "$log") || return $?
  expect "$file_text" "$2"
}

expect_contains() {
  case "$1" in
    *"$2"*) ;;
    *) note "$1"; note "expected output containing '$2'"; return 1 ;;
  esac
}

expect_listed() {
  listed=$(output ls --state "$2" --quiet)
  expect_contains "$listed" "$1"
}

expect_unlisted() {
  listed=$(output ls --quiet)
  if printf '%s\n' "$listed" | grep -Fxq "$1"; then
    note "$1 is still listed"
    return 1
  fi
}

# --- Steps.

begin "terra runs"
version=$(terra_version 2>> "$log")
passed

mkdir -p "$project/work" "$project/readonly" "$project/setup-work"
cp -R "$suite" "$project/suite"
cd "$project"
printf HOST_SEED > work/host
printf INITIAL > work/host-update
printf READ_ONLY > readonly/seed
printf '#!/bin/sh\necho HOST_EXECUTABLE\n' > work/host-run
chmod 755 work/host-run
# Below every OS's ephemeral range, so no outgoing connection already holds the port.
allowed_port=$(( $$ % 12000 + 20000 ))
denied_port=$(( allowed_port + 1 ))
podman_port=$(( allowed_port + 2 ))
wireguard_port=$(( allowed_port + 3 ))
wireguard_denied_port=$(( allowed_port + 4 ))
for recipe in $boxes; do
  sed -e "s/{allowed_port}/$allowed_port/g" -e "s/{denied_port}/$denied_port/g" \
    -e "s/{podman_port}/$podman_port/g" \
    -e "s/{wireguard_port}/$wireguard_port/g" -e "s/{wireguard_denied_port}/$wireguard_denied_port/g" \
    "suite/recipes/$recipe.yaml" > "$recipe.yaml"
done

begin "setup bakes the recipe, and again is a no-op"
setup_output=$(output ./probe.yaml setup)
expect_contains "$setup_output" BAKE_OK
run probe setup
shown=$(output probe show --json --with-env-values)
expect_contains "$shown" recipe-value
passed

begin "setup mounts: writable default, explicit read-only, phase isolation"
printf RUNTIME_ONLY > work/runtime-only-seed
setup_output=$(output ./setup-mounts.yaml setup)
expect_contains "$setup_output" SETUP_MOUNTS_OK
test ! -e suite/forbidden
expect_file setup-work/setup-result SETUP_WROTE
run setup-mounts -d
run setup-mounts exec --no-tty -- sh -ec 'for i in $(seq 1 30); do [ -s /work/runtime-result ] && break; sleep 1; done; grep -qx RUNTIME_WROTE /work/runtime-result; test ! -e /work/guest/namespaces.sh; test ! -e /setup-only/setup-result; grep -qx SETUP_COPY /setup-output'
expect_file work/on-start ON_START
expect_file work/daemon DAEMON
run setup-mounts stop
expect_file work/pre-stop PRE_STOP
mv setup-work "$work/previous-setup-work"
shown=$(output setup-mounts show --json)
setup_json=$(printf '%s\n' "$shown" | sed -n '/^  "setup": {/,/^  }/s/^ *//p')
setup_json=$(printf '%s' "$setup_json" | tr -d '\n')
physical_project=$(pwd -P)
expect_contains "$setup_json" "\"host\": \"$physical_project/suite\",\"guest\": \"/work\",\"readonly\": true}"
passed

begin "storage import defers setup sources and local approval"
run setup-mounts storage export "$work/setup-mounts.terra"
run setup-mounts storage import --trust-recipe "$work/setup-mounts.terra"
run setup-mounts setup --dry-run
run setup-mounts -d
run setup-mounts exec --no-tty -- sh -ec 'grep -qx SETUP_COPY /setup-output'
run setup-mounts stop
mkdir setup-work
if refused=$(output setup-mounts setup --rebuild); then
  note "rebuild after import succeeded without local approval"
  false
fi
expect_contains "$refused" --trust-recipe
setup_output=$(output setup-mounts setup --rebuild --trust-recipe)
expect_contains "$setup_output" SETUP_MOUNTS_OK
passed

begin "setup workdirs: created in the root, and a file is refused"
run ./setup-workdir.yaml setup
workload_output=$(output setup-workdir --foreground)
expect_contains "$workload_output" SETUP_WORKDIR_OK
if failed=$(output ./setup-bad-workdir.yaml setup); then
  note "setup with an unusable workdir succeeded"
  false
fi
expect_contains "$failed" "terra-agent: setup failed: creating setup workdir /etc/passwd"
expect_contains "$failed" "setup failed - fix the recipe"
expect_listed setup-bad-workdir needs_setup
passed

begin "nested mount targets are refused before setup"
if failed=$(output ./nested-mounts.yaml setup); then
  note "setup with nested mount targets succeeded"
  false
fi
expect_contains "$failed" "overlap in setup"
expect_contains "$failed" "mount at separate paths"
expect_unlisted nested-mounts
passed

begin "a detached box runs on_start commands, daemons and its workload"
run probe -d
guest_check exercise-ready.sh
expect_file work/ready recipe-value
expect_listed probe running
passed

begin "exec: user, root, hostname, env, workdir, status, streams"
user_id=$(output probe exec --no-tty -- id -u)
expect "$user_id" 1000
root_id=$(output probe exec --no-tty --root -- id -u)
expect "$root_id" 0
hostname=$(output probe exec --no-tty -- hostname)
expect "$hostname" probe
run probe exec --no-tty --env PROBE=exec-value --workdir /tmp -- \
  sh -ec 'test "$PROBE" = exec-value; current_workdir=$(pwd); test "$current_workdir" = /tmp'
expect "$(exit_status probe exec --no-tty -- sh -c 'exit 7')" 7
streams_status=0
"$terra" probe exec --no-tty -- sh -c 'echo out; echo err >&2' > "$work/stdout" 2> "$work/stderr" || streams_status=$?
cat "$work/stdout" "$work/stderr" >> "$log"
[ "$streams_status" -eq 0 ] || exit "$streams_status"
expect_file "$work/stdout" out
expect_file "$work/stderr" err
tty_output=$(output probe exec --tty -- sh -ec 'test -t 0; test -t 1; echo TTY_OK')
expect_contains "$tty_output" TTY_OK
passed

begin "the guest runs containers: namespaces, cgroups, overlayfs"
run probe exec --no-tty --root -- sh -c 'echo ROOT_WRITE > /etc/workload-probe'
guest_check namespaces.sh
guest_check overlay.sh --root
passed

begin "the guest gets no hardware virtualization"
guest_check no-virtualization.sh --root
passed

begin "shares: read-write, read-only, links"
guest_check shares.sh
host_run_output=$(output probe exec --no-tty -- /work/host-run)
expect "$host_run_output" HOST_EXECUTABLE
expect_file work/host linked
expect_file work/after renamed
readonly_entries=$(ls -A readonly 2>> "$log")
expect "$readonly_entries" seed
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
expect_file sync-back/value first
run probe exec --no-tty -- sh -c 'printf extra > /tmp/synced/extra'
run probe sync --delete --checksum ./sync-source/ :/tmp/synced/
run probe exec --no-tty -- sh -c 'test ! -e /tmp/synced/extra'
run probe sync ./sync-source/ :/tmp/owned/deep/
run probe exec --no-tty -- sh -ec 'owner=$(stat -c %u /tmp/owned); user=$(id -u); test "$owner" = "$user"'
passed

begin "network: published ports, allowlist, local DNS, denial"
body=$(curl -fsS --retry 60 --retry-delay 1 --retry-all-errors --max-time 5 \
  "http://127.0.0.1:$allowed_port/" 2>> "$log")
expect "$body" GUEST_NETWORK
body=$(curl -fsS --max-time 5 "http://127.0.0.1:$denied_port/" 2>> "$log")
expect "$body" DENIED_ROUTE
network_output=$(output probe exec --no-tty \
  --env "ALLOWED_PORT=$allowed_port" --env "DENIED_PORT=$denied_port" \
  -- sh -e /suite/guest/network.sh)
expect_contains "$network_output" NETWORK_OK
passed

begin "network: a box without an allowlist reaches nothing"
run ./isolated.yaml setup
network_output=$(output isolated --foreground)
expect_contains "$network_output" ISOLATED_OK
passed

begin "network: a box with networking off keeps loopback"
run ./offline.yaml setup
run offline -d
network_output=$(output offline exec --no-tty -- sh -e /suite/guest/local-only.sh)
expect_contains "$network_output" LOCAL_ONLY_OK
run offline stop
expect_listed offline stopped
passed

begin "network: podman's published port reaches the host"
run ./podman.yaml setup
run podman -d
run podman exec --no-tty -- sh -e /suite/guest/podman-publish.sh
body=$(curl -fsS --retry 30 --retry-delay 1 --retry-all-errors --max-time 5 \
  "http://127.0.0.1:$podman_port/" 2>> "$log")
expect "$body" CONTAINER_NETWORK
run podman stop
passed

begin "network: wireguard-go encrypts IPv4 and IPv6 through direct UDP sockets"
run ./wireguard.yaml setup
run wireguard -d
network_output=$(output wireguard exec --no-tty -- sh -e /suite/guest/wireguard.sh)
expect_contains "$network_output" WIREGUARD_UNPRIVILEGED_OK
network_output=$(output wireguard exec --no-tty --root -- sh -e /suite/guest/wireguard.sh "$wireguard_port" "$wireguard_denied_port")
expect_contains "$network_output" WIREGUARD_OK
run wireguard stop
passed

begin "a read-only root prepares workdirs and refuses writes; boot-lifetime volumes start empty"
run ./readonly.yaml setup
run readonly -d
workdir=$(output readonly exec --no-tty -- pwd)
expect "$workdir" /prepared/deep
touch_error=$(output readonly exec --no-tty --root -- sh -c 'touch /etc/probe 2>&1; true')
expect_contains "$touch_error" "Read-only file system"
run readonly exec --no-tty -- sh -ec 'echo KEPT > /kept/value; echo GONE > /scratch/value'
run readonly stop
run readonly -d
workdir=$(output readonly exec --no-tty -- pwd)
expect "$workdir" /prepared/deep
kept_value=$(output readonly exec --no-tty -- cat /kept/value)
expect "$kept_value" KEPT
run readonly exec --no-tty -- sh -ec 'test ! -e /scratch/value'
run readonly stop
passed

begin "a rootfs overlay makes a read-only root writable for one boot"
run ./overlay.yaml setup
run overlay -d
run overlay exec --no-tty --root -- sh -ec 'echo CHANGED > /etc/overlay-probe'
overlay_value=$(output overlay exec --no-tty -- cat /etc/overlay-probe)
expect "$overlay_value" CHANGED
run overlay stop
run overlay -d
run overlay exec --no-tty -- sh -ec 'test ! -e /etc/overlay-probe'
run overlay stop
passed

begin "stop runs pre_stop and keeps the box"
run probe stop
expect_listed probe stopped
hooks=$(tr '\n' ' ' 2>> "$log" < work/hooks)
expect "$hooks" "start stop "
passed

begin "storage: inspect, export, persist, import"
storage=$(output probe storage show --json)
expect_contains "$storage" rootfs.img
expect_contains "$storage" vol-data.img
run probe storage export "$work/storage.terra"
test -s "$work/storage.terra"
run probe storage prune
run probe -d
restart_output=$(output probe exec --no-tty --root -- sh -e /suite/guest/storage-restart.sh)
expect_contains "$restart_output" RESTART_OK
run probe stop
hooks=$(tr '\n' ' ' 2>> "$log" < work/hooks)
expect "$hooks" "start stop start stop "
if refused=$(output probe storage import "$work/storage.terra"); then
  note "import without --trust-recipe succeeded"
  false
fi
expect_contains "$refused" gate.test
expect_contains "$refused" --trust-recipe
run probe storage import --trust-recipe "$work/storage.terra"
run probe -d
restore_output=$(output probe exec --no-tty -- \
  sh -ec 'value=$(cat /data/value); test "$value" = PERSISTED; echo RESTORED_OK')
expect_contains "$restore_output" RESTORED_OK
run probe stop
imported="$work/imported"
mkdir -p "$imported/work" "$imported/readonly"
cp -R "$project/suite" "$imported/suite"
run --project "$imported" probe storage import --trust-recipe "$work/storage.terra"
listed=$(output --project "$imported" ls --state stopped --quiet)
expect_contains "$listed" probe
run --project "$imported" probe -d
restore_output=$(output --project "$imported" probe exec --no-tty -- \
  sh -ec 'value=$(cat /data/value); test "$value" = PERSISTED; echo RESTORED_OK')
expect_contains "$restore_output" RESTORED_OK
run --project "$imported" probe stop
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
diagnostics=$(output bad-bake logs --diagnostics)
expect_contains "$diagnostics" "init failed"
expect_listed bad-bake needs_setup
passed

begin "setup rebuilds from scratch only when the recipe says something new"
setup_output=$(output ./rebuild.yaml setup)
expect_contains "$setup_output" BAKED_ONE
expect_setup_untouched() {
  untouched=$(output ./rebuild.yaml setup) || { note "setup failed"; return 1; }
  case "$untouched" in
    *"from scratch"* | *BAKED_*) note "an unchanged recipe was rebuilt"; return 1 ;;
  esac
}
expect_setup_untouched
{ echo "# only a comment"; cat rebuild.yaml; } > rebuild.next
mv rebuild.next rebuild.yaml
expect_setup_untouched
sed 's/BAKED_ONE/BAKED_TWO/' rebuild.yaml > rebuild.next
mv rebuild.next rebuild.yaml
changed=$(output ./rebuild.yaml setup)
expect_contains "$changed" "from scratch: the recipe changed"
expect_contains "$changed" BAKED_TWO
passed

begin "a new run keeps the root, and a foreground workload's exit status is terra's"
printf 'workload: {run: exit 7}\n' >> rebuild.yaml
kept=$(output ./rebuild.yaml setup)
expect_contains "$kept" "keeps its root"
expect "$(exit_status rebuild --foreground)" 7
passed

begin "rm discards the box, --purge forgets it"
run probe rm
expect_listed probe not_created
run probe rm --purge
expect_unlisted probe
passed

echo "terra $version works on this machine"
