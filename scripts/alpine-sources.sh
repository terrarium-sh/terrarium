#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
image='docker.io/library/alpine@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b'
tree="$root/build/alpine-source-tree"
database="$tree/installed"
manifest="$tree/manifest.tsv"
sources="$tree/sources"

rm -rf "$tree"
mkdir -p "$sources"
tar -xOzf "$root/build/alpine-minirootfs.tar.gz" ./lib/apk/db/installed > "$database"
architecture=$(awk -F: '/^A:/ && $2 != "noarch" { print $2; exit }' "$database")
case "$architecture" in
    x86_64 | aarch64) ;;
    *) echo "unsupported Alpine source architecture: $architecture" >&2; exit 1 ;;
esac

awk '
function emit() {
    if (package != "" && license ~ /GPL/) {
        if (origin == "" || commit == "") {
            print "missing Alpine source origin or commit for " package > "/dev/stderr"
            failed=1
        }
        print package "\t" version "\t" origin "\t" commit "\t" license
    }
}
BEGIN { RS=""; FS="\n" }
{
    package=version=origin=license=commit=""
    for (i=1; i<=NF; i++) {
        if ($i ~ /^P:/) package=substr($i,3)
        if ($i ~ /^V:/) version=substr($i,3)
        if ($i ~ /^L:/) license=substr($i,3)
        if ($i ~ /^o:/) origin=substr($i,3)
        if ($i ~ /^c:/) commit=substr($i,3)
    }
    emit()
}
END { exit failed }
' "$database" > "$manifest"
sort -u -k3,4 "$manifest" -o "$manifest"

while read -r package version origin commit license <&3; do
    directory="$sources/$origin-$commit"
    git init -q "$directory"
    git -C "$directory" remote add origin https://github.com/alpinelinux/aports.git
    git -C "$directory" fetch -q --depth=1 origin "$commit"
    git -C "$directory" archive "$commit" "main/$origin" | tar -x -C "$directory" --strip-components=2
    rm -rf "$directory/.git"
    mkdir -p "$tree/distfiles"
    podman run --rm --security-opt=label=disable --volume "$directory:/package:ro" --volume "$tree/distfiles:/distfiles:rw" \
        --env "CHOST=$architecture" --entrypoint /bin/sh "$image" -ec '
            apk add --no-cache abuild=3.17.0-r0
            cp -a /package /tmp/package
            cd /tmp/package
            export SRCDEST=/distfiles
            for attempt in 1 2 3; do
                abuild -F fetch && break
                [ "$attempt" = 3 ] && exit 1
                sleep "$attempt"
            done
        ' </dev/null
done 3< "$manifest"

tar -C "$tree" -czf "$root/build/alpine-corresponding-source.tar.gz" installed manifest.tsv sources distfiles
