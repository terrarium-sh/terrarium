#!/bin/sh
set -eu

kernel_repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
kernel_recipe_hash=$(sha256sum "$kernel_repo/kernel/Containerfile" | cut -d' ' -f1)
kernel_builder="localhost/terra-kernel-builder:$kernel_recipe_hash"
if ! podman image exists "$kernel_builder"; then
    podman build --tag "$kernel_builder" --file "$kernel_repo/kernel/Containerfile" "$kernel_repo/kernel"
fi
mkdir -p "$kernel_repo/build"
exec podman run --rm --network=none --userns=keep-id --user "$(id -u):$(id -g)" \
    --cap-drop=all --security-opt=no-new-privileges --security-opt=label=disable \
    --volume "$kernel_repo:$kernel_repo:ro" \
    --volume "$kernel_repo/build:$kernel_repo/build:rw" \
    --workdir "$kernel_repo" --entrypoint /usr/bin/env "$kernel_builder" "$@"
