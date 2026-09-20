#!/usr/bin/env python3
"""Refresh pinned build tools while keeping their build entry points synchronized."""

import argparse
import difflib
import io
import json
from pathlib import Path
import re
import tarfile
import tomllib
import urllib.request


def fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": "terrarium-pin-updater"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read()


def version_key(version):
    return tuple(map(int, version.split(".")))


def replace_pattern(files, pattern, replacement):
    for path, text in files.items():
        files[path] = re.sub(pattern, replacement, text, flags=re.MULTILINE)


def update_rust(files):
    for channel, path in (("stable", "rust-toolchain.toml"), ("nightly", "components/rust-toolchain.toml")):
        manifest = tomllib.loads(fetch(f"https://static.rust-lang.org/dist/channel-rust-{channel}.toml").decode())
        current = tomllib.loads(files[path])["toolchain"]["channel"]
        if channel == "stable":
            latest = manifest["pkg"]["rust"]["version"].split()[0]
            if version_key(latest) <= version_key(current):
                continue
            files[path] = files[path].replace(f'channel = "{current}"', f'channel = "{latest}"')
        else:
            latest = "nightly-" + manifest["date"]
            if latest <= current:
                continue
            if not manifest["pkg"]["rust-std"]["target"].get("wasm32-wasip3", {}).get("available"):
                raise ValueError(f"{latest} does not provide wasm32-wasip3")
            replace_pattern(files, re.escape(current), latest)


def update_cargo_tools(files):
    for crate, pin in (
        ("wasm-tools", "WASM_TOOLS_VERSION"),
        ("cargo-fuzz", "CARGO_FUZZ_VERSION"),
        ("cargo-audit", "CARGO_AUDIT_VERSION"),
        ("wit-bindgen", "WIT_BINDGEN_VERSION"),
    ):
        metadata = json.loads(fetch(f"https://crates.io/api/v1/crates/{crate}"))
        latest = max(
            (release["num"] for release in metadata["versions"]
             if not release["yanked"] and re.fullmatch(r"\d+\.\d+\.\d+", release["num"])),
            key=version_key,
        )
        current = re.search(rf"^{pin} := (.+)$", files["Makefile"], re.MULTILINE)[1]
        if version_key(latest) <= version_key(current):
            continue
        files["Makefile"] = files["Makefile"].replace(f"{pin} := {current}", f"{pin} := {latest}")
        replace_pattern(files, rf"({crate} --version ){re.escape(current)}\b", rf"\g<1>{latest}")
        if crate == "wit-bindgen":
            replace_pattern(files, rf'(wit-bindgen\s*=\s*(?:\{{\s*version\s*=\s*)?"=){re.escape(current)}"', rf'\g<1>{latest}"')


def update_zig(files):
    releases = json.loads(fetch("https://ziglang.org/download/index.json"))
    latest = max((version for version in releases if re.fullmatch(r"\d+\.\d+\.\d+", version)), key=version_key)
    current = re.search(r"^ZIG_VERSION := (.+)$", files["Makefile"], re.MULTILINE)[1]
    if version_key(latest) <= version_key(current):
        return
    files["Makefile"] = files["Makefile"].replace(f"ZIG_VERSION := {current}", f"ZIG_VERSION := {latest}")
    replace_pattern(files, rf"(version: |Zig ){re.escape(current)}\b", rf"\g<1>{latest}")


def fetch_image_digest(image, tag):
    metadata = json.loads(fetch(f"https://hub.docker.com/v2/repositories/library/{image}/tags/{tag}"))
    digest = metadata["digest"]
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ValueError(f"invalid digest for {image}:{tag}")
    return digest


def update_containers(files):
    alpine_version = re.search(r"^ALPINE_VERSION := (.+)$", files["pins.mk"], re.MULTILINE)[1]
    branch = alpine_version.rsplit(".", 1)[0]
    source_path = "scripts/alpine-sources.sh"
    digest = fetch_image_digest("alpine", branch)
    files[source_path] = re.sub(r"docker.io/library/alpine(?:[\w:.-]+)?@sha256:[0-9a-f]{64}", f"docker.io/library/alpine:{branch}@{digest}", files[source_path])
    index = fetch(f"https://dl-cdn.alpinelinux.org/alpine/v{branch}/main/x86_64/APKINDEX.tar.gz")
    with tarfile.open(fileobj=io.BytesIO(index), mode="r:gz") as archive:
        records = archive.extractfile("APKINDEX").read().decode()
    for record in records.strip().split("\n\n"):
        fields = dict(line.split(":", 1) for line in record.splitlines() if ":" in line)
        if fields.get("P") == "abuild":
            files[source_path] = re.sub(r"abuild=[\w.+-]+", "abuild=" + fields["V"], files[source_path])
            break
    else:
        raise ValueError("Alpine package index does not contain abuild")
    container_path = "kernel/Containerfile"
    tag = re.search(r"docker.io/library/debian:([^@]+)@", files[container_path])[1]
    digest = fetch_image_digest("debian", tag)
    files[container_path] = re.sub(r"(docker.io/library/debian:[^@]+@)sha256:[0-9a-f]{64}", rf"\g<1>{digest}", files[container_path])
    snapshots = json.loads(fetch("https://snapshot.debian.org/mr/timestamp/"))["result"]
    for repository in ("debian", "debian-security"):
        latest = max(snapshots[repository])
        if not re.fullmatch(r"\d{8}T\d{6}Z", latest):
            raise ValueError(f"invalid {repository} snapshot: {latest}")
        pattern = rf"(snapshot.debian.org/archive/{repository}/)(\d{{8}}T\d{{6}}Z)"
        current = re.search(pattern, files[container_path])[2]
        if latest > current:
            files[container_path] = re.sub(pattern, rf"\g<1>{latest}", files[container_path])


UPDATERS = {"rust": update_rust, "cargo-tools": update_cargo_tools, "zig": update_zig, "containers": update_containers}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("component", choices=UPDATERS)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    paths = [
        "Makefile", "README.dev.md", "pins.mk", "rust-toolchain.toml", "components/rust-toolchain.toml",
        "kernel/Containerfile", "scripts/alpine-sources.sh", "scripts/build-host.ps1",
        *(str(path.relative_to(args.root)) for path in args.root.glob(".github/workflows/*.yml")),
        "components/Cargo.toml",
    ]
    original = {path: (args.root / path).read_text() for path in paths}
    updated = original.copy()
    UPDATERS[args.component](updated)
    for path, text in updated.items():
        if text != original[path]:
            print("".join(difflib.unified_diff(original[path].splitlines(True), text.splitlines(True), fromfile=path, tofile=path)), end="")
            if not args.dry_run:
                (args.root / path).write_text(text)


if __name__ == "__main__":
    main()
