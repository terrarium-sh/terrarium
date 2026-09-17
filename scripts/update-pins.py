#!/usr/bin/env python3
"""Refresh guest input versions and hashes from their upstream releases."""

import argparse
import difflib
import hashlib
import io
from pathlib import Path
import re
import tarfile
import urllib.request


ALPINE_URL = "https://dl-cdn.alpinelinux.org/alpine"
E2FSPROGS_URL = "https://www.kernel.org/pub/linux/kernel/people/tytso/e2fsprogs"
ARCHITECTURES = ("x86_64", "aarch64")


def fetch(url):
    with urllib.request.urlopen(url, timeout=60) as response:
        return response.read()


def version_key(version):
    return tuple(map(int, version.split(".")))


def read_pin(pins, name):
    return re.search(rf"^{name} := (.+)$", pins, re.MULTILINE)[1]


def replace_pins(pins, updates):
    for name, value in updates.items():
        pins, count = re.subn(rf"^{name} := .+$", f"{name} := {value}", pins, flags=re.MULTILINE)
        if count != 1:
            raise ValueError(f"expected one {name} in pins.mk, found {count}")
    return pins


def verify_download(url, checksums):
    filename = url.rsplit("/", 1)[1]
    expected = re.findall(rf"^([0-9a-f]{{64}})\s+\*?{re.escape(filename)}$", checksums, re.MULTILINE)
    if len(expected) != 1:
        raise ValueError(f"missing or ambiguous SHA-256 for {filename}")
    digest = hashlib.sha256(fetch(url)).hexdigest()
    if digest != expected[0]:
        raise ValueError(f"SHA-256 mismatch for {url}")
    return digest


def update_e2fsprogs(pins):
    listing = fetch(f"{E2FSPROGS_URL}/").decode()
    versions = re.findall(r'href="v([0-9]+\.[0-9]+(?:\.[0-9]+)?)/"', listing)
    latest = max(versions, key=version_key)
    if version_key(latest) <= version_key(read_pin(pins, "E2FSPROGS_VERSION")):
        return pins
    url = f"{E2FSPROGS_URL}/v{latest}"
    checksum = verify_download(
        f"{url}/e2fsprogs-{latest}.tar.gz", fetch(f"{url}/sha256sums.asc").decode()
    )
    return replace_pins(pins, {"E2FSPROGS_VERSION": latest, "E2FSPROGS_SHA256": checksum})


def read_packages(index):
    with tarfile.open(fileobj=io.BytesIO(index), mode="r:gz") as archive:
        records = archive.extractfile("APKINDEX").read().decode()
    packages = {}
    for record in records.strip().split("\n\n"):
        fields = dict(line.split(":", 1) for line in record.splitlines() if ":" in line)
        if fields.get("P") in ("doas", "doas-sudo-shim"):
            packages[fields["P"]] = fields["V"]
    return packages


def update_alpine(pins):
    versions = []
    for architecture in ARCHITECTURES:
        listing = fetch(f"{ALPINE_URL}/latest-stable/releases/{architecture}/").decode()
        matches = re.findall(
            rf'href="alpine-minirootfs-([0-9]+\.[0-9]+\.[0-9]+)-{architecture}\.tar\.gz"', listing
        )
        versions.append(max(matches, key=version_key))
    if len(set(versions)) != 1:
        raise ValueError(f"Alpine release differs between architectures: {versions}")
    latest = versions[0]
    if version_key(latest) < version_key(read_pin(pins, "ALPINE_VERSION")):
        raise ValueError(f"refusing Alpine downgrade to {latest}")
    branch = "v" + latest.rsplit(".", 1)[0]
    updates = {"ALPINE_VERSION": latest}
    package_versions = {}
    for architecture in ARCHITECTURES:
        rootfs_url = f"{ALPINE_URL}/{branch}/releases/{architecture}/alpine-minirootfs-{latest}-{architecture}.tar.gz"
        updates[f"ALPINE_SHA256_{architecture}"] = verify_download(
            rootfs_url, fetch(f"{rootfs_url}.sha256").decode()
        )
        repository = f"{ALPINE_URL}/{branch}/main/{architecture}"
        packages = read_packages(fetch(f"{repository}/APKINDEX.tar.gz"))
        for package, prefix in (("doas", "DOAS"), ("doas-sudo-shim", "DOAS_SHIM")):
            version = packages[package]
            if package in package_versions and version != package_versions[package]:
                raise ValueError(f"{package} version differs between architectures")
            package_versions[package] = version
            filename = f"{package}-{version}.apk"
            updates[f"{prefix}_APK"] = filename
            updates[f"{prefix}_SHA256_{architecture}"] = hashlib.sha256(fetch(f"{repository}/{filename}")).hexdigest()
    return replace_pins(pins, updates)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("component", choices=("alpine", "e2fsprogs"))
    parser.add_argument("--pins", type=Path, default=Path("pins.mk"))
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    original = args.pins.read_text()
    updated = {"alpine": update_alpine, "e2fsprogs": update_e2fsprogs}[args.component](original)
    print("".join(difflib.unified_diff(original.splitlines(True), updated.splitlines(True), fromfile="pins.mk", tofile="pins.mk")), end="")
    if not args.dry_run and updated != original:
        args.pins.write_text(updated)


if __name__ == "__main__":
    main()
