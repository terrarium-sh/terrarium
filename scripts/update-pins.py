#!/usr/bin/env python3
"""Refresh guest input versions and hashes from their upstream releases."""

import argparse
import difflib
import gzip
import hashlib
import io
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
from typing import NamedTuple
import urllib.request
import zlib


ALPINE_URL = "https://dl-cdn.alpinelinux.org/alpine"
E2FSPROGS_URL = "https://www.kernel.org/pub/linux/kernel/people/tytso/e2fsprogs"
ARCHITECTURES = ("x86_64", "aarch64")
KEYS_DIR = Path(__file__).resolve().parent.parent / ".github" / "keys"
APK_SIGNATURE_DIGESTS = {"RSA": "sha1", "RSA256": "sha256", "RSA512": "sha512"}


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


class GzipMember(NamedTuple):
    compressed: bytes
    inflated: bytes


def gzip_members(archive):
    members = []
    while archive:
        stream = zlib.decompressobj(16 + zlib.MAX_WBITS)
        try:
            inflated = stream.decompress(archive)
        except zlib.error as error:
            raise ValueError(f"invalid gzip stream: {error}") from error
        if not stream.eof:
            raise ValueError("truncated gzip stream")
        members.append(GzipMember(archive[: len(archive) - len(stream.unused_data)], inflated))
        archive = stream.unused_data
    if len(members) < 2:
        raise ValueError("signed archive has no data after its signature")
    return members


def read_pkginfo(member):
    with tarfile.open(fileobj=io.BytesIO(member), mode="r:") as archive:
        if ".PKGINFO" not in archive.getnames():
            return {}
        content = archive.extractfile(".PKGINFO").read().decode()
    return dict(line.split(" = ", 1) for line in content.splitlines() if " = " in line)


def verify_rsa(digest, key_path, signature, data):
    with tempfile.TemporaryDirectory() as directory:
        signature_path = Path(directory) / "signature"
        data_path = Path(directory) / "data"
        signature_path.write_bytes(signature)
        data_path.write_bytes(data)
        result = subprocess.run(
            ["openssl", "dgst", f"-{digest}", "-verify", str(key_path), "-signature", str(signature_path), str(data_path)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise ValueError(f"signature from {key_path.name} does not verify: {result.stderr.strip()}")


def verify_apk(archive):
    members = gzip_members(archive)
    with tarfile.open(fileobj=io.BytesIO(members[0].inflated), mode="r:") as signatures:
        entries = signatures.getmembers()
        if not entries or any(not entry.isfile() or not entry.name.startswith(".SIGN.") for entry in entries):
            raise ValueError("invalid APK signature section")
        signature_name = entries[0].name
        signature = signatures.extractfile(entries[0]).read()
    kind, key_name = signature_name.removeprefix(".SIGN.").split(".", 1)
    digest = APK_SIGNATURE_DIGESTS.get(kind)
    if digest is None:
        raise ValueError(f"unsupported APK signature type {kind}")
    if not re.fullmatch(r"[A-Za-z0-9@_.+-]+\.rsa\.pub", key_name):
        raise ValueError(f"invalid APK signing key name {key_name}")
    key_path = KEYS_DIR / key_name
    if not key_path.is_file():
        raise ValueError(f"no committed key for {key_name}")
    verify_rsa(digest, key_path, signature, members[1].compressed)
    pkginfo = read_pkginfo(members[1].inflated)
    if pkginfo:
        if len(members) != 3:
            raise ValueError("package must have a signed control section and a data section")
        if hashlib.sha256(members[2].compressed).hexdigest() != pkginfo.get("datahash"):
            raise ValueError("data section does not match the signed datahash")
    elif len(members) != 2:
        raise ValueError("index must have exactly two gzip members")
    return members[1].inflated


def verify_pgp(key_path, signature, data):
    with tempfile.TemporaryDirectory() as directory:
        keyring = Path(directory) / "trusted.gpg"
        signature_path = Path(directory) / "signature"
        data_path = Path(directory) / "data"
        signature_path.write_bytes(signature)
        data_path.write_bytes(data)
        decoded = subprocess.run(
            ["gpg", "--homedir", directory, "--batch", "--dearmor", "--output", str(keyring), str(key_path)],
            capture_output=True,
            text=True,
        )
        if decoded.returncode != 0:
            raise ValueError(f"cannot read {key_path.name}: {decoded.stderr.strip()}")
        verified = subprocess.run(
            ["gpgv", "--homedir", directory, "--keyring", str(keyring), str(signature_path), str(data_path)],
            capture_output=True,
            text=True,
        )
        if verified.returncode != 0:
            raise ValueError(f"signature from {key_path.name} does not verify: {verified.stderr.strip()}")


def update_e2fsprogs(pins):
    listing = fetch(f"{E2FSPROGS_URL}/").decode()
    versions = re.findall(r'href="v([0-9]+\.[0-9]+(?:\.[0-9]+)?)/"', listing)
    latest = max(versions, key=version_key)
    if version_key(latest) <= version_key(read_pin(pins, "E2FSPROGS_VERSION")):
        return pins
    url = f"{E2FSPROGS_URL}/v{latest}"
    archive = fetch(f"{url}/e2fsprogs-{latest}.tar.gz")
    verify_pgp(KEYS_DIR / "tytso.asc", fetch(f"{url}/e2fsprogs-{latest}.tar.sign"), gzip.decompress(archive))
    return replace_pins(
        pins, {"E2FSPROGS_VERSION": latest, "E2FSPROGS_SHA256": hashlib.sha256(archive).hexdigest()}
    )


def read_packages(index):
    with tarfile.open(fileobj=io.BytesIO(index), mode="r:") as archive:
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
        rootfs = fetch(rootfs_url)
        verify_pgp(KEYS_DIR / "alpine-release.asc", fetch(f"{rootfs_url}.asc"), rootfs)
        updates[f"ALPINE_SHA256_{architecture}"] = hashlib.sha256(rootfs).hexdigest()
        repository = f"{ALPINE_URL}/{branch}/main/{architecture}"
        index = fetch(f"{repository}/APKINDEX.tar.gz")
        packages = read_packages(verify_apk(index))
        for package, prefix in (("doas", "DOAS"), ("doas-sudo-shim", "DOAS_SHIM")):
            version = packages[package]
            if package in package_versions and version != package_versions[package]:
                raise ValueError(f"{package} version differs between architectures")
            package_versions[package] = version
            filename = f"{package}-{version}.apk"
            archive = fetch(f"{repository}/{filename}")
            pkginfo = read_pkginfo(verify_apk(archive))
            if (pkginfo.get("pkgname"), pkginfo.get("pkgver")) != (package, version) or pkginfo.get("arch") not in (architecture, "noarch"):
                raise ValueError(f"signed package identity does not match {architecture}/{filename}")
            updates[f"{prefix}_APK"] = filename
            updates[f"{prefix}_SHA256_{architecture}"] = hashlib.sha256(archive).hexdigest()
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
