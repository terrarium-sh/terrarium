#!/usr/bin/env python3
"""Offline checks for upstream pin selection and coordinated updates."""

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


guest = load_script("update-pins")
tools = load_script("update-build-tools")


def package_index(packages):
    data = "\n\n".join(f"P:{name}\nV:{version}" for name, version in packages.items()).encode()
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        member = tarfile.TarInfo("APKINDEX")
        member.size = len(data)
        archive.addfile(member, io.BytesIO(data))
    return buffer.getvalue()


class GuestPinsTest(unittest.TestCase):
    def setUp(self):
        self.pins = (ROOT / "pins.mk").read_text()
        self.feeds = {}
        self.fetch = patch.object(guest, "fetch", side_effect=self.feeds.__getitem__)
        self.fetch.start()
        self.addCleanup(self.fetch.stop)

    def add_archive(self, url):
        data = url.encode()
        self.feeds[url] = data
        checksum = hashlib.sha256(data).hexdigest()
        sums = f"{checksum}  {url.rsplit('/', 1)[1]}\n".encode()
        self.feeds[url + ".sha256"] = sums
        return checksum, sums

    def add_alpine(self, version="3.25.1"):
        branch = "v" + version.rsplit(".", 1)[0]
        for architecture in guest.ARCHITECTURES:
            self.feeds[f"{guest.ALPINE_URL}/latest-stable/releases/{architecture}/"] = (
                f'<a href="alpine-minirootfs-{version}-{architecture}.tar.gz">release</a>'
                f'<a href="alpine-minirootfs-99.0.0_rc1-{architecture}.tar.gz">rc</a>'
            ).encode()
            self.add_archive(f"{guest.ALPINE_URL}/{branch}/releases/{architecture}/alpine-minirootfs-{version}-{architecture}.tar.gz")
            repository = f"{guest.ALPINE_URL}/{branch}/main/{architecture}"
            self.feeds[f"{repository}/APKINDEX.tar.gz"] = package_index({"doas": "6.9-r12", "doas-sudo-shim": "0.3-r1"})
            for filename in ("doas-6.9-r12.apk", "doas-sudo-shim-0.3-r1.apk"):
                self.feeds[f"{repository}/{filename}"] = (architecture + filename).encode()

    def test_alpine_updates_packages_and_all_architecture_hashes_together(self):
        self.add_alpine()
        updated = guest.update_alpine(self.pins)
        self.assertEqual(guest.read_pin(updated, "ALPINE_VERSION"), "3.25.1")
        self.assertEqual(guest.read_pin(updated, "DOAS_APK"), "doas-6.9-r12.apk")
        self.assertEqual(guest.read_pin(updated, "DOAS_SHIM_APK"), "doas-sudo-shim-0.3-r1.apk")
        for architecture in guest.ARCHITECTURES:
            for prefix in ("ALPINE", "DOAS", "DOAS_SHIM"):
                name = f"{prefix}_SHA256_{architecture}"
                self.assertNotEqual(guest.read_pin(updated, name), guest.read_pin(self.pins, name))
        self.assertEqual(guest.update_alpine(updated), updated)
        for name in ("KERNEL_VERSION", "KERNEL_SHA256", "E2FSPROGS_VERSION", "E2FSPROGS_SHA256"):
            self.assertEqual(guest.read_pin(updated, name), guest.read_pin(self.pins, name))

    def test_alpine_package_updates_do_not_require_a_rootfs_release(self):
        self.add_alpine(guest.read_pin(self.pins, "ALPINE_VERSION"))
        self.assertIn("DOAS_APK := doas-6.9-r12.apk", guest.update_alpine(self.pins))

    def test_alpine_rejects_architecture_mismatches(self):
        self.add_alpine()
        repository = f"{guest.ALPINE_URL}/v3.25/main/aarch64"
        self.feeds[f"{repository}/APKINDEX.tar.gz"] = package_index({"doas": "6.9-r11", "doas-sudo-shim": "0.3-r1"})
        with self.assertRaisesRegex(ValueError, "version differs"):
            guest.update_alpine(self.pins)
        self.feeds[f"{guest.ALPINE_URL}/latest-stable/releases/aarch64/"] = b'<a href="alpine-minirootfs-3.25.0-aarch64.tar.gz">release</a>'
        with self.assertRaisesRegex(ValueError, "release differs"):
            guest.update_alpine(self.pins)

    def test_alpine_rejects_downgrades(self):
        self.add_alpine("3.1.0")
        with self.assertRaisesRegex(ValueError, "downgrade"):
            guest.update_alpine(self.pins)

    def test_corrupt_download_and_missing_checksum_fail(self):
        url = "https://example.org/source.tar.gz"
        _, sums = self.add_archive(url)
        self.feeds[url] = b"corrupted"
        with self.assertRaisesRegex(ValueError, "mismatch"):
            guest.verify_download(url, sums.decode())
        with self.assertRaisesRegex(ValueError, "missing"):
            guest.verify_download(url, "")

    def test_e2fsprogs_selects_numeric_stable_release_and_verifies_hash(self):
        self.feeds[guest.E2FSPROGS_URL + "/"] = b'<a href="v1.9/">old</a><a href="v1.100.0/">stable</a><a href="v2.0-rc1/">rc</a>'
        digest, sums = self.add_archive(guest.E2FSPROGS_URL + "/v1.100.0/e2fsprogs-1.100.0.tar.gz")
        self.feeds[guest.E2FSPROGS_URL + "/v1.100.0/sha256sums.asc"] = b"-----BEGIN PGP SIGNED MESSAGE-----\n\n" + sums
        updated = guest.update_e2fsprogs(self.pins)
        self.assertEqual(guest.read_pin(updated, "E2FSPROGS_VERSION"), "1.100.0")
        self.assertEqual(guest.read_pin(updated, "E2FSPROGS_SHA256"), digest)
        self.assertEqual(guest.update_e2fsprogs(updated), updated)

    def test_missing_pin_is_not_silently_ignored(self):
        with self.assertRaises(ValueError):
            guest.replace_pins(self.pins, {"MISSING_PIN": "1"})


class BuildToolsTest(unittest.TestCase):
    def setUp(self):
        self.files = {
            "Makefile": "WASM_TOOLS_VERSION := 1.2.0\nCARGO_FUZZ_VERSION := 0.1.0\nCARGO_AUDIT_VERSION := 0.1.0\nWIT_BINDGEN_VERSION := 0.1.0\nZIG_VERSION := 0.9.0\n",
            "rust-toolchain.toml": '[toolchain]\nchannel = "1.90.0"\n',
            "components/rust-toolchain.toml": '[toolchain]\nchannel = "nightly-2026-01-01"\n',
            "build.yml": "run: cargo install wasm-tools --version 1.2.0\nrun: cargo install cargo-fuzz --version 0.1.0\nrun: cargo install cargo-audit --version 0.1.0\nversion: 0.9.0\nrun: cargo +nightly-2026-01-01 build\n",
            "README.dev.md": "Install Zig 0.9.0\n",
            "component/Cargo.toml": 'wit-bindgen = { version = "=0.1.0", features = ["async-spawn"] }\n',
            "policy/Cargo.toml": 'wit-bindgen = "=0.1.0"\n',
            "pins.mk": "ALPINE_VERSION := 3.24.1\n",
            "scripts/alpine-sources.sh": "image='docker.io/library/alpine@sha256:" + "a" * 64 + "'\napk add abuild=3.17.0-r0\n",
            "kernel/Containerfile": "FROM docker.io/library/debian:bookworm-slim@sha256:" + "a" * 64 + "\nhttp://snapshot.debian.org/archive/debian/20260101T000000Z/\nhttp://snapshot.debian.org/archive/debian-security/20260101T000000Z/\n",
        }
        self.feeds = {}
        self.fetch = patch.object(tools, "fetch", side_effect=self.feeds.__getitem__)
        self.fetch.start()
        self.addCleanup(self.fetch.stop)

    def test_cargo_tools_ignore_yanked_and_prerelease_versions_and_sync_consumers(self):
        for crate in ("wasm-tools", "cargo-fuzz", "cargo-audit", "wit-bindgen"):
            self.feeds[f"https://crates.io/api/v1/crates/{crate}"] = json.dumps({"versions": [
                {"num": "9.0.0-rc1", "yanked": False}, {"num": "8.0.0", "yanked": True},
                {"num": "1.10.0", "yanked": False}, {"num": "1.9.0", "yanked": False},
            ]}).encode()
        tools.update_cargo_tools(self.files)
        self.assertIn("WASM_TOOLS_VERSION := 1.10.0", self.files["Makefile"])
        self.assertIn("wasm-tools --version 1.10.0", self.files["build.yml"])
        self.assertIn("cargo-fuzz --version 1.10.0", self.files["build.yml"])
        self.assertIn("cargo-audit --version 1.10.0", self.files["build.yml"])
        self.assertIn('version = "=1.10.0"', self.files["component/Cargo.toml"])
        self.assertIn('wit-bindgen = "=1.10.0"', self.files["policy/Cargo.toml"])
        unchanged = self.files.copy()
        tools.update_cargo_tools(self.files)
        self.assertEqual(self.files, unchanged)

    def test_zig_ignores_master_and_updates_workflows_and_documentation(self):
        self.feeds["https://ziglang.org/download/index.json"] = b'{"master": {}, "0.10.0": {}, "0.9.0": {}}'
        tools.update_zig(self.files)
        self.assertIn("ZIG_VERSION := 0.10.0", self.files["Makefile"])
        self.assertIn("version: 0.10.0", self.files["build.yml"])
        self.assertIn("Zig 0.10.0", self.files["README.dev.md"])

    def test_rust_updates_channels_and_requires_the_wasm_target(self):
        self.feeds["https://static.rust-lang.org/dist/channel-rust-stable.toml"] = b'[pkg.rust]\nversion = "1.100.0 (hash date)"\n'
        nightly = b'date = "2026-02-01"\n[pkg.rust-std.target.wasm32-wasip3]\navailable = true\n'
        self.feeds["https://static.rust-lang.org/dist/channel-rust-nightly.toml"] = nightly
        original = self.files.copy()
        tools.update_rust(self.files)
        self.assertIn('channel = "1.100.0"', self.files["rust-toolchain.toml"])
        self.assertIn("nightly-2026-02-01", self.files["build.yml"])
        self.feeds["https://static.rust-lang.org/dist/channel-rust-nightly.toml"] = nightly.replace(b"true", b"false")
        with self.assertRaisesRegex(ValueError, "wasm32-wasip3"):
            tools.update_rust(original)

    def test_containers_update_digests_abuild_and_each_snapshot(self):
        for image, tag in (("alpine", "3.24"), ("debian", "bookworm-slim")):
            self.feeds[f"https://hub.docker.com/v2/repositories/library/{image}/tags/{tag}"] = json.dumps({"digest": "sha256:" + "b" * 64}).encode()
        self.feeds["https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/APKINDEX.tar.gz"] = package_index({"abuild": "3.18.0-r1"})
        self.feeds["https://snapshot.debian.org/mr/timestamp/"] = b'{"result": {"debian": ["20260201T000000Z"], "debian-security": ["20260202T000000Z"]}}'
        tools.update_containers(self.files)
        self.assertIn("alpine:3.24@sha256:" + "b" * 64, self.files["scripts/alpine-sources.sh"])
        self.assertIn("abuild=3.18.0-r1", self.files["scripts/alpine-sources.sh"])
        self.assertIn("debian:bookworm-slim@sha256:" + "b" * 64, self.files["kernel/Containerfile"])
        self.assertIn("debian/20260201T000000Z/", self.files["kernel/Containerfile"])
        self.assertIn("debian-security/20260202T000000Z/", self.files["kernel/Containerfile"])


class PinPullRequestTest(unittest.TestCase):
    def run_workflow(self, **settings):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            command = root / "command"
            command.write_text(r'''#!/usr/bin/env python3
import json, os, pathlib, sys
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ["COMMAND_LOG"], "a") as log:
    log.write(json.dumps([name, *args]) + "\n")
if name == "git" and args[:2] == ["diff", "--quiet"]:
    raise SystemExit(0 if os.environ.get("NO_CHANGES") else 1)
if name == "git" and args[0] == "diff":
    print("test pin diff")
if name == "gh" and args[:2] == ["pr", "list"]:
    print("1" if os.environ.get("EXISTING_PR") else "0")
if name == "gh" and args[:2] == ["pr", "create"]:
    assert "Update alpine pins" in pathlib.Path(args[args.index("--body-file") + 1]).read_text()
''')
            command.chmod(0o755)
            for name in ("git", "gh"):
                (root / name).symlink_to(command)
            log = root / "commands.jsonl"
            env = os.environ | settings | {
                "PATH": f"{root}:{os.environ['PATH']}", "COMMAND_LOG": str(log), "BASE_BRANCH": "main",
            }
            result = subprocess.run(["bash", str(ROOT / "scripts/open-pin-pr.sh"), "alpine", "pins.mk"], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            return [json.loads(line) for line in log.read_text().splitlines()]

    def test_new_pr_stages_only_requested_files_and_dispatches_build(self):
        commands = self.run_workflow()
        self.assertIn(["git", "add", "--", "pins.mk"], commands)
        self.assertTrue(any(command[:3] == ["gh", "pr", "create"] for command in commands))
        self.assertTrue(any(command[:4] == ["gh", "workflow", "run", "build.yml"] for command in commands))

    def test_no_changes_or_existing_pr_do_not_commit_or_push(self):
        for settings in ({"NO_CHANGES": "1"}, {"EXISTING_PR": "1"}):
            with self.subTest(settings=settings):
                commands = self.run_workflow(**settings)
                self.assertFalse(any(command[:2] in (["git", "commit"], ["git", "push"]) for command in commands))


if __name__ == "__main__":
    unittest.main()
