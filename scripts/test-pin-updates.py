#!/usr/bin/env python3
"""Offline checks for upstream pin selection and coordinated updates."""

import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
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


def tar_archive(entries):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:") as archive:
        for name, data in entries.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    return buffer.getvalue()


def package_index(packages):
    data = "\n\n".join(f"P:{name}\nV:{version}" for name, version in packages.items()).encode()
    return gzip.compress(tar_archive({"APKINDEX": data}))


class GuestPinsTest(unittest.TestCase):
    def setUp(self):
        self.pins = (ROOT / "pins.mk").read_text()
        self.feeds = {}
        self.pgp_verifications = []
        self.apk_verifications = []
        self.fetch = patch.object(guest, "fetch", side_effect=self.feeds.__getitem__)
        self.fetch.start()
        self.addCleanup(self.fetch.stop)

        def record_pgp(key_path, signature, data):
            self.pgp_verifications.append((key_path.name, signature, data))

        def record_apk(archive):
            self.apk_verifications.append(archive)
            return gzip.decompress(archive)

        for name, recorder in (("verify_pgp", record_pgp), ("verify_apk", record_apk)):
            patcher = patch.object(guest, name, side_effect=recorder)
            patcher.start()
            self.addCleanup(patcher.stop)

    def rootfs_url(self, version, architecture):
        branch = "v" + version.rsplit(".", 1)[0]
        return f"{guest.ALPINE_URL}/{branch}/releases/{architecture}/alpine-minirootfs-{version}-{architecture}.tar.gz"

    def repository(self, version, architecture):
        branch = "v" + version.rsplit(".", 1)[0]
        return f"{guest.ALPINE_URL}/{branch}/main/{architecture}"

    def add_alpine(self, version="3.25.1"):
        for architecture in guest.ARCHITECTURES:
            self.feeds[f"{guest.ALPINE_URL}/latest-stable/releases/{architecture}/"] = (
                f'<a href="alpine-minirootfs-{version}-{architecture}.tar.gz">release</a>'
                f'<a href="alpine-minirootfs-99.0.0_rc1-{architecture}.tar.gz">rc</a>'
            ).encode()
            rootfs_url = self.rootfs_url(version, architecture)
            self.feeds[rootfs_url] = f"{architecture} rootfs".encode()
            self.feeds[rootfs_url + ".asc"] = b"rootfs signature"
            repository = self.repository(version, architecture)
            self.feeds[f"{repository}/APKINDEX.tar.gz"] = package_index({"doas": "6.9-r12", "doas-sudo-shim": "0.3-r1"})
            for package, package_version in (("doas", "6.9-r12"), ("doas-sudo-shim", "0.3-r1")):
                filename = f"{package}-{package_version}.apk"
                metadata = f"pkgname = {package}\npkgver = {package_version}\narch = {architecture}\n".encode()
                self.feeds[f"{repository}/{filename}"] = gzip.compress(tar_archive({".PKGINFO": metadata}))

    def test_alpine_updates_packages_and_all_architecture_hashes_together(self):
        self.add_alpine()
        updated = guest.update_alpine(self.pins)
        self.assertEqual(guest.read_pin(updated, "ALPINE_VERSION"), "3.25.1")
        self.assertEqual(guest.read_pin(updated, "DOAS_APK"), "doas-6.9-r12.apk")
        self.assertEqual(guest.read_pin(updated, "DOAS_SHIM_APK"), "doas-sudo-shim-0.3-r1.apk")
        for architecture in guest.ARCHITECTURES:
            repository = self.repository("3.25.1", architecture)
            digests = {
                "ALPINE": hashlib.sha256(self.feeds[self.rootfs_url("3.25.1", architecture)]).hexdigest(),
                "DOAS": hashlib.sha256(self.feeds[f"{repository}/doas-6.9-r12.apk"]).hexdigest(),
                "DOAS_SHIM": hashlib.sha256(self.feeds[f"{repository}/doas-sudo-shim-0.3-r1.apk"]).hexdigest(),
            }
            for prefix, digest in digests.items():
                self.assertEqual(guest.read_pin(updated, f"{prefix}_SHA256_{architecture}"), digest)
        self.assertEqual(
            [verification[0] for verification in self.pgp_verifications],
            ["alpine-release.asc", "alpine-release.asc"],
        )
        self.assertEqual(len(self.apk_verifications), 6)
        self.assertEqual(guest.update_alpine(updated), updated)
        for name in ("KERNEL_VERSION", "KERNEL_SHA256", "E2FSPROGS_VERSION", "E2FSPROGS_SHA256"):
            self.assertEqual(guest.read_pin(updated, name), guest.read_pin(self.pins, name))

    def test_alpine_package_updates_do_not_require_a_rootfs_release(self):
        self.add_alpine(guest.read_pin(self.pins, "ALPINE_VERSION"))
        self.assertIn("DOAS_APK := doas-6.9-r12.apk", guest.update_alpine(self.pins))

    def test_alpine_rejects_architecture_mismatches(self):
        self.add_alpine()
        repository = self.repository("3.25.1", "aarch64")
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

    def test_e2fsprogs_selects_numeric_stable_release_and_verifies_signature(self):
        self.feeds[guest.E2FSPROGS_URL + "/"] = b'<a href="v1.9/">old</a><a href="v1.100.0/">stable</a><a href="v2.0-rc1/">rc</a>'
        archive = gzip.compress(b"e2fsprogs 1.100.0 tarball")
        self.feeds[guest.E2FSPROGS_URL + "/v1.100.0/e2fsprogs-1.100.0.tar.gz"] = archive
        self.feeds[guest.E2FSPROGS_URL + "/v1.100.0/e2fsprogs-1.100.0.tar.sign"] = b"detached signature"
        updated = guest.update_e2fsprogs(self.pins)
        self.assertEqual(guest.read_pin(updated, "E2FSPROGS_VERSION"), "1.100.0")
        self.assertEqual(guest.read_pin(updated, "E2FSPROGS_SHA256"), hashlib.sha256(archive).hexdigest())
        self.assertEqual(
            self.pgp_verifications,
            [("tytso.asc", b"detached signature", b"e2fsprogs 1.100.0 tarball")],
        )
        self.assertEqual(guest.update_e2fsprogs(updated), updated)

    def test_signed_package_must_match_requested_identity(self):
        self.add_alpine()
        url = f"{self.repository('3.25.1', 'x86_64')}/doas-6.9-r12.apk"
        for field, value in (("pkgname", "other"), ("pkgver", "1-r0"), ("arch", "aarch64")):
            metadata = {"pkgname": "doas", "pkgver": "6.9-r12", "arch": "x86_64"}
            metadata[field] = value
            content = "".join(f"{key} = {value}\n" for key, value in metadata.items()).encode()
            self.feeds[url] = gzip.compress(tar_archive({".PKGINFO": content}))
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "identity"):
                guest.update_alpine(self.pins)

    def test_missing_pin_is_not_silently_ignored(self):
        with self.assertRaises(ValueError):
            guest.replace_pins(self.pins, {"MISSING_PIN": "1"})


@unittest.skipUnless(shutil.which("openssl"), "openssl required")
class ApkSignatureTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        private_key = self.root / "tester.pem"
        subprocess.run(
            ["openssl", "genpkey", "-quiet", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(private_key)],
            check=True,
        )
        public_key = self.root / "tester.rsa.pub"
        subprocess.run(
            ["openssl", "pkey", "-in", str(private_key), "-pubout", "-out", str(public_key)],
            check=True,
            capture_output=True,
        )
        self.private_key = private_key
        self.key_name = public_key.name
        keys_dir = patch.object(guest, "KEYS_DIR", self.root)
        keys_dir.start()
        self.addCleanup(keys_dir.stop)

    def sign(self, data):
        signature = self.root / "signature"
        subprocess.run(
            ["openssl", "dgst", "-sha1", "-sign", str(self.private_key), "-out", str(signature)],
            input=data,
            check=True,
        )
        return signature.read_bytes()

    def index_content(self):
        return gzip.compress(tar_archive({"DESCRIPTION": b"test", "APKINDEX": b"P:doas\nV:6.9-r12\n"}))

    def signed_index(self, signature=None):
        content = self.index_content()
        if signature is None:
            signature = self.sign(content)
        return gzip.compress(tar_archive({f".SIGN.RSA.{self.key_name}": signature})) + content

    def signed_package(self, datahash=None):
        content = gzip.compress(tar_archive({"etc/doas.conf": b"permit nopass user"}))
        pkginfo = f"pkgname = doas\ndatahash = {datahash or hashlib.sha256(content).hexdigest()}\n".encode()
        control = gzip.compress(tar_archive({".PKGINFO": pkginfo}))
        signature = self.sign(control)
        return gzip.compress(tar_archive({f".SIGN.RSA.{self.key_name}": signature})) + control + content

    def test_signed_index_and_package_verify(self):
        guest.verify_apk(self.signed_index())
        guest.verify_apk(self.signed_package())

    def test_tampered_signature_content_and_datahash_are_rejected(self):
        signature = bytearray(self.sign(self.index_content()))
        signature[0] ^= 1
        with self.assertRaisesRegex(ValueError, "does not verify"):
            guest.verify_apk(self.signed_index(bytes(signature)))
        corrupted = bytearray(self.signed_index())
        corrupted[-1] ^= 1
        with self.assertRaisesRegex(ValueError, "invalid gzip stream"):
            guest.verify_apk(bytes(corrupted))
        package = bytearray(self.signed_package())
        package[-1] ^= 1
        with self.assertRaisesRegex(ValueError, "invalid gzip stream"):
            guest.verify_apk(bytes(package))
        with self.assertRaisesRegex(ValueError, "datahash"):
            guest.verify_apk(self.signed_package(datahash="0" * 64))

    def test_missing_package_data_is_rejected(self):
        members = guest.gzip_members(self.signed_package())
        truncated = b"".join(member.compressed for member in members[:2])
        with self.assertRaisesRegex(ValueError, "data section"):
            guest.verify_apk(truncated)

    def test_unsigned_index_in_signature_section_is_rejected(self):
        content = self.index_content()
        signature = gzip.compress(tar_archive({
            f".SIGN.RSA.{self.key_name}": self.sign(content),
            "APKINDEX": b"P:doas\nV:99-r0\n",
        }))
        with self.assertRaisesRegex(ValueError, "signature section"):
            guest.verify_apk(signature + content)
        self.assertEqual(guest.read_packages(guest.verify_apk(self.signed_index())), {"doas": "6.9-r12"})

    def test_key_paths_outside_committed_directory_are_rejected(self):
        content = self.index_content()
        for key in (str(self.root / self.key_name), f"../{self.root.name}/{self.key_name}"):
            signature = gzip.compress(tar_archive({f".SIGN.RSA.{key}": self.sign(content)}))
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "key name"):
                guest.verify_apk(signature + content)

    def test_unknown_signing_key_is_rejected(self):
        content = gzip.compress(tar_archive({"APKINDEX": b"P:doas\n"}))
        archive = gzip.compress(tar_archive({".SIGN.RSA.missing.rsa.pub": b"signature"})) + content
        with self.assertRaisesRegex(ValueError, "no committed key"):
            guest.verify_apk(archive)


@unittest.skipUnless(shutil.which("gpg") and shutil.which("gpgv"), "gpg and gpgv required")
class PgpVerificationTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.home = self.root / "gnupg"
        self.home.mkdir(mode=0o700)
        subprocess.run(
            [
                "gpg", "--homedir", str(self.home), "--batch", "--passphrase", "",
                "--quick-gen-key", "tester@example.invalid", "ed25519", "sign", "0",
            ],
            check=True,
            capture_output=True,
        )
        self.public_key = self.root / "public.asc"
        with self.public_key.open("wb") as public:
            subprocess.run(
                ["gpg", "--homedir", str(self.home), "--armor", "--export", "tester@example.invalid"],
                stdout=public,
                check=True,
            )

    def sign(self, data):
        data_path = self.root / "data"
        data_path.write_bytes(data)
        signature = self.root / "data.asc"
        subprocess.run(
            [
                "gpg", "--homedir", str(self.home), "--batch", "--yes", "--armor",
                "--detach-sign", "--output", str(signature), str(data_path),
            ],
            check=True,
            capture_output=True,
        )
        return signature.read_bytes()

    def test_detached_signature_verifies_and_tampering_is_rejected(self):
        data = b"guest input"
        signature = self.sign(data)
        guest.verify_pgp(self.public_key, signature, data)
        with self.assertRaisesRegex(ValueError, "does not verify"):
            guest.verify_pgp(self.public_key, signature, b"tampered")


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
        nightly = b'date = "2026-02-01"\n[pkg.rust-std.target.wasm32-unknown-unknown]\navailable = true\n[pkg.rust-std.target.wasm32-wasip3]\navailable = true\n'
        self.feeds["https://static.rust-lang.org/dist/channel-rust-nightly.toml"] = nightly
        original = self.files.copy()
        tools.update_rust(self.files)
        self.assertIn('channel = "1.100.0"', self.files["rust-toolchain.toml"])
        self.assertIn("nightly-2026-02-01", self.files["build.yml"])
        self.feeds["https://static.rust-lang.org/dist/channel-rust-nightly.toml"] = nightly.replace(
            b"[pkg.rust-std.target.wasm32-unknown-unknown]\navailable = true",
            b"[pkg.rust-std.target.wasm32-unknown-unknown]\navailable = false",
        )
        with self.assertRaisesRegex(ValueError, "wasm32-unknown-unknown"):
            tools.update_rust(original)
        self.feeds["https://static.rust-lang.org/dist/channel-rust-nightly.toml"] = nightly.replace(
            b"[pkg.rust-std.target.wasm32-wasip3]\navailable = true",
            b"[pkg.rust-std.target.wasm32-wasip3]\navailable = false",
        )
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
