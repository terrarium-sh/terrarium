#!/usr/bin/env python3
"""Test Bubblewrap pin validation and source distribution without downloads."""

import re
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class BubblewrapSourceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        for name in ("Makefile", "pins.mk", ".gitignore", "components/rust-toolchain.toml"):
            destination = self.directory / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, destination)
        self.source = self.directory / "vendor/bubblewrap"
        self.source.mkdir(parents=True)
        self.version = re.search(r"^BUBBLEWRAP_VERSION := (.+)$", (ROOT / "pins.mk").read_text(), re.MULTILINE)[1]
        (self.source / "meson.build").write_text(f"project(\n  version : '{self.version}',\n)\ndependency(\n  version : '>=2.1.9',\n)\n")
        (self.source / "bubblewrap.c").write_text("pinned source\n")
        (self.source / "COPYING").write_text("fixture license\n")
        self.git(self.source, "init", "--quiet")
        self.git(self.source, "add", ".")
        self.git(self.source, "commit", "--quiet", "-m", "Pinned upstream sources")
        commit = self.git(self.source, "rev-parse", "HEAD").stdout.strip()
        pins = self.directory / "pins.mk"
        pins.write_text(re.sub(r"^BUBBLEWRAP_COMMIT := .+$", f"BUBBLEWRAP_COMMIT := {commit}", pins.read_text(), flags=re.MULTILINE))

    def git(self, directory, *arguments):
        return subprocess.run(["git", "-c", "user.name=Source test", "-c", "user.email=source-test@example.invalid", *arguments],
                              cwd=directory, check=True, capture_output=True, text=True)

    def make(self, *arguments, directory=None):
        return subprocess.run(["make", "ARCH=x86_64", *arguments], cwd=directory or self.directory,
                              capture_output=True, text=True)

    def test_checkout_commit_and_version_must_match_pins(self):
        result = self.make("check-bubblewrap")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        pins = self.directory / "pins.mk"
        original = pins.read_text()
        pins.write_text(re.sub(r"^BUBBLEWRAP_COMMIT := .+$", "BUBBLEWRAP_COMMIT := " + "0" * 40, original, flags=re.MULTILINE))
        result = self.make("check-bubblewrap")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Bubblewrap commit differs from pins.mk", result.stderr)
        pins.write_text(original)
        (self.source / "meson.build").write_text("project(\n  version : '999.0.0',\n)\n")
        result = self.make("check-bubblewrap")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Bubblewrap version differs from pins.mk", result.stderr)

    def test_source_archive_contains_submodule_and_validates_without_git(self):
        (self.directory / ".gitmodules").write_text('[submodule "vendor/bubblewrap"]\n\tpath = vendor/bubblewrap\n\turl = https://example.invalid/bubblewrap.git\n')
        self.git(self.directory, "init", "--quiet")
        self.git(self.directory, "add", ".")
        self.git(self.directory, "commit", "--quiet", "-m", "Terra sources with submodule")
        build = self.directory / "build"
        build.mkdir()
        inputs = ["linux-fixture.tar.xz", "mke2fs", "rootfs.img.gz", "alpine-corresponding-source.tar.gz",
                  "libcap-fixture.tar.xz", "e2fsprogs.tar.gz", "alpine-minirootfs.tar.gz", "doas-fixture.apk", "shim-fixture.apk"]
        for name in inputs:
            (build / name).write_bytes(b"fixture source input\n")
        result = self.make("KERNEL_VERSION=fixture", "LIBCAP_VERSION=fixture", "DOAS_APK=doas-fixture.apk",
                           "DOAS_SHIM_APK=shim-fixture.apk", *(f"--old-file=build/{name}" for name in inputs), "source-dist")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        extracted = self.directory / "extracted"
        with tarfile.open(build / "terra-source.tar.gz") as archive:
            self.assertFalse(any(".git/" in name or name.endswith("/.git") for name in archive.getnames()))
            archive.extractall(extracted, filter="data")
        packaged_source = extracted / "terrarium/vendor/bubblewrap"
        self.assertEqual((packaged_source / "bubblewrap.c").read_text(), "pinned source\n")
        self.assertEqual((packaged_source / "COPYING").read_text(), "fixture license\n")
        self.assertTrue((extracted / "terrarium/build/libcap-fixture.tar.xz").is_file())
        result = self.make("check-bubblewrap", directory=extracted / "terrarium")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
