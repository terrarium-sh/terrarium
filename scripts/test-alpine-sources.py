#!/usr/bin/env python3
"""Offline checks for alpine-sources.sh."""

import io
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
COLLECTOR = ROOT / "scripts/alpine-sources.sh"

GIT = r'''#!/usr/bin/env python3
import io, os, pathlib, sys, tarfile

args = sys.argv[1:]
if "init" in args:
    pathlib.Path(args[-1]).mkdir(parents=True, exist_ok=True)
if "fetch" in args and os.environ.get("FAIL_FETCH"):
    raise SystemExit(23)
if "archive" in args:
    path = args[args.index("archive") + 2]
    data = b"pkgname=test\npkgver=1\n"
    with tarfile.open(fileobj=sys.stdout.buffer, mode="w|") as archive:
        entry = tarfile.TarInfo(path + "/APKBUILD")
        entry.size = len(data)
        archive.addfile(entry, io.BytesIO(data))
'''

PODMAN = r'''#!/usr/bin/env python3
import os, pathlib, sys

if os.environ.get("FAIL_PODMAN"):
    raise SystemExit(24)
chost = sys.argv[sys.argv.index("--env") + 1].split("=", 1)[1]
for index, argument in enumerate(sys.argv):
    if argument == "--volume" and sys.argv[index + 1].endswith(":/distfiles:rw"):
        directory = pathlib.Path(sys.argv[index + 1].split(":", 1)[0])
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "source.tar.gz").write_bytes(chost.encode())
'''


class AlpineSourcesTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        scripts = self.root / "scripts"
        scripts.mkdir()
        self.collector = scripts / "alpine-sources.sh"
        shutil.copy2(COLLECTOR, self.collector)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.command("git", GIT)
        self.command("podman", PODMAN)

    def tearDown(self):
        self.temp.cleanup()

    def command(self, name, body):
        path = self.bin / name
        path.write_text(body)
        path.chmod(path.stat().st_mode | stat.S_IXUSR)

    def write_database(self, records):
        image = self.root / "build/alpine-minirootfs.tar.gz"
        image.parent.mkdir()
        data = ("A:aarch64\n\n" + "\n\n".join(records)).encode()
        with tarfile.open(image, "w:gz") as archive:
            entry = tarfile.TarInfo("./lib/apk/db/installed")
            entry.size = len(data)
            archive.addfile(entry, io.BytesIO(data))

    def collect(self, **extra):
        env = os.environ | {"PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}"} | extra
        return subprocess.run([self.collector], cwd=self.root, env=env, capture_output=True, text=True)

    def test_collects_each_gpl_origin_once_with_sources_and_distfiles(self):
        self.write_database([
            "P:busybox\nV:1\nL:GPL-2.0-only\no:busybox\nc:deadbeef",
            "P:busybox-doc\nV:1\nL:GPL-2.0-only\no:busybox\nc:deadbeef",
            "P:musl\nV:1\nL:MIT\no:musl\nc:feedface",
        ])
        result = self.collect()
        self.assertEqual(result.returncode, 0, result.stderr)
        output = self.root / "build/alpine-corresponding-source.tar.gz"
        with tarfile.open(output) as archive:
            names = archive.getnames()
            manifest = archive.extractfile("manifest.tsv").read().decode().splitlines()
            distfile = archive.extractfile("distfiles/source.tar.gz").read()
        self.assertEqual(len(manifest), 1)
        self.assertEqual(manifest[0].split("\t")[2:4], ["busybox", "deadbeef"])
        self.assertIn("sources/busybox-deadbeef/APKBUILD", names)
        self.assertIn("distfiles/source.tar.gz", names)
        self.assertEqual(distfile, b"aarch64")

    def test_missing_gpl_metadata_fails_without_an_archive(self):
        self.write_database(["P:busybox\nV:1\nL:GPL-2.0-only\no:busybox"])
        result = self.collect()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing Alpine source origin or commit", result.stderr)
        self.assertFalse((self.root / "build/alpine-corresponding-source.tar.gz").exists())

    def test_fetch_and_container_failures_do_not_archive_partial_sources(self):
        self.write_database(["P:busybox\nV:1\nL:GPL-2.0-only\no:busybox\nc:deadbeef"])
        for failure in ("FAIL_FETCH", "FAIL_PODMAN"):
            with self.subTest(failure=failure):
                result = self.collect(**{failure: "1"})
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.root / "build/alpine-corresponding-source.tar.gz").exists())


if __name__ == "__main__":
    unittest.main()
