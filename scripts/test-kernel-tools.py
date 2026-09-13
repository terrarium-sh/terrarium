#!/usr/bin/env python3
"""Test kernel configuration and artifact validation helpers."""

from __future__ import annotations

import gzip
import hashlib
import importlib.util
import io
import tarfile
import tempfile
import unittest
from pathlib import Path


SCRIPTS = Path(__file__).parent


def tool(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CONFIG = tool("check-kernel-config")
ARTIFACT = tool("kernel-artifact")


class KernelConfigTests(unittest.TestCase):
    def validate(self, config: str, fragment: str) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            resolved = directory / ".config"
            requested = directory / "fragment"
            resolved.write_text(config)
            requested.write_text(fragment)
            CONFIG.validate(resolved, [requested])

    def test_valid_requested_settings_pass(self) -> None:
        self.validate("CONFIG_VIRTIO_BLK=y\n# CONFIG_DEBUG_INFO is not set\n", "CONFIG_VIRTIO_BLK=y\n# CONFIG_DEBUG_INFO is not set\n")

    def test_missing_requested_setting_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "CONFIG_VIRTIO_BLK: wanted y, got n"):
            self.validate("# CONFIG_VIRTIO_BLK is not set\n", "CONFIG_VIRTIO_BLK=y\n")

    def test_unintended_enabled_setting_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "CONFIG_DEBUG_INFO: wanted n, got y"):
            self.validate("CONFIG_DEBUG_INFO=y\n", "# CONFIG_DEBUG_INFO is not set\n")


class KernelArtifactTests(unittest.TestCase):
    def export(self, directory: Path) -> tuple[Path, bytes, Path]:
        kernel = directory / "vmlinux"
        config = directory / ".config"
        inputs = directory / "kernel.inputs"
        archive = directory / "kernel.tar.gz"
        image = b"minimal Terra kernel\0"
        kernel.write_bytes(gzip.compress(image, mtime=0))
        config.write_text("CONFIG_VIRTIO_BLK=y\n")
        inputs.write_text("x86_64\nsource-pin\n")
        ARTIFACT.export_kernel(kernel, config, inputs, archive)
        return archive, image, inputs

    def import_into(self, archive: Path, inputs: Path, checksum: str, directory: Path) -> tuple[Path, Path]:
        kernel = directory / "output" / "vmlinux"
        config = directory / "output" / ".config"
        ARTIFACT.import_kernel(archive, checksum, inputs, kernel, config)
        return kernel, config

    def test_round_trip_preserves_kernel_and_config(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            archive, image, inputs = self.export(directory)
            checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
            kernel, config = self.import_into(archive, inputs, checksum, directory)
            self.assertEqual(kernel.read_bytes(), image)
            self.assertEqual(config.read_text(), "CONFIG_VIRTIO_BLK=y\n")
            self.assertEqual(gzip.decompress(kernel.with_suffix(".gz").read_bytes()), image)

    def test_checksum_mismatch_leaves_destinations_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            archive, _, inputs = self.export(directory)
            kernel = directory / "vmlinux"
            config = directory / ".config"
            kernel.write_bytes(b"old kernel")
            config.write_bytes(b"old config")
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                ARTIFACT.import_kernel(archive, "wrong", inputs, kernel, config)
            self.assertEqual(kernel.read_bytes(), b"old kernel")
            self.assertEqual(config.read_bytes(), b"old config")

    def test_input_identity_mismatch_leaves_destinations_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            archive, _, inputs = self.export(directory)
            kernel = directory / "vmlinux"
            config = directory / ".config"
            kernel.write_bytes(b"old kernel")
            config.write_bytes(b"old config")
            inputs.write_text("aarch64\nsource-pin\n")
            checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
            with self.assertRaisesRegex(ValueError, "does not match"):
                ARTIFACT.import_kernel(archive, checksum, inputs, kernel, config)
            self.assertEqual(kernel.read_bytes(), b"old kernel")
            self.assertEqual(config.read_bytes(), b"old config")

    def test_symlink_member_is_rejected_before_writing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            archive = directory / "kernel.tar.gz"
            with archive.open("wb") as raw:
                with gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as compressed:
                    with tarfile.open(fileobj=compressed, mode="w") as tar:
                        link = tarfile.TarInfo("vmlinux.gz")
                        link.type = tarfile.SYMTYPE
                        link.linkname = "outside"
                        tar.addfile(link)
                        for name in ("kernel.config", "kernel.inputs"):
                            entry = tarfile.TarInfo(name)
                            entry.size = 0
                            tar.addfile(entry, io.BytesIO())
            inputs = directory / "kernel.inputs"
            inputs.write_bytes(b"")
            kernel = directory / "vmlinux"
            config = directory / ".config"
            kernel.write_bytes(b"old kernel")
            config.write_bytes(b"old config")
            checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
            with self.assertRaisesRegex(ValueError, "regular files"):
                ARTIFACT.import_kernel(archive, checksum, inputs, kernel, config)
            self.assertEqual(kernel.read_bytes(), b"old kernel")
            self.assertEqual(config.read_bytes(), b"old config")


if __name__ == "__main__":
    unittest.main()
