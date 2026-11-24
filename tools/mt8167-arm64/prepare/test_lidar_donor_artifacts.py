#!/usr/bin/env python3
"""Host-only tests for the donor-derived Lidar artifact generator.

Every fixture is synthetic.  No real dump byte, preloader or TEE image is in
the repository, and no test opens a device.
"""
from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent / "install"))

import lidar_backup_set as backup  # noqa: E402
import lidar_donor_artifacts as donor  # noqa: E402

MTK = donor.MTK_IMAGE_MAGIC


def pattern(size: int, seed: int) -> bytes:
    block = bytes((index * 7 + seed) & 0xFF for index in range(256))
    return (block * (size // 256 + 1))[:size]


def fake_stock_tee1(size: int) -> bytes:
    body = MTK + b"\0\0\0\0atf\0" + pattern(size - 12, 3)
    return body[:size].ljust(size, b"\0")


def fake_preloader(size: int) -> bytes:
    body = donor.PRELOADER_MAGIC + pattern(size - 10, 5)
    return body[:size].ljust(size, b"\0")


def fake_koboreru(size: int = 8200) -> bytes:
    body = MTK + b"\0\0\0\0atf\0" + pattern(size - 12, 1)
    return body[:size].ljust(size, b"\0")


class Fixture:
    def __init__(self, root: Path):
        self.root = root
        self.backup_dir = root / "backup"
        self.backup_dir.mkdir()
        self.preloader = fake_preloader(backup.BOOT_AREA_BYTES)
        self.tee1 = fake_stock_tee1(backup.BY_NAME["tee1"].size)
        records = {}
        for area in backup.BACKUP_SET:
            if area.name == "boot0":
                data = self.preloader
            elif area.name == "tee1":
                data = self.tee1
            else:
                data = pattern(area.size, len(area.name))
            path = self.backup_dir / f"{area.name}.bin"
            path.write_bytes(data)
            records[area.name] = {
                "file": path.name,
                "size": area.size,
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        self.manifest = self.backup_dir / "backup-manifest.json"
        self.manifest.write_text(json.dumps({
            "schema": backup.SCHEMA,
            "device": {
                "hwcode": "0x8167",
                "flash_bytes": backup.FLASH_BYTES,
                "boot_area_bytes": backup.BOOT_AREA_BYTES,
            },
            "files": records,
        }))
        self.koboreru = fake_koboreru()
        self.koboreru_sha = hashlib.sha256(self.koboreru).hexdigest()
        self.preloader_sha = hashlib.sha256(self.preloader).hexdigest()


class GenerateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fx = Fixture(self.root)

    def generate(self, **kwargs):
        kwargs.setdefault("preloader_sha256", self.fx.preloader_sha)
        return donor.generate(
            self.fx.backup_dir, self.fx.manifest, self.root / "out", **kwargs)

    def test_composes_the_stock_tail_and_records_every_digest(self):
        manifest = self.generate(
            koboreru=self.fx.koboreru, koboreru_sha256=self.fx.koboreru_sha)
        self.assertEqual(manifest["schema"], donor.SCHEMA)
        self.assertEqual(
            manifest["backup_manifest_sha256"],
            hashlib.sha256(self.fx.manifest.read_bytes()).hexdigest())
        records = {record["name"]: record for record in manifest["artifacts"]}
        self.assertEqual(set(records), {
            "boot0-preloader.bin", "tee1-stock.bin", "tee1-stock-tail.bin",
            "tee1-stage.bin"})
        for name, record in records.items():
            data = (self.root / "out" / name).read_bytes()
            self.assertEqual(record["size"], len(data))
            self.assertEqual(record["sha256"], hashlib.sha256(data).hexdigest())
            self.assertTrue(record["donor_derived"])
        self.assertEqual(records["tee1-stage.bin"]["size"], len(self.fx.tee1))
        tail = self.fx.tee1[len(self.fx.koboreru):]
        self.assertEqual(
            (self.root / "out" / "tee1-stock-tail.bin").read_bytes(), tail)
        self.assertEqual(
            (self.root / "out" / "tee1-stage.bin").read_bytes(),
            self.fx.koboreru + tail)
        self.assertEqual(
            (self.root / "out" / "boot0-preloader.bin").read_bytes(),
            self.fx.preloader)

    def test_without_koboreru_emits_only_the_stock_images(self):
        manifest = self.generate()
        names = {record["name"] for record in manifest["artifacts"]}
        self.assertEqual(names, {"boot0-preloader.bin", "tee1-stock.bin"})

    def test_refuses_an_unverified_backup_and_writes_no_manifest(self):
        (self.fx.backup_dir / "tee1.bin").write_bytes(b"\0" * 16)
        with self.assertRaises(donor.Refusal) as failure:
            self.generate()
        self.assertIn("no usable verified backup", str(failure.exception))
        self.assertFalse((self.root / "out" / donor.MANIFEST_NAME).exists())

    def test_refuses_a_preloader_that_is_not_the_reviewed_image(self):
        with self.assertRaises(donor.Refusal) as failure:
            self.generate(preloader_sha256="0" * 64)
        self.assertIn("not the reviewed 2019 signed preloader", str(failure.exception))

    def test_refuses_a_changed_tee1_after_the_manifest_pin(self):
        data = bytearray((self.fx.backup_dir / "tee1.bin").read_bytes())
        data[-1] ^= 0xFF
        (self.fx.backup_dir / "tee1.bin").write_bytes(data)
        with self.assertRaises(donor.Refusal) as failure:
            self.generate()
        self.assertIn("no usable verified backup", str(failure.exception))

    def test_refuses_koboreru_digest_and_size_mismatches(self):
        with self.assertRaises(donor.Refusal):
            self.generate(koboreru=self.fx.koboreru,
                          koboreru_sha256="0" * 64)
        with self.assertRaises(donor.Refusal):
            self.generate(koboreru=self.fx.koboreru, koboreru_sha256=None)
        too_large = fake_koboreru(backup.BY_NAME["tee1"].size + 1)
        with self.assertRaises(donor.Refusal):
            self.generate(
                koboreru=too_large,
                koboreru_sha256=hashlib.sha256(too_large).hexdigest())

    def test_load_artifact_rejects_a_changed_generated_file(self):
        manifest = self.generate()
        path = self.root / "out" / "boot0-preloader.bin"
        data = bytearray(path.read_bytes())
        data[0] ^= 0xFF
        path.write_bytes(data)
        with self.assertRaises(donor.Refusal):
            donor.load_artifact(self.root / "out", manifest, "boot0-preloader.bin")


class OutputGuardTests(unittest.TestCase):
    def test_refuses_a_public_checkout_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            checkout = Path(temporary)
            (checkout / ".git").mkdir()
            with self.assertRaises(donor.Refusal) as failure:
                donor.require_local_output(checkout / "release")
            self.assertIn("must stay private", str(failure.exception))

    def test_accepts_private_local_and_external_directories(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            checkout = root / "checkout"
            (checkout / ".git").mkdir(parents=True)
            private_out = checkout / "private" / "artifacts"
            self.assertEqual(donor.require_local_output(private_out),
                             private_out.resolve())
            self.assertEqual(
                donor.require_local_output(checkout / "local-firmware"),
                (checkout / "local-firmware").resolve())
            outside = root / "elsewhere"
            self.assertEqual(donor.require_local_output(outside), outside.resolve())


class CliTests(unittest.TestCase):
    def test_cli_writes_a_manifest_and_prints_its_digests(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fx = Fixture(root)
            out = root / "private" / "artifacts"
            koboreru = root / "koboreru.bin"
            koboreru.write_bytes(fx.koboreru)
            code = donor.main([
                "--backup-dir", str(fx.backup_dir),
                "--out", str(out),
                "--koboreru", str(koboreru),
                "--koboreru-sha256", fx.koboreru_sha,
                "--preloader-sha256", fx.preloader_sha,
            ])
            self.assertEqual(code, 0)
            self.assertTrue((out / donor.MANIFEST_NAME).is_file())


if __name__ == "__main__":
    unittest.main()
