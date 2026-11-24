#!/usr/bin/env python3
"""Tests for the Lidar backup set and its host-only verifier."""
from __future__ import annotations

import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import lidar_backup_set as backup  # noqa: E402


def content_for(name: str, size: int) -> bytes:
    """Deterministic bytes so every test manifest can pin a real sha256."""
    prefix = f"{name}:".encode()
    return prefix + b"\0" * (size - len(prefix))


class BackupSetDataTests(unittest.TestCase):
    def test_the_set_is_the_measured_lidar_boot_chain(self):
        expected = {
            "boot0": ("boot1", 0, 0x200000),
            "boot1": ("boot2", 0, 0x200000),
            "gpt": ("gpt", 0, 0x16000),
            "gpt_backup": ("gpt_backup", 0x1C7FFBE00, 0x4200),
            "lk_a": ("user", 0x300000, 0x100000),
            "lk_b": ("user", 0x900000, 0x100000),
            "tee1": ("user", 0x400000, 0x500000),
            "tee2": ("user", 0xA00000, 0x500000),
            "expdb": ("user", 0xF00000, 0xA00000),
            "misc": ("user", 0x1900000, 0x80000),
            "persist": ("user", 0x1980000, 0x1000000),
        }
        self.assertEqual({area.name: (area.kind, area.offset, area.size)
                          for area in backup.BACKUP_SET}, expected)
        self.assertEqual(backup.FLASH_BYTES, 7650410496)
        self.assertEqual(backup.GPT_BACKUP_OFFSET, backup.FLASH_BYTES - backup.GPT_BACKUP_BYTES)
        self.assertEqual(backup.BY_NAME["boot1"].kind, "boot2")

    def test_slots_the_normal_installer_owns_are_not_in_the_boot_chain_set(self):
        for name in ("boot_a", "boot_b", "userdata", "system_a", "system_b", "cache"):
            with self.subTest(name=name):
                self.assertNotIn(name, backup.BY_NAME)
        self.assertNotIn("nvram", backup.BY_NAME)  # this GPT has no nvram partition


class _ManifestFixture:
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.manifest_path = self.root / "backup-manifest.json"
        self.files = self.root / "files"
        self.files.mkdir()
        self.manifest = {
            "schema": backup.SCHEMA,
            "device": {
                "hwcode": "0x8167",
                "flash_bytes": backup.FLASH_BYTES,
                "boot_area_bytes": backup.BOOT_AREA_BYTES,
            },
            "files": {},
        }
        for area in backup.BACKUP_SET:
            name = area.name
            payload = content_for(name, area.size)
            (self.files / f"{name}.bin").write_bytes(payload)
            self.manifest["files"][name] = {
                "file": f"{name}.bin",
                "size": area.size,
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        self.write_manifest()

    def write_manifest(self, value=None):
        self.manifest_path.write_text(json.dumps(self.manifest if value is None else value))


class BackupVerifierTests(_ManifestFixture, unittest.TestCase):
    def test_a_complete_backup_verifies_clean(self):
        self.assertEqual(backup.verify_backup_set(self.files, self.manifest_path), ())
        parsed = backup.load_manifest(self.manifest_path)
        self.assertEqual(backup.verify_backup_set(self.files, parsed), ())
        backup.require_complete_backup(self.files, self.manifest_path)

    def test_a_missing_file_is_reported(self):
        (self.files / "tee1.bin").unlink()
        findings = backup.verify_backup_set(self.files, self.manifest_path)
        self.assertEqual([(item.entry, item.problem) for item in findings],
                         [("tee1", "missing")])

    def test_a_short_file_is_a_size_failure_not_a_hash_failure(self):
        path = self.files / "expdb.bin"
        path.write_bytes(path.read_bytes()[:-1])
        findings = backup.verify_backup_set(self.files, self.manifest_path)
        self.assertEqual([(item.entry, item.problem) for item in findings],
                         [("expdb", "size")])
        self.assertIn("expected", findings[0].detail)

    def test_a_long_file_is_a_size_failure(self):
        path = self.files / "misc.bin"
        path.write_bytes(path.read_bytes() + b"\0")
        findings = backup.verify_backup_set(self.files, self.manifest_path)
        self.assertEqual([(item.entry, item.problem) for item in findings],
                         [("misc", "size")])

    def test_a_changed_byte_is_a_sha256_failure(self):
        path = self.files / "boot0.bin"
        payload = bytearray(path.read_bytes())
        payload[0] ^= 0xFF
        path.write_bytes(bytes(payload))
        findings = backup.verify_backup_set(self.files, self.manifest_path)
        self.assertEqual([(item.entry, item.problem) for item in findings],
                         [("boot0", "sha256")])
        self.assertIn("manifest pins", findings[0].detail)
        with self.assertRaisesRegex(backup.BackupSetError, "boot0: sha256"):
            backup.require_complete_backup(self.files, self.manifest_path)

    def test_every_failure_is_reported_in_set_order(self):
        (self.files / "boot1.bin").unlink()
        path = self.files / "persist.bin"
        path.write_bytes(path.read_bytes()[:-4])
        findings = backup.verify_backup_set(self.files, self.manifest_path)
        self.assertEqual([(item.entry, item.problem) for item in findings],
                         [("boot1", "missing"), ("persist", "size")])


class ManifestValidationTests(_ManifestFixture, unittest.TestCase):
    def test_a_missing_entry_is_refused_before_any_file_read(self):
        value = copy.deepcopy(self.manifest)
        del value["files"]["lk_b"]
        with self.assertRaisesRegex(backup.BackupSetError, "missing backup entries: lk_b"):
            backup.parse_manifest(value)

    def test_an_unknown_entry_cannot_widen_the_set(self):
        value = copy.deepcopy(self.manifest)
        value["files"]["nvram"] = dict(value["files"]["persist"])
        with self.assertRaisesRegex(backup.BackupSetError, "unknown backup entries: nvram"):
            backup.parse_manifest(value)

    def test_a_wrong_size_cannot_pass_as_the_area(self):
        value = copy.deepcopy(self.manifest)
        value["files"]["boot0"]["size"] = 0x100000
        with self.assertRaisesRegex(backup.BackupSetError, "does not match the backup set size"):
            backup.parse_manifest(value)

    def test_a_wrong_device_geometry_is_refused(self):
        value = copy.deepcopy(self.manifest)
        value["device"]["flash_bytes"] = 0x100000000
        with self.assertRaisesRegex(backup.BackupSetError, "not the Lidar geometry"):
            backup.parse_manifest(value)

    def test_a_path_traversal_file_name_is_refused(self):
        value = copy.deepcopy(self.manifest)
        value["files"]["boot0"]["file"] = "../boot0.bin"
        with self.assertRaisesRegex(backup.BackupSetError, "unsafe file name"):
            backup.parse_manifest(value)

    def test_a_manifest_schema_must_match(self):
        value = copy.deepcopy(self.manifest)
        value["schema"] = "libreecho-lidar-backup-v0"
        with self.assertRaisesRegex(backup.BackupSetError, "schema"):
            backup.parse_manifest(value)

    def test_the_verifier_refuses_a_malformed_manifest_file(self):
        self.manifest_path.write_text("{")
        with self.assertRaisesRegex(backup.BackupSetError, "not JSON"):
            backup.verify_backup_set(self.files, self.manifest_path)


if __name__ == "__main__":
    unittest.main()
