#!/usr/bin/env python3
"""Regression tests for the 0.13.15 owner-local MT8163 importer contract."""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


TOOLS_DIR = Path(__file__).resolve().parent
IMPORTER = TOOLS_DIR / "initramfs/libreecho-vendor-import"
SHIPPED_SPEC_DIR = TOOLS_DIR / "initramfs/vendor-assets"
V2_SPEC = SHIPPED_SPEC_DIR / "mt8163-v181-stock-v2.tsv"
LIDAR_BUNDLE_ID = "lidar-mt7668-stock-v1"
LIDAR_SPEC = SHIPPED_SPEC_DIR / (LIDAR_BUNDLE_ID + ".tsv")
LIDAR_FILES = (
    "WIFI_RAM_CODE_MT7668.bin",
    "WIFI_RAM_CODE2_SDIO_MT7668.bin",
    "EEPROM_MT7668.bin",
    "TxPwrLimit_MT76x8.dat",
    "wifi.cfg",
)
# The importer pins the two MT7668 RAM codes and bounds the per-unit
# calibration.  The contract under test is the layout, inventory and pin
# enforcement, not the vendor payload, so the fixtures take their sizes from
# the shipped spec and carry synthetic bytes.
LIDAR_PER_UNIT_SIZES = {
    "EEPROM_MT7668.bin": 1024,
    "TxPwrLimit_MT76x8.dat": 64,
    "wifi.cfg": 32,
}
LIDAR_HASH_CONSTANTS = {
    "WIFI_RAM_CODE_MT7668.bin": ("LIDAR_RAM_CODE_HASH", "LIDAR_RAM_CODE_SIZE"),
    "WIFI_RAM_CODE2_SDIO_MT7668.bin": ("LIDAR_CR4_CODE_HASH",
                                       "LIDAR_CR4_CODE_SIZE"),
}
TARGETS = (
    "ROMv2_lm_patch_1_0_hdr.bin",
    "ROMv2_lm_patch_1_1_hdr.bin",
    "WIFI_RAM_CODE_8163",
    "WMT_SOC.cfg",
)


def patch_payload(meta: bytes, fill: int) -> bytes:
    payload = bytearray([fill] * 28)
    payload[22:28] = meta
    return bytes(payload)


def unknown_payloads() -> dict[str, bytes]:
    return {
        "ROMv2_lm_patch_1_0_hdr.bin": patch_payload(bytes.fromhex("8a0022000600"), 0x31),
        "ROMv2_lm_patch_1_1_hdr.bin": patch_payload(bytes.fromhex("8a0021000ef0"), 0x42),
        "WIFI_RAM_CODE_8163": b"unknown-owner-local-wifi-code",
        "WMT_SOC.cfg": b"unknown-owner-local-wmt-config\n",
    }


def write_payloads(root: Path, payloads: dict[str, bytes]) -> Path:
    layout = root / "system/vendor/firmware"
    layout.mkdir(parents=True, exist_ok=True)
    for name, payload in payloads.items():
        (layout / name).write_bytes(payload)
    return layout


def manifest_lines(payloads: dict[str, bytes], source_layout: str = "system/vendor/firmware") -> str:
    lines = []
    for name in TARGETS:
        payload = payloads[name]
        lines.append(
            f"{hashlib.sha256(payload).hexdigest()}|{len(payload)}|"
            f"{source_layout}/{name}|{name}\n"
        )
    return "".join(lines)


def shipped_lidar_records() -> dict[str, tuple[str, str]]:
    """The digest/size rows of the shipped Lidar spec, keyed by target name."""
    records = {}
    for line in LIDAR_SPEC.read_text().splitlines():
        if not line:
            continue
        digest, size, _source, name = line.split("|")
        records[name] = (digest, size)
    return records


def sized_fixture(size: int, seed: bytes) -> bytes:
    return (seed * (size // len(seed) + 1))[:size]


def synthetic_lidar_payloads(
        records: dict[str, tuple[str, str]]) -> dict[str, bytes]:
    payloads = {}
    for name in LIDAR_FILES:
        digest, size = records[name]
        length = LIDAR_PER_UNIT_SIZES[name] if digest == "per-unit" else int(size)
        payloads[name] = sized_fixture(
            length, f"{name}:synthetic-lidar-fixture\n".encode())
    return payloads


def lidar_fixture(root: Path) -> tuple[Path, Path, dict[str, bytes]]:
    """A spec and importer copy pinned to synthetic RAM-code digests.

    The importer's RAM-code digests are compile-time constants, so the copy
    carries the fixture digests and the spec rows carry the matching hashes.
    Sizes stay those of the shipped spec, so the size pin is still exercised.
    """
    records = shipped_lidar_records()
    payloads = synthetic_lidar_payloads(records)
    spec_dir = root / "specs"
    spec_dir.mkdir()
    rows = []
    for name in LIDAR_FILES:
        digest, _size = records[name]
        source = f"system/vendor/firmware/{name}"
        if digest == "per-unit":
            rows.append(f"per-unit|-|{source}|{name}\n")
            continue
        payload = payloads[name]
        rows.append(f"{hashlib.sha256(payload).hexdigest()}|{len(payload)}|"
                    f"{source}|{name}\n")
    (spec_dir / (LIDAR_BUNDLE_ID + ".tsv")).write_text("".join(rows))

    script = IMPORTER.read_text()
    for name, (hash_constant, size_constant) in LIDAR_HASH_CONSTANTS.items():
        digest, size = records[name]
        payload = payloads[name]
        script = script.replace(f"{hash_constant}={digest}",
                                f"{hash_constant}={hashlib.sha256(payload).hexdigest()}")
        script = script.replace(f"{size_constant}={size}",
                                f"{size_constant}={len(payload)}")
    importer = root / "libreecho-vendor-import"
    importer.write_text(script)
    importer.chmod(0o755)
    return importer, spec_dir, payloads


class VendorImporterCompatTests(unittest.TestCase):
    def run_importer(
        self,
        root: Path,
        source: Path,
        *,
        spec_dir: Path = SHIPPED_SPEC_DIR,
        force: bool = False,
        target: str | None = None,
        firmware_seed: dict[str, bytes] | None = None,
        importer: Path = IMPORTER,
    ) -> tuple[subprocess.CompletedProcess[str], Path, Path]:
        data = root / "data"
        config = data / "libreecho/config"
        firmware = root / "runtime-firmware"
        config.mkdir(parents=True, exist_ok=True)
        firmware.mkdir(parents=True, exist_ok=True)
        for name, payload in (firmware_seed or {}).items():
            (firmware / name).write_bytes(payload)
        force_marker = config / "vendor-import-force-next-boot"
        if force:
            force_marker.write_text("force-unverified-owner-local-import-v1\n")
            force_marker.chmod(0o600)
        target_file = root / "target"
        if target is not None:
            target_file.write_text(f"target_id={target}\n")
        environment = {
            **os.environ,
            "LIBREECHO_VENDOR_TEST_MODE": "1",
            "LIBREECHO_VENDOR_TARGET_FILE": str(target_file),
            "DATA_ROOT": str(data),
            "LIBREECHO_VENDOR_SOURCE_ROOT": str(source),
            "LIBREECHO_VENDOR_FIRMWARE_ROOT": str(firmware),
            "LIBREECHO_VENDOR_SPEC_DIR": str(spec_dir),
            "LIBREECHO_VENDOR_STAGE_PARENT": str(root / "vendor-stage"),
            "LIBREECHO_VENDOR_STATUS_PATH": str(root / "run/libreecho/vendor-import.status"),
        }
        result = subprocess.run(
            ["/bin/sh", str(importer)],
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=15,
        )
        return result, config / "vendor-assets.tsv", Path(environment["LIBREECHO_VENDOR_STATUS_PATH"])

    def test_lidar_rejects_a_ram_code_set_outside_the_pin(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "system-a"
            write_payloads(source, {
                "WIFI_RAM_CODE_MT7668.bin": b"not-the-pinned-ram-code",
                "WIFI_RAM_CODE2_SDIO_MT7668.bin": b"not-the-pinned-cr4-code",
                "EEPROM_MT7668.bin": bytes(1024),
                "TxPwrLimit_MT76x8.dat": b"calibration\n",
                "wifi.cfg": b"ssid=test\n",
            })
            # Lidar has no force path: even a force marker must not bless an
            # unrecognised RAM-code pair.
            result, enrolled, status = self.run_importer(
                root, source, target="lidar", force=True)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn("VENDOR_IMPORT_LIDAR_SET_INVALID", result.stderr)
            self.assertNotIn("VENDOR_IMPORT_LIDAR_INSTALLED", result.stdout)
            self.assertEqual(status.read_text(),
                             "state=failed\nverification=none\n"
                             "source_partition=system_a\nsource_layout=none\n"
                             "force_requested=0\n"
                             "error=VENDOR_IMPORT_LIDAR_SET_INVALID\n")
            self.assertFalse(enrolled.exists())
            self.assertEqual(list((root / "runtime-firmware").iterdir()), [])

    def test_lidar_pinned_set_imports_runtime_files_and_keeps_the_patch(self) -> None:
        patch = b"image-owned-mt7668-patch\n"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "system-a"
            importer, spec_dir, payloads = lidar_fixture(root)
            write_payloads(source, payloads)
            result, enrolled, status = self.run_importer(
                root, source, target="lidar", spec_dir=spec_dir,
                importer=importer,
                firmware_seed={"mt7668_patch_e2_hdr.bin": patch})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("VENDOR_IMPORT_LIDAR_INSTALLED "
                          "verification=lidar-hash-pinned-ram-per-unit-calibration "
                          "source_layout=system/vendor/firmware\n", result.stdout)
            self.assertEqual(status.read_text(),
                             "state=imported\n"
                             "verification=lidar-hash-pinned-ram-per-unit-calibration\n"
                             "source_partition=system_a\n"
                             "source_layout=system/vendor/firmware\n"
                             "force_requested=0\nerror=none\n")
            # The importer never enrols a Lidar set.
            self.assertFalse(enrolled.exists())
            runtime = root / "runtime-firmware"
            for name, payload in payloads.items():
                target = runtime / name
                self.assertEqual(target.read_bytes(), payload)
                self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            self.assertEqual((runtime / "mt7668_patch_e2_hdr.bin").read_bytes(),
                             patch)
            self.assertFalse((runtime / "WIFI_RAM_CODE").exists())

    def test_lidar_replaces_per_unit_calibration_on_every_boot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "system-a"
            importer, spec_dir, payloads = lidar_fixture(root)
            write_payloads(source, payloads)
            self.run_importer(root, source, target="lidar", spec_dir=spec_dir,
                              importer=importer)
            # Re-provisioned unit: only the calibration changed.
            (source / "system/vendor/firmware/EEPROM_MT7668.bin").write_bytes(
                bytes([0x5a]) * 1024)
            shutil.rmtree(root / "runtime-firmware")
            shutil.rmtree(root / "run")
            result, _, _ = self.run_importer(root, source, target="lidar",
                                            spec_dir=spec_dir,
                                            importer=importer)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                (root / "runtime-firmware/EEPROM_MT7668.bin").read_bytes(),
                bytes([0x5a]) * 1024)

    def test_shipped_lidar_spec_pins_match_the_importer_constants(self) -> None:
        script = IMPORTER.read_text()
        records = shipped_lidar_records()
        self.assertEqual(set(records), set(LIDAR_FILES))
        for name, (hash_constant, size_constant) in LIDAR_HASH_CONSTANTS.items():
            digest, size = records[name]
            self.assertIn(f"{hash_constant}={digest}", script)
            self.assertIn(f"{size_constant}={size}", script)

    def test_second_validated_revision_is_shipped_as_one_atomic_manifest(self) -> None:
        self.assertEqual(
            V2_SPEC.read_text(),
            "".join(
                (
                    "b4460117f51a43f3284594ec08d8c8861ecc0e42b17820987da03ecabdebac1e|128720|etc/firmware/ROMv2_lm_patch_1_0_hdr.bin|ROMv2_lm_patch_1_0_hdr.bin\n",
                    "10c4ed22a10b8a136bffd7ffce4d552300d76f8e593627d2a9841c3b11a5697e|50148|etc/firmware/ROMv2_lm_patch_1_1_hdr.bin|ROMv2_lm_patch_1_1_hdr.bin\n",
                    "9669cc9b03cfdc5e8fd4fd6e14c4c4050e8c196738ca4707eea12f14a6a8e64c|373840|etc/firmware/WIFI_RAM_CODE_8163|WIFI_RAM_CODE_8163\n",
                    "302bd4462de99c028c04092e561c1500d65582ce42a93c4c72ccae6e2c99013d|119|etc/firmware/WMT_SOC.cfg|WMT_SOC.cfg\n",
                )
            ),
        )

    def test_forced_unknown_set_enrols_hashes_then_verifies_without_force(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "system-a"
            payloads = unknown_payloads()
            write_payloads(source, payloads)

            first, enrolled, status = self.run_importer(root, source, force=True)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertIn("verification=forced-unverified\n", status.read_text())
            self.assertTrue(enrolled.is_file())
            self.assertFalse(enrolled.is_symlink())
            self.assertEqual(stat.S_IMODE(enrolled.stat().st_mode), 0o600)
            self.assertEqual(enrolled.read_text(), manifest_lines(payloads))
            self.assertNotIn(b"unknown-owner-local-wifi-code", enrolled.read_bytes())

            # A cold boot discards all runtime bytes and status. Only the
            # persisted hash/size contract may authorise the second import.
            self.assertFalse(enrolled.with_name("vendor-import-force-next-boot").exists())
            self.assertEqual(sorted(p.name for p in enrolled.parent.iterdir()), ["vendor-assets.tsv"])
            self.assertFalse((root / "vendor-stage").exists())
            shutil.rmtree(root / "runtime-firmware")
            shutil.rmtree(root / "run")
            second, enrolled_again, status_again = self.run_importer(root, source)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(enrolled_again.read_text(), manifest_lines(payloads))
            self.assertIn("verification=owner-local-enrolled\n", status_again.read_text())
            self.assertFalse(enrolled.with_name("vendor-import-force-next-boot").exists())
            for name, payload in payloads.items():
                self.assertEqual((root / "runtime-firmware" / name).read_bytes(), payload)
            self.assertEqual((root / "runtime-firmware/WIFI_RAM_CODE").read_bytes(), payloads["WIFI_RAM_CODE_8163"])

    def test_changed_enrolled_set_is_reimported_and_reenrolled(self) -> None:
        """An owner who updates their stock ROM keeps Wi-Fi: the new set is used."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "system-a"
            payloads = unknown_payloads()
            layout = write_payloads(source, payloads)
            first, enrolled, _ = self.run_importer(root, source, force=True)
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertTrue(enrolled.exists())

            (layout / "WIFI_RAM_CODE_8163").write_bytes(b"changed-after-enrolment")
            payloads["WIFI_RAM_CODE_8163"] = b"changed-after-enrolment"
            shutil.rmtree(root / "runtime-firmware")  # a cold boot starts from RAM
            shutil.rmtree(root / "run")
            second, enrolled_again, status = self.run_importer(root, source)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertIn("verification=forced-unverified\n", status.read_text())
            self.assertEqual(enrolled_again.read_text(), manifest_lines(payloads))

    def test_rows_from_different_approved_revisions_are_never_mixed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "system-a"
            spec_dir = root / "specs"
            spec_dir.mkdir()
            revision_one = {
                name: f"revision-one-{name}".encode() for name in TARGETS
            }
            revision_two = {
                name: f"revision-two-{name}".encode() for name in TARGETS
            }
            (spec_dir / "mt8163-v181-stock-v1.tsv").write_text(manifest_lines(revision_one))
            (spec_dir / "mt8163-v181-stock-v2.tsv").write_text(manifest_lines(revision_two))
            mixed = {
                TARGETS[0]: revision_one[TARGETS[0]],
                TARGETS[1]: revision_one[TARGETS[1]],
                TARGETS[2]: revision_two[TARGETS[2]],
                TARGETS[3]: revision_two[TARGETS[3]],
            }
            write_payloads(source, mixed)

            result, _, status = self.run_importer(root, source, spec_dir=spec_dir)
            self.assertEqual(result.returncode, 2)
            self.assertIn("VENDOR_IMPORT_NO_HASH_PINNED_SET", result.stderr)
            self.assertIn("error=VENDOR_IMPORT_NO_HASH_PINNED_SET\n", status.read_text())

    def test_safe_structurally_compatible_unknown_set_is_imported(self) -> None:
        """An uncatalogued stock revision is the owner's firmware: import it."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "system-a"
            source.mkdir()
            outside = root / "outside-firmware"
            outside.mkdir()
            (source / "vendor").mkdir()
            (source / "vendor/firmware").symlink_to(outside, target_is_directory=True)
            write_payloads(source, unknown_payloads())

            result, enrolled, status = self.run_importer(root, source)
            self.assertEqual(result.returncode, 0, result.stderr)
            status_text = status.read_text()
            self.assertIn("verification=forced-unverified\n", status_text)
            self.assertIn("source_layout=system/vendor/firmware\n", status_text)
            self.assertTrue(enrolled.exists(), "the imported set is enrolled for later boots")

    def test_malformed_unknown_set_is_not_offerable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "system-a"
            payloads = unknown_payloads()
            payloads["ROMv2_lm_patch_1_0_hdr.bin"] = patch_payload(b"broken", 0x31)
            write_payloads(source, payloads)

            result, _, status = self.run_importer(root, source)
            self.assertEqual(result.returncode, 2)
            self.assertNotIn("VENDOR_IMPORT_UNKNOWN_COMPATIBLE_SET", result.stderr)
            self.assertIn("VENDOR_IMPORT_NO_HASH_PINNED_SET", result.stderr)
            self.assertIn("error=VENDOR_IMPORT_NO_HASH_PINNED_SET\n", status.read_text())


    def test_damaged_enrolment_copy_is_rejected_before_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "system-a"
            write_payloads(source, unknown_payloads())
            bindir = root / "bin"
            bindir.mkdir()
            # Corrupt only the enrolled manifest copy, preserving its schema.
            # Schema validation alone must not bless different trust records.
            copier = bindir / "cp"
            copier.write_text(
                "#!/bin/sh\n"
                "/bin/cp \"$@\" || exit $?\n"
                "case \"$2\" in\n"
                "  */.vendor-assets.tsv.enrol.*)\n"
                "    sed '1s/^[^|]*/" + "0" * 64 + "/' \"$2\" > \"$2.damage\"\n"
                "    mv \"$2.damage\" \"$2\"\n"
                "    chmod 0600 \"$2\"\n"
                "    ;;\n"
                "esac\n"
            )
            copier.chmod(0o755)
            with mock.patch.dict(os.environ, {"PATH": f"{bindir}:{os.environ['PATH']}"}):
                result, enrolled, status = self.run_importer(root, source, force=True)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn("VENDOR_IMPORT_ENROLLED_SPEC_COPY_MISMATCH", result.stderr)
            self.assertFalse(enrolled.exists())
            self.assertIn("state=failed\n", status.read_text())
            self.assertEqual(list(enrolled.parent.iterdir()), [])

    def test_image_builder_pins_the_current_importer(self) -> None:
        expected = hashlib.sha256(IMPORTER.read_bytes()).hexdigest()
        self.assertIn(
            f'CONNECTIVITY_IMPORTER_SHA256 = "{expected}"',
            (TOOLS_DIR / "build_recovery_image.py").read_text(),
        )


if __name__ == "__main__":
    unittest.main()
