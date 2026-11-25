#!/usr/bin/env python3
"""Host-only tests for the Lidar preparation command and its Amonet adapter.

The command is exercised through ``main`` with an in-memory fake adapter.  No
test opens USB; the real adapter runs only against the Amonet simulated BROM,
and those cases skip when the sibling checkout or the reviewed backup is
absent.  The adapter's own command construction is checked with a recording
runner and a throwaway checkout.
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent / "install"))

import amonet_adapter  # noqa: E402
import lidar_backup_set as backup  # noqa: E402
import lidar_prepare as prepare  # noqa: E402

# The real adapter runs against the sibling Amonet fork and a reviewed Lidar
# readback.  CI without them skips those cases.  The Amonet checkout may be
# named by AMONET; the backup directory must be named by LIDAR_BACKUP_DIR
# because the reviewed dump is private evidence and has no in-tree default.
PLATFORM_ROOT = HERE.parents[2]
AMONET_CHECKOUT = Path(os.environ.get("AMONET")
                       or PLATFORM_ROOT.parent / "amonet")
LIDAR_BACKUP_DIR = os.environ.get("LIDAR_BACKUP_DIR")
LIDAR_SIM = Path(LIDAR_BACKUP_DIR) if LIDAR_BACKUP_DIR else None
REVIEWED_DIGESTS = {
    "boot0": "d5fc0bbbc89b7dfaa7ca39fc1d0bc8da0df4a66e2324f3a9742ba70c04f5e327",
    "boot1": "4c8e02060ab820652000e4ffae90c5554d88230625edc704d269bee3efeb80f3",
    "expdb": "e5b844cc57f57094ea4585e235f36c78c1cd222262bb89d53c94dcb4d6b3e55d",
    "gpt": "7668e74b33f37cc06e73c99c9226d8b7f8f6259f2a7e4678378bf7e40196b682",
    "gpt_backup": "07fda82bd175d93cacfd32e0c2f15ce141688856deffa9e67131cba721f0945c",
    "tee1": "aa2b92914cf3dc8dcfebc958b99d752cb98bb20a79bf48570639587c838ad75e",
}


def _skip(reason: str) -> None:
    print(f"SKIP: {reason}", file=sys.stderr)
    raise unittest.SkipTest(reason)


def require_simulator() -> None:
    if not (AMONET_CHECKOUT / "modules" / "lidar_brom.py").is_file():
        _skip(f"amonet checkout not present at {AMONET_CHECKOUT}")
    if LIDAR_SIM is None:
        _skip("LIDAR_BACKUP_DIR is not set; name the reviewed Lidar backup to "
              "run the real-adapter simulator cases")
    if not LIDAR_SIM.is_dir():
        _skip(f"reviewed Lidar backup not present at {LIDAR_SIM}")


# Live GPT offsets.
OFFSETS = {
    "kb": 0x100000, "dkb": 0x200000, "lk_a": 0x300000, "tee1": 0x400000,
    "lk_b": 0x900000, "tee2": 0xA00000, "expdb": 0xF00000, "misc": 0x1900000,
    "persist": 0x1980000, "boot_a": 0x2980000, "boot_b": 0x3980000,
    "swdl": 0x4980000, "system_a": 0x6980000, "system_b": 0x53180000,
    "cache": 0x9F980000, "userdata": 0xA1980000,
}
SIZES = {name: sectors * 512 for _index, name, sectors in
         prepare.targets.get_target("lidar")["partitions"]}
TOTAL_SECTORS = backup.FLASH_BYTES // 512
BACKUP_LAST_LBA = backup.GPT_BACKUP_OFFSET // 512 + 32  # header LBA


def gpt_entries() -> bytes:
    entries = bytearray(128 * 128)
    for index, (_number, name, _sectors) in enumerate(
            prepare.targets.get_target("lidar")["partitions"]):
        first = OFFSETS[name] // 512
        last = first + SIZES[name] // 512 - 1
        entry = bytearray(128)
        entry[0:16] = bytes([index + 1]) * 16
        struct.pack_into("<QQ", entry, 32, first, last)
        entry[56:56 + len(name) * 2] = name.encode("utf-16-le")
        entries[index * 128:(index + 1) * 128] = entry
    return bytes(entries)


def gpt_header(my_lba: int, alternate_lba: int, entries_lba: int) -> bytes:
    block = bytearray(512)
    block[0:8] = b"EFI PART"
    struct.pack_into("<I", block, 8, 0x00010000)
    struct.pack_into("<I", block, 12, 92)
    struct.pack_into("<QQQQ", block, 24, my_lba, alternate_lba, 34,
                     TOTAL_SECTORS - 34)
    struct.pack_into("<QII", block, 72, entries_lba, 128, 128)
    return bytes(block)


def make_gpt() -> tuple[bytes, bytes]:
    entries = gpt_entries()
    primary = bytes(512) + gpt_header(1, BACKUP_LAST_LBA, 2) + entries
    primary = primary.ljust(0x16000, b"\0")
    backup_data = entries + gpt_header(BACKUP_LAST_LBA, 1, BACKUP_LAST_LBA - 32)
    return primary, backup_data


def deterministic(name: str, size: int, prefix: bytes = b"") -> bytes:
    body = (prefix + name.encode() + b":") if prefix else b""
    return (body + bytes((index * 31 + len(name)) & 0xFF
                         for index in range(size)))[:size].ljust(size, b"\0")


class FakeDevice:
    """In-memory device with the fake-adapter seam the command uses."""

    dry_run = False

    def __init__(self, *, hwcode: int = 0x8167, flash_bytes: int = backup.FLASH_BYTES,
                 boot_area_bytes: int = backup.BOOT_AREA_BYTES, gpt=None):
        self.identity_value = amonet_adapter.Identity(
            hwcode, flash_bytes, boot_area_bytes, 512)
        self.areas = {
            "boot0": bytearray(deterministic("boot0", backup.BOOT_AREA_BYTES,
                                             prepare.PRELOADER_MAGIC)),
            "boot1": bytearray(deterministic("boot1", backup.BOOT_AREA_BYTES,
                                             b"EMMC_BOOT")),
            "expdb": bytearray(backup.BY_NAME["expdb"].size),
            "tee1": bytearray(
                prepare.MTK_IMAGE_MAGIC + b"\0\0\0\0atf\0"
                + deterministic("tee1", backup.BY_NAME["tee1"].size)[12:]),
            "misc": bytearray(backup.BY_NAME["misc"].size),
            "persist": bytearray(backup.BY_NAME["persist"].size),
            "lk_a": bytearray(deterministic("lk_a", backup.BY_NAME["lk_a"].size)),
            "lk_b": bytearray(deterministic("lk_b", backup.BY_NAME["lk_b"].size)),
            "tee2": bytearray(deterministic("tee2", backup.BY_NAME["tee2"].size)),
        }
        primary, backup_gpt = make_gpt() if gpt is None else gpt
        self.areas["gpt"] = bytearray(primary)
        self.areas["gpt_backup"] = bytearray(backup_gpt)
        self.writes: list[tuple] = []
        self.reads = 0
        self.corrupt_readback: set[str] = set()
        self.bad_expdb_after_write = False
        self._expdb_reads_pending = 0

    def identity(self):
        return self.identity_value

    def _area(self, area):
        return self.areas[area.name]

    def read_area(self, area):
        self.reads += 1
        data = bytes(self._area(area)[:area.size])
        if area.name in self.corrupt_readback:
            self.corrupt_readback.discard(area.name)
            return bytes([data[0] ^ 0xFF]) + data[1:]
        return data

    def _absolute(self, offset: int):
        for area in backup.BACKUP_SET:
            if area.kind == "user" and area.name != "gpt":
                if offset >= area.offset and offset < area.offset + area.size:
                    return area, offset - area.offset
        if offset < 0x16000:
            return backup.BY_NAME["gpt"], offset
        if backup.GPT_BACKUP_OFFSET <= offset < backup.GPT_BACKUP_OFFSET + 0x4200:
            return backup.BY_NAME["gpt_backup"], offset - backup.GPT_BACKUP_OFFSET
        raise AssertionError(f"fake device has no area at 0x{offset:x}")

    def read_absolute(self, offset: int, length: int):
        self.reads += 1
        area, relative = self._absolute(offset)
        data = bytes(self.areas[area.name][relative:relative + length])
        if area.name == "expdb" and self._expdb_reads_pending > 0:
            self._expdb_reads_pending -= 1
            if self._expdb_reads_pending == 0:
                return prepare.FASTBOOT_PLEASE + bytes(length - len(prepare.FASTBOOT_PLEASE))
        return data

    def write_absolute(self, offset: int, data: bytes):
        area, relative = self._absolute(offset)
        self.writes.append(("absolute", area.name, offset, len(data),
                            hashlib.sha256(data).hexdigest()))
        target = self.areas[area.name]
        target[relative:relative + len(data)] = data
        if area.name == "expdb" and self.bad_expdb_after_write:
            self._expdb_reads_pending = 2

    def write_partition(self, name: str, data: bytes):
        self.writes.append(("partition", name, 0, len(data),
                            hashlib.sha256(data).hexdigest()))
        self.areas[name] = bytearray(data)

    def write_boot_area1(self, offset: int, data: bytes):
        self.writes.append(("boot1", "boot0", offset, len(data),
                            hashlib.sha256(data).hexdigest()))
        self.areas["boot0"][offset:offset + len(data)] = data


class DryAdapter:
    """Dry-run seam: records nothing and returns no device data."""

    dry_run = True

    def identity(self):
        return None

    def read_area(self, area):
        return None

    def read_absolute(self, offset, length):
        return None

    def write_absolute(self, offset, data):
        pass

    def write_partition(self, name, data):
        pass

    def write_boot_area1(self, offset, data):
        pass


def chain_inputs(root: Path) -> dict[str, str]:
    root.mkdir(parents=True, exist_ok=True)
    kaeru = prepare.MTK_IMAGE_MAGIC + b"\x00\x00\x00\x00LK\0" + b"\0" * 4084
    koboreru = prepare.MTK_IMAGE_MAGIC + b"\x00\x00\x00\x00atf\0" + b"\0" * 8188
    paths = {"kaeru": root / "kaeru.bin", "koboreru": root / "koboreru.bin"}
    for key, data in (("kaeru", kaeru), ("koboreru", koboreru)):
        paths[key].write_bytes(data)
    return {key: str(path) for key, path in paths.items()}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def quiet_main(argv, **kwargs):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = prepare.main(argv, **kwargs)
    return code, out.getvalue(), err.getvalue()


class CommandCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fake = FakeDevice()
        self.inputs = chain_inputs(self.root / "inputs")
        self.log = self.root / "log.jsonl"
        # The fake device's boot0 stands for the reviewed 2019 preloader; the
        # command's production constant is not testable against a synthetic image.
        self._reviewed_preloader = prepare.REVIEWED_PRELOADER_SHA256
        prepare.REVIEWED_PRELOADER_SHA256 = hashlib.sha256(
            bytes(self.fake.areas["boot0"])).hexdigest()
        self.addCleanup(lambda: setattr(
            prepare, "REVIEWED_PRELOADER_SHA256", self._reviewed_preloader))

    def factory(self, args):
        return self.fake

    def checkout(self):
        checkout = self.root / "amonet"
        (checkout / "modules").mkdir(parents=True)
        (checkout / "modules" / "lidar_brom.py").write_text("")
        return checkout

    def base(self, command, *extra):
        return ["--log", str(self.log), command, *extra]

    def identify(self):
        code, out, err = quiet_main(self.base("identify"), adapter_factory=self.factory)
        self.assertEqual(code, 0, err)
        return out

    def backup(self, directory=None):
        directory = Path(directory or self.root / "backup")
        code, out, err = quiet_main(
            self.base("backup", "--backup-dir", str(directory)),
            adapter_factory=self.factory)
        self.assertEqual(code, 0, err)
        return directory

    def reports(self):
        drill = self.root / "drill-report.json"
        stock = self.root / "stock-boot-report.json"
        code, _out, err = quiet_main(
            self.base("stock-boot", "--report", str(stock), "--confirmed"))
        self.assertEqual(code, 0, err)
        return drill, stock

    def drill(self, directory, report):
        args = self.base("drill", "--backup-dir", str(directory),
                         "--report", str(report), "--yes")
        return quiet_main(args, adapter_factory=self.factory)

    def install_args(self, directory, drill, stock, *extra):
        return self.base(
            "install", "--backup-dir", str(directory),
            "--drill-report", str(drill), "--stock-boot-report", str(stock),
            "--kaeru", self.inputs["kaeru"],
            "--kaeru-sha256", sha(Path(self.inputs["kaeru"])),
            "--koboreru", self.inputs["koboreru"],
            "--koboreru-sha256", sha(Path(self.inputs["koboreru"])),
            "--yes", *extra)

    def run_args(self, session, *extra):
        return ["--log", str(self.log), "run", "--session-dir", str(session),
                "--kaeru", self.inputs["kaeru"],
                "--kaeru-sha256", sha(Path(self.inputs["kaeru"])),
                "--koboreru", self.inputs["koboreru"],
                "--koboreru-sha256", sha(Path(self.inputs["koboreru"])),
                "--yes", "--stock-boot-ok", *extra]

    def fastboot(self, product="LIDAR", code=0):
        return lambda cmd, **kwargs: subprocess.CompletedProcess(
            cmd, code, f"product: {product}\n", "")

    def _move_misc_entry(self, data: bytes, base: int) -> bytes:
        changed = bytearray(data)
        struct.pack_into("<Q", changed, base + 7 * 128 + 32,
                         OFFSETS["misc"] // 512 + 8)  # misc first LBA
        return bytes(changed)

    def prepared(self):
        self.identify()
        directory = self.backup()
        _drill, stock = self.reports()
        report = self.root / "drill-report.json"
        code, _out, err = self.drill(directory, report)
        self.assertEqual(code, 0, err)
        self.fake.writes.clear()
        return directory, report, stock


class IdentifyTests(CommandCase):
    def test_happy_path_reports_the_lidar_identity(self):
        out = self.identify()
        self.assertIn("log:", out)
        events = [json.loads(line) for line in self.log.read_text().splitlines()]
        ok = [event for event in events if event["stage"] == "identify"]
        self.assertEqual(ok[-1]["action"], "ok")
        self.assertEqual(ok[-1]["hwcode"], "0x8167")

    def test_wrong_hwcode_refuses(self):
        self.fake.identity_value = amonet_adapter.Identity(
            0x8163, backup.FLASH_BYTES, backup.BOOT_AREA_BYTES, 512)
        code, _out, err = quiet_main(self.base("identify"), adapter_factory=self.factory)
        self.assertEqual(code, 2)
        self.assertIn("not an Echo Plus 2nd Gen", err)

    def test_geometry_mismatch_refuses(self):
        primary, backup_gpt = make_gpt()
        self.fake.areas["gpt"] = bytearray(self._move_misc_entry(primary, 1024))
        self.fake.areas["gpt_backup"] = bytearray(
            self._move_misc_entry(backup_gpt, 0))
        code, _out, err = quiet_main(self.base("identify"), adapter_factory=self.factory)
        self.assertEqual(code, 2)
        self.assertIn("GPT partition 'misc'", err)

    def test_primary_gpt_alone_must_agree_with_the_backup(self):
        primary, backup_gpt = make_gpt()
        self.fake.areas["gpt"] = bytearray(self._move_misc_entry(primary, 1024))
        code, _out, err = quiet_main(self.base("identify"), adapter_factory=self.factory)
        self.assertEqual(code, 2)
        self.assertIn("backup GPT entries differ", err)

    def test_backup_gpt_alone_must_agree_with_the_primary(self):
        primary, backup_gpt = make_gpt()
        self.fake.areas["gpt_backup"] = bytearray(
            self._move_misc_entry(backup_gpt, 0))
        code, _out, err = quiet_main(self.base("identify"), adapter_factory=self.factory)
        self.assertEqual(code, 2)
        self.assertIn("backup GPT entries differ", err)

    def test_wrong_flash_geometry_refuses(self):
        self.fake.identity_value = amonet_adapter.Identity(
            0x8167, backup.FLASH_BYTES + 512, backup.BOOT_AREA_BYTES, 512)
        code, _out, err = quiet_main(self.base("identify"), adapter_factory=self.factory)
        self.assertEqual(code, 2)
        self.assertIn("eMMC user area", err)


class BackupTests(CommandCase):
    def test_backup_writes_a_verified_manifest_and_second_read(self):
        directory = self.backup()
        manifest = directory / "backup-manifest.json"
        self.assertTrue(manifest.is_file())
        self.assertEqual(backup.verify_backup_set(directory, manifest), ())
        files = backup.load_manifest(manifest)
        for area in backup.BACKUP_SET:
            self.assertEqual(files[area.name]["sha256"],
                             hashlib.sha256((directory / files[area.name]["file"]).read_bytes()).hexdigest())

    def test_a_changed_second_read_refuses(self):
        original = self.fake.read_area
        calls = {"n": 0}

        def flaky(area):
            calls["n"] += 1
            data = original(area)
            if calls["n"] == 4:
                return bytes([data[0] ^ 0xFF]) + data[1:]
            return data

        self.fake.read_area = flaky
        code, _out, err = quiet_main(
            self.base("backup", "--backup-dir", str(self.root / "backup")),
            adapter_factory=self.factory)
        self.assertEqual(code, 2)
        self.assertIn("second readback", err)

    def test_backup_is_never_overwritten(self):
        directory = self.backup()
        code, _out, err = quiet_main(
            self.base("backup", "--backup-dir", str(directory)),
            adapter_factory=self.factory)
        self.assertEqual(code, 2)
        self.assertIn("already exists", err)


class DrillTests(CommandCase):
    def test_drill_writes_the_recorded_order_and_never_boot1(self):
        self.identify()
        directory = self.backup()
        report = self.root / "drill-report.json"
        code, _out, err = self.drill(directory, report)
        self.assertEqual(code, 0, err)
        self.assertTrue(json.loads(report.read_text())["ok"])
        self.assertEqual([write[1] for write in self.fake.writes],
                         ["gpt", "gpt_backup", "expdb", "tee1", "boot0", "boot0"])
        self.assertEqual(self.fake.writes[-1][2], 0)  # boot0 sector 0 last
        self.assertFalse(any(write[1] == "boot1" for write in self.fake.writes))

    def test_drill_mismatch_refuses_before_writing(self):
        self.identify()
        directory = self.backup()
        self.fake.areas["expdb"][0] ^= 0xFF
        code, _out, err = self.drill(directory, self.root / "drill.json")
        self.assertEqual(code, 2)
        self.assertIn("drill pre-check", err)
        self.assertEqual([write[1] for write in self.fake.writes],
                         ["gpt", "gpt_backup"])

    def test_drill_requires_yes(self):
        self.identify()
        directory = self.backup()
        code, _out, err = quiet_main(
            self.base("drill", "--backup-dir", str(directory)),
            adapter_factory=self.factory)
        self.assertEqual(code, 2)
        self.assertIn("--yes", err)
        self.assertEqual(self.fake.writes, [])

    def test_drill_rechecks_identity_before_writing(self):
        directory = self.backup()
        self.fake.identity_value = amonet_adapter.Identity(
            0x8163, backup.FLASH_BYTES, backup.BOOT_AREA_BYTES, 512)
        code, _out, err = self.drill(directory, self.root / "drill.json")
        self.assertEqual(code, 2)
        self.assertIn("not an Echo Plus 2nd Gen", err)
        self.assertEqual(self.fake.writes, [])

    def test_dry_run_prints_the_same_expdb_write_as_the_real_loop(self):
        adapter = amonet_adapter.AmonetClient(
            self.checkout(),
            runner=lambda *args, **kwargs: self.fail("dry run executed a command"),
            dry_run=True)
        out = io.StringIO()
        log = prepare.JsonlLog(self.root / "dry.jsonl", dry_run=True)
        with contextlib.redirect_stdout(out):
            prepare.stage_drill(
                adapter, log, self.root / "backup",
                self.root / "backup" / "backup-manifest.json",
                self.root / "drill.json")
        printed = out.getvalue()
        self.assertIn("write --offset 0xf00000 --input", printed)
        self.assertIn(f"# {backup.BY_NAME['expdb'].size} bytes", printed)
        self.assertIn("write --area tee1 --input", printed)
        self.assertNotIn("write --area expdb", printed)


class InstallTests(CommandCase):
    def test_happy_path_writes_expdb_tee1_then_boot0(self):
        directory, drill, stock = self.prepared()
        code, _out, err = quiet_main(
            self.install_args(directory, drill, stock), adapter_factory=self.factory)
        self.assertEqual(code, 0, err)
        names = [write[1] for write in self.fake.writes if write[0] != "absolute"]
        self.assertEqual(names, ["tee1", "boot0", "boot0"])
        self.assertTrue(self.fake.areas["expdb"][:4] == prepare.MTK_IMAGE_MAGIC)
        self.assertEqual(self.fake.areas["tee1"][:11],
                         prepare.MTK_IMAGE_MAGIC + b"\0\0\0\0atf")
        self.assertFalse(any(write[1] == "boot1" for write in self.fake.writes))
        events = [json.loads(line) for line in self.log.read_text().splitlines()]
        self.assertTrue(any(event.get("generation") == "kaeru-v2" for event in events))
        donor_dir = directory.parent / "donor-artifacts"
        donor_manifest = json.loads((donor_dir / "donor-artifacts.json").read_text())
        self.assertTrue(all(record["donor_derived"]
                            for record in donor_manifest["artifacts"]))
        staged = (donor_dir / "tee1-stage.bin").read_bytes()
        self.assertEqual(bytes(self.fake.areas["tee1"]), staged)
        self.assertTrue(staged.startswith(Path(self.inputs["koboreru"]).read_bytes()))

    def test_missing_backup_refuses(self):
        _drill, stock = self.reports()
        code, _out, err = quiet_main(
            self.install_args(self.root / "absent", self.root / "drill.json", stock),
            adapter_factory=self.factory)
        self.assertEqual(code, 2)
        self.assertIn("no usable verified backup", err)
        self.assertEqual(self.fake.writes, [])

    def test_corrupt_backup_refuses(self):
        directory, drill, stock = self.prepared()
        (directory / "tee1.bin").write_bytes(b"\0" * 16)
        code, _out, err = quiet_main(
            self.install_args(directory, drill, stock), adapter_factory=self.factory)
        self.assertEqual(code, 2)
        self.assertIn("no usable verified backup", err)
        self.assertEqual(self.fake.writes, [])

    def test_input_digest_mismatch_refuses(self):
        directory, drill, stock = self.prepared()
        args = self.install_args(directory, drill, stock)
        index = args.index("--kaeru-sha256") + 1
        args[index] = "0" * 64
        code, _out, err = quiet_main(args, adapter_factory=self.factory)
        self.assertEqual(code, 2)
        self.assertIn("pinned digest", err)
        self.assertEqual(self.fake.writes, [])

    def test_unreviewed_backup_preloader_refuses(self):
        directory, drill, stock = self.prepared()
        prepare.REVIEWED_PRELOADER_SHA256 = "0" * 64
        code, _out, err = quiet_main(
            self.install_args(directory, drill, stock), adapter_factory=self.factory)
        self.assertEqual(code, 2)
        self.assertIn("not the reviewed 2019 signed preloader", err)
        self.assertEqual(self.fake.writes, [])

    def test_broken_stock_expdb_refuses_before_any_write(self):
        directory, drill, stock = self.prepared()
        self.fake.areas["expdb"][:16] = prepare.FASTBOOT_PLEASE + b"\0" * 3
        code, _out, err = quiet_main(
            self.install_args(directory, drill, stock), adapter_factory=self.factory)
        self.assertEqual(code, 2)
        self.assertIn("FASTBOOT_PLEASE", err)
        self.assertEqual(self.fake.writes, [])

    def test_installed_expdb_is_never_rewritten(self):
        directory, drill, stock = self.prepared()
        self.fake.areas["expdb"][:16] = prepare.MTK_IMAGE_MAGIC + b"\0" * 12
        code, _out, err = quiet_main(
            self.install_args(directory, drill, stock), adapter_factory=self.factory)
        self.assertEqual(code, 2)
        self.assertIn("already holds a v2 Kaeru", err)
        self.assertEqual(self.fake.writes, [])

    def test_bad_expdb_magic_after_the_stage_refuses_before_later_writes(self):
        directory, drill, stock = self.prepared()
        self.fake.bad_expdb_after_write = True
        code, _out, err = quiet_main(
            self.install_args(directory, drill, stock), adapter_factory=self.factory)
        self.assertEqual(code, 2)
        self.assertIn("expdb generation check failed", err)
        self.assertEqual([write[1] for write in self.fake.writes], ["expdb"])

    def test_readback_mismatch_after_tee1_refuses(self):
        directory, drill, stock = self.prepared()
        self.fake.corrupt_readback = {"tee1"}
        code, _out, err = quiet_main(
            self.install_args(directory, drill, stock), adapter_factory=self.factory)
        self.assertEqual(code, 2)
        self.assertIn("readback does not match", err)
        self.assertNotIn("boot1", [write[1] for write in self.fake.writes])

    def test_install_requires_yes(self):
        directory, drill, stock = self.prepared()
        args = self.install_args(directory, drill, stock)
        args.remove("--yes")
        code, _out, err = quiet_main(args, adapter_factory=self.factory)
        self.assertEqual(code, 2)
        self.assertIn("--yes", err)
        self.assertEqual(self.fake.writes, [])

    def test_write_policy_refuses_expdb_and_boot1(self):
        with self.assertRaises(prepare.Refusal):
            prepare.require_writable("expdb")
        with self.assertRaises(prepare.Refusal):
            prepare.require_writable("boot1")
        prepare.require_writable("expdb", same_byte_drill=True)
        prepare.require_writable("expdb", chain_install=True)

    def test_install_rechecks_gpt_geometry_before_writing(self):
        directory, drill, stock = self.prepared()
        primary, backup_gpt = make_gpt()
        self.fake.areas["gpt"] = bytearray(self._move_misc_entry(primary, 1024))
        self.fake.areas["gpt_backup"] = bytearray(
            self._move_misc_entry(backup_gpt, 0))
        code, _out, err = quiet_main(
            self.install_args(directory, drill, stock), adapter_factory=self.factory)
        self.assertEqual(code, 2)
        self.assertIn("GPT partition 'misc'", err)
        self.assertEqual(self.fake.writes, [])

    def expected_expdb_stage(self) -> bytes:
        kaeru = Path(self.inputs["kaeru"]).read_bytes()
        return kaeru + b"\0" * (prepare.KAERU_STAGE_BYTES - len(kaeru))

    def test_resume_skips_an_identical_expdb_stage(self):
        directory, drill, stock = self.prepared()
        self.fake.areas["expdb"] = bytearray(self.expected_expdb_stage())
        code, _out, err = quiet_main(
            self.install_args(directory, drill, stock), adapter_factory=self.factory)
        self.assertEqual(code, 0, err)
        self.assertEqual([write[1] for write in self.fake.writes],
                         ["tee1", "boot0", "boot0"])
        events = [json.loads(line) for line in self.log.read_text().splitlines()]
        self.assertTrue(any(event.get("action") == "expdb-already-installed"
                            for event in events))

    def test_resume_refuses_a_different_kaeru_stage(self):
        directory, drill, stock = self.prepared()
        stage = bytearray(self.expected_expdb_stage())
        stage[-1] = 1
        self.fake.areas["expdb"] = stage
        code, _out, err = quiet_main(
            self.install_args(directory, drill, stock), adapter_factory=self.factory)
        self.assertEqual(code, 2)
        self.assertIn("already holds a v2 Kaeru", err)
        self.assertEqual(self.fake.writes, [])

    def test_dry_run_install_generates_no_donor_artifacts(self):
        directory, _drill, _stock = self.prepared()
        donor_dir = self.root / "dry-donor"
        log = prepare.JsonlLog(self.root / "dry.jsonl", dry_run=True)
        prepare.stage_install(
            DryAdapter(), log, directory, directory / "backup-manifest.json",
            self.root / "missing-drill.json", self.root / "missing-stock.json",
            kaeru_path=Path(self.inputs["kaeru"]),
            kaeru_sha256=sha(Path(self.inputs["kaeru"])),
            koboreru_path=Path(self.inputs["koboreru"]),
            koboreru_sha256=sha(Path(self.inputs["koboreru"])),
            donor_dir=donor_dir)
        self.assertFalse(donor_dir.exists())


class RunTests(CommandCase):
    def test_full_run_succeeds_in_order(self):
        session = self.root / "session"
        code, out, err = quiet_main(
            self.run_args(session), adapter_factory=self.factory,
            fastboot_runner=self.fastboot())
        self.assertEqual(code, 0, err)
        self.assertTrue((session / "backup" / "backup-manifest.json").is_file())
        self.assertTrue((session / "drill-report.json").is_file())
        self.assertTrue((session / "stock-boot-report.json").is_file())
        self.assertTrue(self.log.is_file())
        events = [json.loads(line) for line in self.log.read_text().splitlines()]
        stages = [event["stage"] for event in events
                  if event["action"] == "ok" and event["stage"] != "cli"]
        self.assertEqual(stages, ["identify", "drill", "stock-boot", "install", "confirm"])
        self.assertEqual([write[1] for write in self.fake.writes],
                         ["gpt", "gpt_backup", "expdb", "tee1", "boot0", "boot0",
                          "expdb", "tee1", "boot0", "boot0"])

    def test_wrong_product_refuses(self):
        session = self.root / "session"
        code, _out, err = quiet_main(
            self.run_args(session), adapter_factory=self.factory,
            fastboot_runner=self.fastboot("RADAR"))
        self.assertEqual(code, 2)
        self.assertIn("not a Lidar Kaeru", err)

    def test_unconfirmed_stock_boot_stops_before_install(self):
        session = self.root / "session"
        args = self.run_args(session)
        args.remove("--stock-boot-ok")
        code, _out, err = quiet_main(
            args, adapter_factory=self.factory, fastboot_runner=self.fastboot(),
            prompt=lambda _text: "no")
        self.assertEqual(code, 2)
        self.assertIn("stock boot was not confirmed", err)
        self.assertFalse(any(write[1] == "expdb" and write[0] == "absolute"
                             and write[3] == prepare.KAERU_STAGE_BYTES
                             for write in self.fake.writes))

    def test_dry_run_prints_every_device_step_and_writes_nothing(self):
        checkout = self.checkout()
        session = self.root / "dry-session"
        args = self.run_args(session)
        args.insert(0, str(checkout))
        args.insert(0, "--amonet")
        args.insert(args.index("run"), "--dry-run")
        code, out, err = quiet_main(args, fastboot_runner=self.fastboot())
        self.assertEqual(code, 0, err)
        self.assertIn("DRY-RUN amonet: ", out)
        self.assertIn("DRY-RUN install: ", out)
        self.assertIn("DRY-RUN fastboot: fastboot getvar product", out)
        self.assertFalse((session / "backup").exists())
        self.assertEqual(self.fake.writes, [])


def printed_amonet_writes(output: str) -> list[tuple[str, str, int, int, str]]:
    """Normalise the dry-run write commands to the fake adapter's tuples."""
    writes = []
    for line in output.splitlines():
        if (not line.startswith("DRY-RUN amonet: ") or " write " not in line
                or "sha256:" not in line):
            continue
        length = int(line.rsplit("#", 1)[1].split()[0])
        digest = line.rsplit("sha256:", 1)[1].strip()
        tokens = line.split()
        rest = tokens[tokens.index("write") + 1:]
        area = rest[rest.index("--area") + 1] if "--area" in rest else None
        offset = (int(rest[rest.index("--offset") + 1], 16)
                  if "--offset" in rest else 0)
        if area == "boot0":
            writes.append(("boot1", "boot0", offset, length, digest))
        elif area is not None:
            writes.append(("partition", area, offset, length, digest))
        else:
            name = next(item.name for item in backup.BACKUP_SET
                        if item.offset == offset
                        and item.kind in ("user", "gpt", "gpt_backup"))
            writes.append(("absolute", name, offset, length, digest))
    return writes


class AmonetAdapterTests(unittest.TestCase):
    """The real adapter against the Amonet simulator over the reviewed backup."""

    def setUp(self):
        require_simulator()
        self.adapter = amonet_adapter.AmonetClient(
            AMONET_CHECKOUT, simulate_dir=LIDAR_SIM)

    def test_identity_matches_the_reviewed_lidar(self):
        self.assertEqual(
            self.adapter.identity(),
            amonet_adapter.Identity(0x8167, backup.FLASH_BYTES,
                                    backup.BOOT_AREA_BYTES, 512))
        self.assertIn("--simulate", self.adapter.commands[0])

    def test_read_area_tee1_reproduces_the_reviewed_digest(self):
        data = self.adapter.read_area(backup.BY_NAME["tee1"])
        self.assertEqual(hashlib.sha256(data).hexdigest(), REVIEWED_DIGESTS["tee1"])

    def test_read_absolute_gpt_reproduces_the_reviewed_digest(self):
        data = self.adapter.read_absolute(0, backup.GPT_PRIMARY_BYTES)
        self.assertEqual(hashlib.sha256(data).hexdigest(), REVIEWED_DIGESTS["gpt"])

    def test_read_area_boot0_reproduces_the_reviewed_digest(self):
        data = self.adapter.read_area(backup.BY_NAME["boot0"])
        self.assertEqual(hashlib.sha256(data).hexdigest(), REVIEWED_DIGESTS["boot0"])


class AmonetAdapterCommandTests(unittest.TestCase):
    """Command construction and refusals, without a device or a simulator."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "modules").mkdir()
        (self.root / "modules" / "lidar_brom.py").write_text("")

    def test_missing_checkout_names_the_flag(self):
        with self.assertRaises(amonet_adapter.AdapterError) as caught:
            amonet_adapter.AmonetClient(self.root / "absent")
        self.assertIn("--amonet", str(caught.exception))
        self.assertIn("AMONET", str(caught.exception))

    def test_identity_command_carries_python_simulate_and_payload(self):
        recorded = {}

        def runner(cmd, **kwargs):
            recorded["cmd"] = cmd
            return subprocess.CompletedProcess(
                cmd, 0,
                json.dumps({"hwcode": "0x8167", "user_bytes": backup.FLASH_BYTES,
                            "boot1_bytes": backup.BOOT_AREA_BYTES,
                            "sector_bytes": 512}), "")

        adapter = amonet_adapter.AmonetClient(
            self.root, python="/usr/bin/python3", simulate_dir="/tmp/sim",
            payload="/tmp/payload.bin", runner=runner)
        self.assertEqual(adapter.identity(),
                         amonet_adapter.Identity(0x8167, backup.FLASH_BYTES,
                                                 backup.BOOT_AREA_BYTES, 512))
        cmd = recorded["cmd"]
        self.assertEqual(cmd[:2],
                         ["/usr/bin/python3", str(self.root / "modules" / "lidar_brom.py")])
        self.assertEqual(cmd[2:5], ["--simulate", "/tmp/sim", "--payload"])
        self.assertEqual(cmd[5], "/tmp/payload.bin")
        self.assertEqual(cmd[6], "identity")

    def test_commands_use_the_documented_syntax(self):
        recorded = []

        def runner(cmd, **kwargs):
            recorded.append(cmd)
            target = next((Path(part) for part in cmd if part.endswith("read.bin")),
                          None)
            if target is not None:
                if "--length" in cmd:
                    size = int(cmd[cmd.index("--length") + 1], 16)
                else:
                    size = backup.BY_NAME[cmd[cmd.index("--area") + 1]].size
                target.write_bytes(b"\0" * size)
            return subprocess.CompletedProcess(cmd, 0, "", "")

        adapter = amonet_adapter.AmonetClient(self.root, runner=runner)
        adapter.read_area(backup.BY_NAME["boot0"])
        adapter.read_area(backup.BY_NAME["gpt"])
        adapter.write_absolute(0xF00000, b"\0" * 512)
        adapter.write_partition("tee1", b"\0" * 512)
        adapter.write_boot_area1(0x200, b"\0" * 512)
        rendered = [" ".join(cmd) for cmd in recorded]
        self.assertIn("read --area boot0 --output", rendered[0])
        self.assertIn("read --offset 0x0 --length 0x16000", rendered[1])
        self.assertIn("write --offset 0xf00000 --input", rendered[2])
        self.assertTrue(rendered[2].endswith("--approve-write"))
        self.assertIn("write --area tee1 --input", rendered[3])
        self.assertTrue(rendered[3].endswith("--approve-write"))
        self.assertIn("write --area boot0 --offset 0x200", rendered[4])
        self.assertTrue(rendered[4].endswith("--approve-write"))

    def test_a_user_area_read_is_partition_relative(self):
        size = backup.BY_NAME["tee1"].size
        payload = bytes((index * 17 + 3) & 0xFF for index in range(size))

        def runner(cmd, **kwargs):
            target = next(Path(part) for part in cmd if part.endswith("read.bin"))
            target.write_bytes(payload)
            return subprocess.CompletedProcess(cmd, 0, "", "")

        adapter = amonet_adapter.AmonetClient(self.root, runner=runner)
        self.assertEqual(adapter.read_area(backup.BY_NAME["tee1"]), payload)

    def test_short_area_and_absolute_reads_are_refused(self):
        def short(cmd, **kwargs):
            target = next(Path(part) for part in cmd if part.endswith("read.bin"))
            target.write_bytes(b"\0" * (backup.BY_NAME["tee1"].size - 512))
            return subprocess.CompletedProcess(cmd, 0, "", "")

        adapter = amonet_adapter.AmonetClient(self.root, runner=short)
        with self.assertRaises(amonet_adapter.AdapterError):
            adapter.read_area(backup.BY_NAME["tee1"])
        with self.assertRaises(amonet_adapter.AdapterError):
            adapter.read_absolute(0, 0x4200)

    def test_dry_run_never_runs_the_runner(self):
        def runner(cmd, **kwargs):
            raise AssertionError("dry run executed a command")

        adapter = amonet_adapter.AmonetClient(
            self.root, runner=runner, dry_run=True)
        self.assertIsNone(adapter.identity())
        self.assertIsNone(adapter.read_area(backup.BY_NAME["expdb"]))
        self.assertIsNone(adapter.read_absolute(0, 512))
        adapter.write_absolute(backup.BY_NAME["expdb"].offset, b"\0" * 512)
        adapter.write_partition("tee1", b"\0" * 512)
        adapter.write_boot_area1(0, b"\0" * 512)

    def test_write_refusals_never_run_the_tool(self):
        adapter = amonet_adapter.AmonetClient(
            self.root, runner=lambda *args, **kwargs: self.fail("refusal ran the tool"))
        with self.assertRaisesRegex(amonet_adapter.AdapterWriteRefused,
                                    "refusing an empty write"):
            adapter.write_absolute(0, b"")
        with self.assertRaisesRegex(amonet_adapter.AdapterWriteRefused,
                                    "boot area 2 is never writable"):
            adapter.write_partition("boot1", b"\0" * 512)
        with self.assertRaisesRegex(amonet_adapter.AdapterWriteRefused,
                                    "512-byte aligned"):
            adapter.write_partition("tee1", b"\0" * 100)

    def test_a_tool_refusal_is_not_reported_as_a_failure(self):
        def refuse(cmd, **kwargs):
            return subprocess.CompletedProcess(cmd, 2, "", "refused: nope")

        with self.assertRaises(amonet_adapter.AdapterWriteRefused):
            amonet_adapter.AmonetClient(
                self.root, runner=refuse).write_partition("tee1", b"\0" * 512)

        # A refused read is a failed command, not a write refusal, and the
        # message carries the command that failed.
        with self.assertRaises(amonet_adapter.AdapterError) as caught:
            amonet_adapter.AmonetClient(self.root, runner=refuse).read_absolute(0, 512)
        self.assertIn("read --offset 0x0 --length 0x200", str(caught.exception))

        def fail(cmd, **kwargs):
            return subprocess.CompletedProcess(cmd, 1, "", "Traceback (most recent call last):")

        with self.assertRaises(amonet_adapter.AdapterError):
            amonet_adapter.AmonetClient(self.root, runner=fail).read_absolute(0, 512)


class AmonetCommandTests(CommandCase):
    """The preparation command over the real adapter and the simulated BROM."""

    def setUp(self):
        require_simulator()
        super().setUp()

    def amonet(self, *, dry_run=False):
        return amonet_adapter.AmonetClient(
            AMONET_CHECKOUT, simulate_dir=LIDAR_SIM, dry_run=dry_run)

    def run_with(self, adapter, command, *extra):
        return quiet_main(self.base(command, *extra),
                          adapter_factory=lambda args: adapter)

    def sim_backup(self):
        directory = self.root / "sim-backup"
        code, _out, err = self.run_with(
            self.amonet(), "backup", "--backup-dir", str(directory))
        self.assertEqual(code, 0, err)
        return directory

    def sim_prepared(self):
        directory = self.sim_backup()
        stock = self.root / "sim-stock.json"
        code, _out, err = quiet_main(
            self.base("stock-boot", "--report", str(stock), "--confirmed"))
        self.assertEqual(code, 0, err)
        drill = self.root / "sim-drill.json"
        code, _out, err = self.run_with(
            self.amonet(), "drill", "--backup-dir", str(directory),
            "--report", str(drill), "--yes")
        self.assertEqual(code, 0, err)
        return directory, drill, stock

    def test_identify_over_the_simulated_brom(self):
        code, _out, err = self.run_with(self.amonet(), "identify")
        self.assertEqual(code, 0, err)
        events = [json.loads(line) for line in self.log.read_text().splitlines()]
        ok = [event for event in events
              if event["stage"] == "identify" and event["action"] == "ok"]
        self.assertEqual(ok[-1]["hwcode"], "0x8167")

    def test_backup_over_the_simulated_brom_reproduces_the_reviewed_digests(self):
        directory = self.sim_backup()
        manifest = directory / "backup-manifest.json"
        self.assertEqual(backup.verify_backup_set(directory, manifest), ())
        files = backup.load_manifest(manifest)
        for name, digest in REVIEWED_DIGESTS.items():
            self.assertEqual(files[name]["sha256"], digest, name)

    def test_drill_over_the_simulated_brom_keeps_boot1(self):
        _directory, drill, _stock = self.sim_prepared()
        report = json.loads(drill.read_text())
        self.assertTrue(report["ok"])
        self.assertEqual(report["boot1"], "verified-unchanged")

    def test_install_planning_prints_the_fake_adapter_write_set(self):
        directory, drill, stock = self.prepared()
        code, _out, err = quiet_main(
            self.install_args(directory, drill, stock), adapter_factory=self.factory)
        self.assertEqual(code, 0, err)
        expected = list(self.fake.writes)
        self.assertTrue(expected)

        args = self.install_args(directory, drill, stock)
        args.insert(args.index("install"), "--dry-run")
        code, out, err = quiet_main(
            args, adapter_factory=lambda _args: self.amonet(dry_run=True))
        self.assertEqual(code, 0, err)
        planned = printed_amonet_writes(out)
        self.assertEqual(planned, expected)
        self.assertTrue(all(len(write[4]) == 64 for write in planned))

    def test_run_dry_run_prints_the_fake_adapter_write_set(self):
        code, _out, err = quiet_main(
            self.run_args(self.root / "fake-session"),
            adapter_factory=self.factory, fastboot_runner=self.fastboot())
        self.assertEqual(code, 0, err)
        expected = list(self.fake.writes)
        self.assertTrue(expected)

        session = self.root / "dry-session"
        args = self.run_args(session)
        args.insert(args.index("run"), "--dry-run")
        code, out, err = quiet_main(
            args, adapter_factory=lambda _args: self.amonet(dry_run=True),
            fastboot_runner=self.fastboot())
        self.assertEqual(code, 0, err)
        planned = printed_amonet_writes(out)
        # A run dry-run writes no backup, so its donor-derived bytes cannot
        # equal the fake run's; the area, offset and length identify the same
        # writes, and every line carries a digest.  Full digest equality is
        # asserted by the install planning test, where the backup exists.
        self.assertEqual([write[:4] for write in planned],
                         [write[:4] for write in expected])
        self.assertTrue(all(len(write[4]) == 64 for write in planned))
        self.assertTrue(any(write[:2] == ("absolute", "expdb")
                            for write in planned))
        self.assertIn("DRY-RUN amonet: ", out)
        self.assertFalse((session / "backup").exists())


class AmonetSelectionTests(CommandCase):
    def test_no_tool_named_refuses_and_names_the_flag(self):
        with mock.patch.dict(os.environ):
            os.environ.pop("AMONET", None)
            code, _out, err = quiet_main(self.base("identify"))
        self.assertEqual(code, 1)
        for token in ("--amonet", "AMONET"):
            self.assertIn(token, err)

    def test_a_named_path_without_the_tool_refuses_with_the_same_code(self):
        checkout = self.root / "empty-amonet"
        checkout.mkdir()
        args = ["--log", str(self.log), "--amonet", str(checkout), "identify"]
        code, _out, err = quiet_main(args)
        self.assertEqual(code, 1)
        self.assertIn("--amonet", err)
        self.assertIn("AMONET", err)

    def test_the_environment_names_the_checkout_too(self):
        checkout = self.root / "empty-amonet"
        checkout.mkdir()
        with mock.patch.dict(os.environ, {"AMONET": str(checkout)}):
            code, _out, err = quiet_main(self.base("identify"))
        self.assertEqual(code, 1)
        self.assertIn("--amonet", err)


if __name__ == "__main__":
    unittest.main()
