#!/usr/bin/env python3
"""Host-only tests for the Lidar preparation command and its mtkclient adapter.

The command is exercised through ``main`` with an in-memory fake adapter, so no
test opens USB or runs mtkclient.  The adapter's own command construction is
checked with a recording runner and a throwaway checkout.
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent / "install"))

import lidar_backup_set as backup  # noqa: E402
import lidar_prepare as prepare  # noqa: E402
import mtk_adapter  # noqa: E402

# Live GPT offsets (lab-notes/phase-01/brom-printgpt.log:123-142, in the
# libreecho-lidar-port archive).
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


class FakeMtk:
    """In-memory device with the fake-adapter seam the command uses."""

    dry_run = False

    def __init__(self, *, hwcode: int = 0x8167, flash_bytes: int = backup.FLASH_BYTES,
                 boot_area_bytes: int = backup.BOOT_AREA_BYTES, gpt=None):
        self.identity_value = mtk_adapter.Identity(
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
        self.writes.append(("absolute", area.name, offset, len(data)))
        target = self.areas[area.name]
        target[relative:relative + len(data)] = data
        if area.name == "expdb" and self.bad_expdb_after_write:
            self._expdb_reads_pending = 2

    def write_partition(self, name: str, data: bytes):
        self.writes.append(("partition", name, 0, len(data)))
        self.areas[name] = bytearray(data)

    def write_boot_area1(self, offset: int, data: bytes):
        self.writes.append(("boot1", "boot0", offset, len(data)))
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
        self.fake = FakeMtk()
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
        checkout = self.root / "mtkclient"
        (checkout / ".venv" / "bin").mkdir(parents=True)
        (checkout / "mtk.py").write_text("")
        (checkout / ".venv" / "bin" / "python").symlink_to(sys.executable)
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
        self.fake.identity_value = mtk_adapter.Identity(
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
        self.fake.identity_value = mtk_adapter.Identity(
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
        self.fake.identity_value = mtk_adapter.Identity(
            0x8163, backup.FLASH_BYTES, backup.BOOT_AREA_BYTES, 512)
        code, _out, err = self.drill(directory, self.root / "drill.json")
        self.assertEqual(code, 2)
        self.assertIn("not an Echo Plus 2nd Gen", err)
        self.assertEqual(self.fake.writes, [])

    def test_dry_run_prints_the_same_expdb_write_as_the_real_loop(self):
        adapter = mtk_adapter.MtkClient(
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
        self.assertIn("wo 0xf00000 0xa00000", printed)
        self.assertIn("w tee1", printed)
        self.assertNotIn("w expdb", printed)


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
        checkout = self.root / "mtkclient"
        (checkout / ".venv" / "bin").mkdir(parents=True)
        (checkout / "mtk.py").write_text("")
        (checkout / ".venv" / "bin" / "python").symlink_to(sys.executable)
        session = self.root / "dry-session"
        args = self.run_args(session)
        args.insert(0, str(checkout))
        args.insert(0, "--mtkclient")
        args.insert(args.index("run"), "--dry-run")
        code, out, err = quiet_main(args, fastboot_runner=self.fastboot())
        self.assertEqual(code, 0, err)
        self.assertIn("DRY-RUN mtkclient: ", out)
        self.assertIn("DRY-RUN install: ", out)
        self.assertIn("DRY-RUN fastboot: fastboot getvar product", out)
        self.assertFalse((session / "backup").exists())
        self.assertEqual(self.fake.writes, [])


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / ".venv" / "bin").mkdir(parents=True)
        (self.root / ".venv" / "bin" / "python").symlink_to(sys.executable)
        (self.root / "mtk.py").write_text("")

    def test_identity_parses_printgpt(self):
        def runner(cmd, **kwargs):
            return subprocess.CompletedProcess(
                cmd, 0,
                "Preloader - HW code:\t\t\t0x8167\n"
                "DAXFlash - EMMC Boot1 Size: 0x200000\n"
                "DAXFlash - EMMC USER Size:  0x1c8000000\n", "")
        adapter = mtk_adapter.MtkClient(self.root, runner=runner)
        self.assertEqual(adapter.identity(),
                         mtk_adapter.Identity(0x8167, 7650410496, 0x200000, 512))

    def test_partition_read_is_partition_relative(self):
        """mtkclient writes a whole partition; no absolute-offset slicing."""
        sizes = {area.name: area.size for area in backup.BACKUP_SET}

        def fill(size: int, seed: int) -> bytes:
            return bytes((index * 17 + seed) & 0xFF for index in range(size))

        def runner(cmd, **kwargs):
            target = next(Path(part) for part in cmd if part.endswith("read.bin"))
            name = cmd[3]
            target.write_bytes(fill(sizes[name], len(name)))
            return subprocess.CompletedProcess(cmd, 0, "", "")

        adapter = mtk_adapter.MtkClient(self.root, runner=runner)
        for name in ("lk_a", "boot0"):
            self.assertEqual(adapter.read_area(backup.BY_NAME[name]),
                             fill(sizes[name], len(name)))

    def test_short_partition_read_is_refused(self):
        def runner(cmd, **kwargs):
            target = next(Path(part) for part in cmd if part.endswith("read.bin"))
            target.write_bytes(b"\0" * (backup.BY_NAME["lk_a"].size - 512))
            return subprocess.CompletedProcess(cmd, 0, "", "")

        adapter = mtk_adapter.MtkClient(self.root, runner=runner)
        with self.assertRaises(mtk_adapter.AdapterError):
            adapter.read_area(backup.BY_NAME["lk_a"])

    def test_commands_use_the_grounded_mtkclient_syntax(self):
        commands = []

        def runner(cmd, **kwargs):
            commands.append(cmd)
            target = next(Path(part) for part in cmd
                          if part.endswith(("read.bin", "write.bin")))
            size = int(cmd[4], 16) if cmd[2] in ("ro", "wo") else 0x200000
            target.write_bytes(b"\0" * size)
            return subprocess.CompletedProcess(cmd, 0, "", "")

        adapter = mtk_adapter.MtkClient(self.root, runner=runner)
        adapter.read_area(backup.BY_NAME["boot0"])
        adapter.read_area(backup.BY_NAME["gpt_backup"])
        adapter.write_partition("tee1", b"\0" * 512)
        adapter.write_boot_area1(0x200, b"\0" * 512)
        rendered = [
            " ".join(
                "<file>" if str(part).endswith(("read.bin", "write.bin"))
                else Path(part).name if i == 0 else part
                for i, part in enumerate(cmd))
            for cmd in commands]
        self.assertTrue(rendered[0].endswith("r boot0 <file> --parttype boot1"))
        self.assertIn("ro 0x1c7ffbe00 0x4200", rendered[1])
        self.assertTrue(rendered[2].endswith("w tee1 <file>"))
        self.assertTrue(rendered[3].endswith(
            "wo 0x200 0x200 <file> --parttype boot1"))

    def test_boot_area_2_is_never_writable(self):
        adapter = mtk_adapter.MtkClient(self.root, runner=lambda *a, **k: None)
        with self.assertRaises(mtk_adapter.AdapterWriteRefused):
            adapter._write_command(
                ["python", "mtk.py", "wo", "0x0", "0x200", "<file>",
                 "--parttype", "boot2"], b"\0" * 512, "boot area 2")

    def test_dry_run_never_runs_the_runner(self):
        def runner(cmd, **kwargs):
            raise AssertionError("dry run executed a command")

        adapter = mtk_adapter.MtkClient(self.root, runner=runner, dry_run=True)
        self.assertIsNone(adapter.identity())
        self.assertIsNone(adapter.read_area(backup.BY_NAME["expdb"]))
        adapter.write_absolute(backup.BY_NAME["expdb"].offset, b"\0" * 512)


if __name__ == "__main__":
    unittest.main()
