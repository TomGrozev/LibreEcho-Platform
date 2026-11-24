#!/usr/bin/env python3
"""Reviewed preparation command for the Echo Plus 2nd Gen (Lidar, MT8167).

This is the reviewed replacement for the hand-run BROM session described in
the public lab notes (``lab-notes/phase-07/prep-command.md`` in the
libreecho-lidar-port repository).  It has one subcommand per stage and ``run``
chains them:

    identify   BROM identity is MT8167 and the GPT is the Lidar geometry
    backup     read the backup set, write it with a manifest, verify a second read
    drill      the same-byte restore drill
    stock-boot the operator confirms the stock device still boots
    install    write the owner-access chain (preloader, Kaeru, Koboreru)
    confirm    Kaeru fastboot reports product LIDAR

Every failure closes the run: no later stage starts and no further write is
issued.  Each stage appends JSON lines to one log.  ``--dry-run`` prints every
device command instead of running it.

Evidence this file leans on:

* Backup set, sizes and offsets: ``install/lidar_backup_set.py``; the sources
  are the stock dump and the live BROM reads
  (``lab-notes/phase-01/notes.md``).
* Drill areas and order: ``lab-notes/phase-03/notes.md`` (gpt, gpt_backup,
  expdb, tee1, boot0; boot1 is never written).
* Stock-boot gate: ``lab-notes/phase-03/notes.md``.
* Chain layout and order: ``lab-notes/phase-03/notes.md``
  (expdb -> tee1 -> BOOT0 area 1, sector 0 last).
* expdb generation: ``install/expdb_guard.py`` and Platform ``AGENTS.md``.
* Lidar identity and partition sizes: ``libreecho_platform_targets.py``;
  the installer's product check is ``install/lidar_install.py``.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import struct
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
INSTALL_DIR = HERE.parent / "install"
sys.path.insert(0, str(INSTALL_DIR))
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

import lidar_backup_set as backup  # noqa: E402
import lidar_donor_artifacts as donor  # noqa: E402
import libreecho_platform_targets as targets  # noqa: E402
from expdb_guard import (  # noqa: E402
    MTK_IMAGE_MAGIC,
    FASTBOOT_PLEASE,
    ExpdbGenerationError,
    check_expdb_prefix,
)
from host_io import (  # noqa: E402
    sha256_bytes,
    sha256_file,
    utc_stamp,
    write_bytes_atomic,
)
from mtk_adapter import (  # noqa: E402
    AdapterError,
    AdapterWriteRefused,
    Identity,
    MtkClient,
)

SCHEMA_BACKUP = backup.SCHEMA
SCHEMA_DRILL = "libreecho-lidar-drill-v1"
SCHEMA_STOCK_BOOT = "libreecho-lidar-stock-boot-v1"

# The same-byte drill order proven on the unit (drill.json:13-79 and
# phase-03/notes.md:54-111): boot0 is last and its sector 0 is written after
# its body.  boot1 is verified and never written.
DRILL_ORDER = ("gpt", "gpt_backup", "expdb", "tee1", "boot0")
NEVER_WRITE = frozenset({"boot1"})
# expdb is written exactly twice by design: the same-byte drill and the one
# Kaeru stage install.  Every other expdb write is refused.
EXPDB = "expdb"
KAERU_STAGE_BYTES = 0x40000
STOCK_BOOT_TOKEN = "stock-boot-ok"
# The reviewed signed preloader pin and magic live in the donor generator now;
# the install stage hands the pin to it and consumes the generated files.
REVIEWED_PRELOADER_SHA256 = donor.REVIEWED_PRELOADER_SHA256
PRELOADER_MAGIC = donor.PRELOADER_MAGIC
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class PrepareError(RuntimeError):
    """The stage failed; later stages do not run."""


class Refusal(PrepareError):
    """The request is unsafe; nothing further was written."""


# --------------------------------------------------------------------- utils
def write_json_atomic(path: Path, value) -> None:
    write_bytes_atomic(path, (json.dumps(value, indent=2, sort_keys=True) + "\n").encode())


class JsonlLog:
    """Append-only JSON-lines log.  One open per event, never truncated."""

    def __init__(self, path: Path, *, dry_run: bool) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.dry_run = dry_run

    def event(self, stage: str, action: str, **fields) -> None:
        record = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "dry_run": self.dry_run,
            "stage": stage,
            "action": action,
            **fields,
        }
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, sort_keys=True) + "\n")


def require_writable(name: str, *, same_byte_drill: bool = False,
                     chain_install: bool = False) -> None:
    """The one write policy, shared by every stage and unit test."""
    if name == "boot1":
        raise Refusal(
            "BOOT1 (eMMC boot area 2) is the identity store and is never written; "
            "the full-4-MiB fallback needs separate approval")
    if name == EXPDB:
        if same_byte_drill:
            return
        if chain_install:
            return
        raise Refusal(
            "expdb is never written outside the same-byte drill and the one Kaeru "
            "stage install; never erase it or write FASTBOOT_PLEASE to it")


# ---------------------------------------------------------------------- gpt
def _gpt_header(block: bytes, where: str) -> dict:
    if len(block) < 512:
        raise Refusal(f"{where}: GPT header is {len(block)} bytes, expected 512")
    if block[:8] != b"EFI PART":
        raise Refusal(f"{where}: no EFI PART signature")
    header_size = struct.unpack_from("<I", block, 12)[0]
    if header_size < 92 or header_size > 512:
        raise Refusal(f"{where}: GPT header size {header_size} is not 92..512")
    my_lba, alternate_lba, first_usable, last_usable = struct.unpack_from(
        "<QQQQ", block, 24)
    entry_lba, entry_count, entry_size = struct.unpack_from("<QII", block, 72)
    if entry_size < 128 or entry_size % 8:
        raise Refusal(f"{where}: GPT entry size {entry_size} is not valid")
    if not 0 < entry_count <= 1024:
        raise Refusal(f"{where}: GPT entry count {entry_count} is not valid")
    return {
        "my_lba": my_lba,
        "alternate_lba": alternate_lba,
        "first_usable": first_usable,
        "last_usable": last_usable,
        "entry_lba": entry_lba,
        "entry_count": entry_count,
        "entry_size": entry_size,
    }


def parse_gpt(primary: bytes, backup_data: bytes) -> dict[str, tuple[int, int]]:
    """Parse the Lidar GPT and require the backup table to agree.

    Returns ``name -> (absolute offset, bytes)`` for the used entries.
    """
    header = _gpt_header(primary[512:1024], "primary GPT")
    entries_bytes = header["entry_count"] * header["entry_size"]
    start = header["entry_lba"] * 512
    entries = primary[start:start + entries_bytes]
    if len(entries) != entries_bytes:
        raise Refusal("primary GPT is shorter than its entry array")

    backup_entries = backup_data[:entries_bytes]
    if len(backup_entries) != entries_bytes:
        raise Refusal("backup GPT is shorter than its entry array")
    if backup_entries != entries:
        raise Refusal("backup GPT entries differ from the primary entries")
    backup_header = _gpt_header(backup_data[entries_bytes:entries_bytes + 512],
                                "backup GPT")
    if backup_header["my_lba"] != header["alternate_lba"]:
        raise Refusal("backup GPT my_lba disagrees with the primary alternate_lba")
    if backup_header["alternate_lba"] != 1:
        raise Refusal("backup GPT alternate_lba is not the primary header LBA 1")
    if backup_header["last_usable"] != header["last_usable"]:
        raise Refusal("backup GPT last_usable differs from the primary")
    if header["my_lba"] != 1:
        raise Refusal("primary GPT my_lba is not 1")

    geometry: dict[str, tuple[int, int]] = {}
    for index in range(header["entry_count"]):
        entry = entries[index * header["entry_size"]:(index + 1) * header["entry_size"]]
        if entry[:16] == b"\0" * 16:
            continue
        first_lba, last_lba = struct.unpack_from("<QQ", entry, 32)
        if last_lba < first_lba:
            raise Refusal(f"GPT entry {index}: last LBA precedes first LBA")
        name = entry[56:128].decode("utf-16-le", errors="replace").rstrip("\0")
        if not name:
            raise Refusal(f"GPT entry {index}: empty partition name")
        if name in geometry:
            raise Refusal(f"GPT repeats partition name {name!r}")
        geometry[name] = (first_lba * 512, (last_lba - first_lba + 1) * 512)
    return geometry


def check_geometry(identity: Identity, geometry: dict[str, tuple[int, int]]) -> None:
    """Require the measured BROM identity and GPT to be the Lidar geometry."""
    if identity.hwcode != 0x8167:
        raise Refusal(
            f"BROM reports hwcode 0x{identity.hwcode:x}, expected 0x8167; this is "
            "not an Echo Plus 2nd Gen (Lidar)")
    if identity.flash_bytes != backup.FLASH_BYTES:
        raise Refusal(
            f"eMMC user area is {identity.flash_bytes} bytes, expected "
            f"{backup.FLASH_BYTES} (brom-printgpt.log:113)")
    if identity.boot_area_bytes != backup.BOOT_AREA_BYTES:
        raise Refusal(
            f"eMMC boot area is {identity.boot_area_bytes} bytes, expected "
            f"{backup.BOOT_AREA_BYTES} (brom-printgpt.log:106)")
    if identity.sector_bytes != backup.SECTOR_BYTES:
        raise Refusal("eMMC logical sector size is not 512")

    target = targets.get_target("lidar")
    if target["storage_sector_size"] != backup.SECTOR_BYTES:
        raise Refusal("target table sector size disagrees with the Lidar GPT")
    for _index, name, sectors in target["partitions"]:
        if name not in geometry:
            raise Refusal(f"GPT has no partition {name!r} that the Lidar target requires")
        expected = sectors * backup.SECTOR_BYTES
        if geometry[name][1] != expected:
            raise Refusal(
                f"GPT partition {name!r} is {geometry[name][1]} bytes, expected {expected}")

    for area in backup.BACKUP_SET:
        if area.kind != "user":
            continue
        if area.name not in geometry:
            raise Refusal(f"GPT has no partition {area.name!r} in the backup set")
        offset, size = geometry[area.name]
        if size != area.size:
            raise Refusal(
                f"GPT {area.name!r} is {size} bytes, backup set expects {area.size}")
        if offset != area.offset:
            raise Refusal(
                f"GPT {area.name!r} starts at 0x{offset:x}, backup set expects "
                f"0x{area.offset:x}; this is not the reviewed Lidar layout")
    last = geometry["userdata"][0] + geometry["userdata"][1]
    if last > identity.flash_bytes:
        raise Refusal("GPT userdata extends past the eMMC user area")


# ------------------------------------------------------------------ stages
def _measure_identity(adapter) -> dict | None:
    """Read the hwcode and both GPTs and require the Lidar geometry."""
    identity = adapter.identity()
    if adapter.dry_run:
        adapter.read_area(backup.BY_NAME["gpt"])
        adapter.read_area(backup.BY_NAME["gpt_backup"])
        return None
    gpt = adapter.read_area(backup.BY_NAME["gpt"])
    gpt_backup = adapter.read_area(backup.BY_NAME["gpt_backup"])
    if gpt is None or gpt_backup is None:
        raise PrepareError("GPT reads returned no data")
    geometry = parse_gpt(gpt, gpt_backup)
    check_geometry(identity, geometry)
    return {"identity": identity, "geometry": geometry}


def _recheck_identity(adapter, log: JsonlLog, stage: str) -> dict | None:
    """A write stage gates itself, so a standalone stage cannot write blind."""
    result = _measure_identity(adapter)
    if result is not None:
        log.event(stage, "identity-ok", hwcode=f"0x{result['identity'].hwcode:x}",
                  partitions=len(result["geometry"]))
    return result


def stage_identify(adapter, log: JsonlLog) -> dict | None:
    result = _measure_identity(adapter)
    if result is None:
        log.event("identify", "planned", check="hwcode/GPT geometry")
        return None
    identity = result["identity"]
    log.event(
        "identify", "ok", hwcode=f"0x{identity.hwcode:x}",
        flash_bytes=identity.flash_bytes, boot_area_bytes=identity.boot_area_bytes,
        partitions=len(result["geometry"]))
    return result


def _load_verified_backup(backup_dir: Path, manifest_path: Path) -> dict[str, dict]:
    try:
        files = backup.load_manifest(manifest_path)
        backup.require_complete_backup(backup_dir, files)
    except backup.BackupSetError as error:
        raise Refusal(f"no usable verified backup: {error}") from error
    return files


def _backup_contents(backup_dir: Path, files: dict[str, dict]) -> dict[str, bytes]:
    return {name: (backup_dir / record["file"]).read_bytes()
            for name, record in files.items()}


def stage_backup(adapter, log: JsonlLog, backup_dir: Path,
                 manifest_path: Path) -> Path:
    if manifest_path.exists():
        raise Refusal(f"{manifest_path} already exists; a backup is never overwritten")
    if not adapter.dry_run:
        backup_dir.mkdir(parents=True, exist_ok=True)
        for area in backup.BACKUP_SET:
            if (backup_dir / f"{area.name}.bin").exists():
                raise Refusal(
                    f"{backup_dir / (area.name + '.bin')} exists; use a new backup directory")

    records: dict[str, dict] = {}
    for area in backup.BACKUP_SET:
        path = backup_dir / f"{area.name}.bin"
        if adapter.dry_run:
            adapter.read_area(area)
            print(f"DRY-RUN backup: write {path} and record its sha256")
            adapter.read_area(area)
            print(f"DRY-RUN backup: require the second read to hash to the first")
            continue
        first = adapter.read_area(area)
        if first is None or len(first) != area.size:
            raise PrepareError(f"backup read of {area.name!r} was short")
        write_bytes_atomic(path, first)
        second = adapter.read_area(area)
        if second is None or sha256_bytes(first) != sha256_bytes(second):
            raise Refusal(
                f"{area.name}: a fresh second readback does not hash to the first "
                "read; the backup is not trustworthy")
        records[area.name] = {
            "file": path.name,
            "size": area.size,
            "sha256": sha256_bytes(first),
        }
        log.event("backup", "wrote", area=area.name, bytes=area.size,
                  sha256=records[area.name]["sha256"])
    if adapter.dry_run:
        print(f"DRY-RUN backup: write manifest {manifest_path}")
        return manifest_path

    manifest = {
        "schema": SCHEMA_BACKUP,
        "device": {
            "hwcode": "0x8167",
            "flash_bytes": backup.FLASH_BYTES,
            "boot_area_bytes": backup.BOOT_AREA_BYTES,
        },
        "files": records,
    }
    write_json_atomic(manifest_path, manifest)
    try:
        backup.require_complete_backup(backup_dir, manifest_path)
    except backup.BackupSetError as error:
        raise Refusal(f"the written backup does not verify: {error}") from error
    digest = sha256_file(manifest_path)
    log.event("backup", "manifest", path=str(manifest_path), sha256=digest)
    return manifest_path


def _expect(data: bytes | None, expected: bytes, what: str) -> bytes:
    if data is None:
        raise PrepareError(f"{what}: read returned no data")
    if data != expected:
        raise Refusal(f"{what}: readback does not match the verified backup")
    return data


def stage_drill(adapter, log: JsonlLog, backup_dir: Path, manifest_path: Path,
                report_path: Path) -> None:
    _recheck_identity(adapter, log, "drill")
    if adapter.dry_run:
        for name in DRILL_ORDER:
            area = backup.BY_NAME[name]
            adapter.read_area(area)
            if name == "boot0":
                adapter.write_boot_area1(backup.SECTOR_BYTES,
                                         bytes(area.size - backup.SECTOR_BYTES))
                adapter.read_area(area)
                adapter.write_boot_area1(0, bytes(backup.SECTOR_BYTES))
            elif name == "tee1":
                adapter.write_partition("tee1", bytes(area.size))
            else:
                adapter.write_absolute(area.offset, bytes(area.size))
            adapter.read_area(area)
            print(f"DRY-RUN drill: {name} is rewritten with the backup bytes and read back")
        adapter.read_area(backup.BY_NAME["boot1"])
        print("DRY-RUN drill: verify boot1 only; never write it")
        print(f"DRY-RUN drill: write report {report_path}")
        return

    files = _load_verified_backup(backup_dir, manifest_path)
    contents = _backup_contents(backup_dir, files)

    current_boot1 = adapter.read_area(backup.BY_NAME["boot1"])
    _expect(current_boot1, contents["boot1"], "drill boot1 (never_write)")

    for name in DRILL_ORDER:
        expected = contents[name]
        area = backup.BY_NAME[name]
        current = adapter.read_area(area)
        _expect(current, expected, f"drill pre-check {name}")
        if name == "boot0":
            require_writable(name, same_byte_drill=True)
            adapter.write_boot_area1(backup.SECTOR_BYTES, expected[backup.SECTOR_BYTES:])
            _expect(adapter.read_area(area)[backup.SECTOR_BYTES:],
                    expected[backup.SECTOR_BYTES:], "drill boot0 body")
            adapter.write_boot_area1(0, expected[:backup.SECTOR_BYTES])
            _expect(adapter.read_area(area), expected, "drill boot0 sector 0 last")
        elif name == "tee1":
            require_writable(name, same_byte_drill=True)
            adapter.write_partition("tee1", expected)
            _expect(adapter.read_area(area), expected, "drill tee1")
        else:
            require_writable(name, same_byte_drill=True)
            adapter.write_absolute(area.offset, expected)
            _expect(adapter.read_area(area), expected, f"drill {name}")
        log.event("drill", "wrote", area=name, bytes=len(expected), same_byte=True)

    _expect(adapter.read_area(backup.BY_NAME["boot1"]), contents["boot1"],
            "drill boot1 after the drill")
    report = {
        "schema": SCHEMA_DRILL,
        "ok": True,
        "manifest_sha256": sha256_file(manifest_path),
        "areas": list(DRILL_ORDER),
        "boot1": "verified-unchanged",
    }
    write_json_atomic(report_path, report)
    log.event("drill", "ok", report=str(report_path), areas=list(DRILL_ORDER))


def stage_stock_boot(log: JsonlLog, report_path: Path, *, dry_run: bool,
                     confirmed: bool, prompt=input) -> None:
    print("Stock-boot check (lab-notes/phase-03/notes.md):")
    print("  1. Power the unit off and remove power.")
    print("  2. Apply power without USB and watch for a normal stock startup.")
    print("  3. Remove power again, then hold the Action button and apply power")
    print("     to re-enter BROM for the install stage.")
    if dry_run:
        print(f"DRY-RUN stock-boot: require the operator token {STOCK_BOOT_TOKEN!r} "
              f"and write {report_path}")
        log.event("stock-boot", "planned", token=STOCK_BOOT_TOKEN)
        return
    if not confirmed:
        answer = prompt(f"Type {STOCK_BOOT_TOKEN!r} after the stock unit started "
                        "normally: ").strip()
        if answer != STOCK_BOOT_TOKEN:
            raise Refusal("stock boot was not confirmed; no chain write is authorized")
    report = {"schema": SCHEMA_STOCK_BOOT, "ok": True, "confirmed_at": utc_stamp()}
    write_json_atomic(report_path, report)
    log.event("stock-boot", "ok", report=str(report_path))


def _check_report(path: Path, schema: str, *, dry_run: bool, what: str) -> dict:
    if not path.is_file():
        if dry_run:
            print(f"DRY-RUN {what}: report {path} is produced by an earlier stage of a real run")
            return {}
        raise Refusal(f"{what}: report {path} is missing; run the earlier stage first")
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise Refusal(f"{what}: cannot read {path}: {error}") from error
    if value.get("schema") != schema or value.get("ok") is not True:
        raise Refusal(f"{what}: {path} does not record a passing stage")
    return value


def _check_input(path: Path, expected_sha256: str, label: str, *,
                 exactly: int | None = None, maximum: int | None = None,
                 magic: bytes | None = None) -> bytes:
    if not path.is_file():
        raise Refusal(f"{label}: {path} does not exist")
    if not HEX64.fullmatch(expected_sha256 or ""):
        raise Refusal(f"{label}: --{label}-sha256 must be a 64-character lowercase hex")
    data = path.read_bytes()
    if exactly is not None and len(data) != exactly:
        raise Refusal(f"{label}: {path} is {len(data)} bytes, expected {exactly}")
    if maximum is not None and len(data) > maximum:
        raise Refusal(f"{label}: {path} is {len(data)} bytes, more than the {maximum} allowed")
    if magic is not None and not data.startswith(magic):
        raise Refusal(f"{label}: {path} does not start with {magic!r}")
    actual = sha256_bytes(data)
    if actual != expected_sha256:
        raise Refusal(
            f"{label}: {path} is {actual}, pinned digest is {expected_sha256}")
    return data


def stage_install(adapter, log: JsonlLog, backup_dir: Path, manifest_path: Path,
                  drill_report: Path, stock_report: Path, *,
                  kaeru_path: Path, kaeru_sha256: str,
                  koboreru_path: Path, koboreru_sha256: str,
                  donor_dir: Path) -> None:
    dry = adapter.dry_run
    kaeru = _check_input(kaeru_path, kaeru_sha256, "kaeru", maximum=KAERU_STAGE_BYTES)
    if len(kaeru) < 16 or kaeru[:4] != MTK_IMAGE_MAGIC or kaeru[8:11] != b"LK\0":
        raise Refusal("Kaeru input is not an MTK LK image")
    koboreru = _check_input(koboreru_path, koboreru_sha256, "koboreru",
                            maximum=backup.BY_NAME["tee1"].size)
    if len(koboreru) < 16 or koboreru[:4] != MTK_IMAGE_MAGIC or koboreru[8:11] != b"atf":
        raise Refusal("Koboreru input is not an MTK ATF/TEE image")

    _recheck_identity(adapter, log, "install")

    if dry:
        if not manifest_path.is_file():
            print(f"DRY-RUN install: {manifest_path} is produced by the backup stage")
        else:
            _load_verified_backup(backup_dir, manifest_path)
        print(f"DRY-RUN install: donor artifacts would be generated under {donor_dir}")
        tee1_stage = b"\0" * backup.BY_NAME["tee1"].size
        preloader = b"\0" * backup.BOOT_AREA_BYTES
    else:
        _load_verified_backup(backup_dir, manifest_path)
        try:
            donor_manifest = donor.generate(
                backup_dir, manifest_path, donor_dir,
                koboreru=koboreru, koboreru_sha256=koboreru_sha256,
                preloader_sha256=REVIEWED_PRELOADER_SHA256)
            tee1_stage = donor.load_artifact(
                donor_dir, donor_manifest, "tee1-stage.bin")
            preloader = donor.load_artifact(
                donor_dir, donor_manifest, "boot0-preloader.bin")
        except donor.Refusal as error:
            raise Refusal(str(error)) from error
    drill = _check_report(drill_report, SCHEMA_DRILL, dry_run=dry, what="install drill gate")
    _check_report(stock_report, SCHEMA_STOCK_BOOT, dry_run=dry, what="install stock-boot gate")
    if drill and not dry and drill.get("manifest_sha256") != sha256_file(manifest_path):
        raise Refusal("the drill report was produced from a different backup manifest")

    expdb_stage = kaeru + b"\0" * (KAERU_STAGE_BYTES - len(kaeru))
    preloader_body = preloader[backup.SECTOR_BYTES:]
    preloader_sector0 = preloader[:backup.SECTOR_BYTES]

    if dry:
        print(f"DRY-RUN install: pre-read expdb[0:16] and refuse an installed v2 chain")
        adapter.write_absolute(backup.BY_NAME["expdb"].offset, expdb_stage)
        adapter.read_absolute(backup.BY_NAME["expdb"].offset, len(expdb_stage))
        print("DRY-RUN install: read expdb[0:16] back and call check_expdb_prefix; "
              "refuse before any later write on a bad magic")
        adapter.read_absolute(backup.BY_NAME["expdb"].offset, 16)
        adapter.write_partition("tee1", tee1_stage)
        adapter.read_area(backup.BY_NAME["tee1"])
        adapter.write_boot_area1(backup.SECTOR_BYTES, preloader_body)
        adapter.read_area(backup.BY_NAME["boot0"])
        adapter.write_boot_area1(0, preloader_sector0)
        adapter.read_area(backup.BY_NAME["boot0"])
        adapter.read_area(backup.BY_NAME["boot1"])
        print("DRY-RUN install: verify boot1 is unchanged; it is never written")
        log.event("install", "planned", expdb_sha256=sha256_bytes(expdb_stage),
                  tee1_sha256=sha256_bytes(tee1_stage))
        return

    boot1_before = adapter.read_area(backup.BY_NAME["boot1"])
    if boot1_before is None:
        raise PrepareError("cannot read BOOT1 before the install")
    expdb_offset = backup.BY_NAME["expdb"].offset
    current = adapter.read_absolute(expdb_offset, len(expdb_stage))
    if current is None:
        raise PrepareError("cannot read the current expdb stage")
    if current == expdb_stage:
        log.event("install", "expdb-already-installed", area="expdb",
                  sha256=sha256_bytes(expdb_stage))
    else:
        if current[:4] == MTK_IMAGE_MAGIC:
            raise Refusal(
                "expdb already holds a v2 Kaeru LK stage whose bytes differ from the "
                "expected stage; never rewrite expdb after installation")
        if current.startswith(FASTBOOT_PLEASE):
            raise Refusal(
                "expdb begins with FASTBOOT_PLEASE: the chain is already broken; "
                "refusing to write flash")

        require_writable(EXPDB, chain_install=True)
        adapter.write_absolute(expdb_offset, expdb_stage)
        _expect(adapter.read_absolute(expdb_offset, len(expdb_stage)),
                expdb_stage, "install expdb Kaeru stage")
        fresh = adapter.read_absolute(expdb_offset, 16)
        try:
            generation = check_expdb_prefix(fresh)
        except ExpdbGenerationError as error:
            raise Refusal(f"install expdb generation check failed: {error}") from error
        log.event("install", "wrote", area="expdb", bytes=len(expdb_stage),
                  generation=generation, sha256=sha256_bytes(expdb_stage))

    require_writable("tee1", chain_install=True)
    adapter.write_partition("tee1", tee1_stage)
    _expect(adapter.read_area(backup.BY_NAME["tee1"]), tee1_stage, "install tee1")
    log.event("install", "wrote", area="tee1", bytes=len(tee1_stage),
              sha256=sha256_bytes(tee1_stage))

    adapter.write_boot_area1(backup.SECTOR_BYTES, preloader_body)
    _expect(adapter.read_area(backup.BY_NAME["boot0"])[backup.SECTOR_BYTES:],
            preloader_body, "install boot0 body")
    adapter.write_boot_area1(0, preloader_sector0)
    _expect(adapter.read_area(backup.BY_NAME["boot0"]), preloader, "install boot0 sector 0 last")
    log.event("install", "wrote", area="boot0", offset=0, bytes=len(preloader),
              sha256=sha256_bytes(preloader), sector0_last=True)

    boot1_after = adapter.read_area(backup.BY_NAME["boot1"])
    if boot1_after != boot1_before:
        raise Refusal(
            "BOOT1 changed during the install; it is never written, so stop and inspect")
    log.event("install", "ok", boot1="unchanged")


def stage_confirm(fastboot: str, log: JsonlLog, *, dry_run: bool,
                  runner=None) -> None:
    products = targets.get_target("lidar")["fastboot_products"]
    expected = products[0]
    cmd = [fastboot, "getvar", "product"]
    if dry_run:
        print(f"DRY-RUN fastboot: {' '.join(cmd)}  # require product: {expected}")
        log.event("confirm", "planned", expected=expected)
        return
    run = runner or subprocess.run
    try:
        proc = run(cmd, capture_output=True, text=True, timeout=30)
    except OSError as error:
        raise PrepareError(f"cannot run {fastboot}: {error}") from error
    except subprocess.TimeoutExpired as error:
        raise PrepareError("fastboot getvar product timed out") from error
    output = (proc.stdout or "") + (proc.stderr or "")
    match = re.search(r"product:\s*([A-Za-z0-9_-]+)\b", output, re.IGNORECASE)
    if match is None:
        raise Refusal(
            f"fastboot did not report a product (exit {proc.returncode}); retry before "
            "any identity decision")
    product = match.group(1).upper()
    if product != expected:
        raise Refusal(f"fastboot reports product {product!r}, expected {expected!r}; "
                      "this is not a Lidar Kaeru")
    log.event("confirm", "ok", product=product)


# --------------------------------------------------------------------- run
def stage_run(adapter, log: JsonlLog, session: Path, *, args,
              fastboot_runner=None, prompt=input) -> None:
    backup_dir = Path(args.backup_dir) if args.backup_dir else session / "backup"
    manifest_path = backup_dir / "backup-manifest.json"
    drill_report = session / "drill-report.json"
    stock_report = session / "stock-boot-report.json"

    stage_identify(adapter, log)
    stage_backup(adapter, log, backup_dir, manifest_path)
    stage_drill(adapter, log, backup_dir, manifest_path, drill_report)
    stage_stock_boot(log, stock_report, dry_run=adapter.dry_run,
                     confirmed=args.stock_boot_ok, prompt=prompt)
    stage_install(
        adapter, log, backup_dir, manifest_path, drill_report, stock_report,
        kaeru_path=Path(args.kaeru), kaeru_sha256=args.kaeru_sha256,
        koboreru_path=Path(args.koboreru), koboreru_sha256=args.koboreru_sha256,
        donor_dir=session / "donor-artifacts")
    stage_confirm(args.fastboot, log, dry_run=adapter.dry_run, runner=fastboot_runner)


# --------------------------------------------------------------------- cli
def add_chain_inputs(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--kaeru", required=True, type=Path,
                        help="source-built Kaeru LK image")
    parser.add_argument("--kaeru-sha256", required=True)
    parser.add_argument("--koboreru", required=True, type=Path,
                        help="source-built Koboreru TEE image")
    parser.add_argument("--koboreru-sha256", required=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Prepare a stock Lidar for the LibreEcho installer over BROM.")
    parser.add_argument("--mtkclient", type=Path,
                        help="mtkclient checkout (required here or in the "
                             "MTKCLIENT environment variable)")
    parser.add_argument("--mtkclient-python", type=Path,
                        help="python for mtkclient (default: <checkout>/.venv/bin/python)")
    parser.add_argument("--workdir", type=Path,
                        help="mtkclient session directory (default: ./lidar-prepare-work)")
    parser.add_argument("--log", type=Path, help="JSON-lines log path")
    parser.add_argument("--dry-run", action="store_true",
                        help="print every device operation without running it")
    parser.add_argument("--fastboot", default="fastboot",
                        help="fastboot executable (default: fastboot on PATH)")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("identify", help="check BROM hwcode and the Lidar GPT geometry")

    backup_cmd = sub.add_parser("backup", help="read the boot-chain backup set")
    backup_cmd.add_argument("--backup-dir", required=True, type=Path)

    drill = sub.add_parser("drill", help="same-byte restore drill over the boot-chain areas")
    drill.add_argument("--backup-dir", required=True, type=Path)
    drill.add_argument("--report", type=Path)
    drill.add_argument("--yes", action="store_true", help="confirm the same-byte writes")

    stock = sub.add_parser("stock-boot", help="record the operator's stock-boot check")
    stock.add_argument("--report", required=True, type=Path)
    stock.add_argument("--confirmed", action="store_true")

    install = sub.add_parser("install", help="write the owner-access chain")
    install.add_argument("--backup-dir", required=True, type=Path)
    install.add_argument("--drill-report", required=True, type=Path)
    install.add_argument("--stock-boot-report", required=True, type=Path)
    add_chain_inputs(install)
    install.add_argument("--donor-dir", type=Path,
                         help="generated donor artifact directory "
                              "(default: <backup-dir>/../donor-artifacts)")
    install.add_argument("--yes", action="store_true", help="confirm the chain writes")

    sub.add_parser("confirm", help="require Kaeru fastboot to report product LIDAR")

    run = sub.add_parser("run", help="chain identify, backup, drill, install and confirm")
    run.add_argument("--session-dir", required=True, type=Path)
    run.add_argument("--backup-dir", type=Path)
    add_chain_inputs(run)
    run.add_argument("--stock-boot-ok", action="store_true",
                     help="the operator already confirmed the stock boot")
    run.add_argument("--yes", action="store_true", help="confirm every write")
    return parser


def _default_log(args) -> Path:
    if args.log:
        return args.log
    if args.command == "run":
        return Path(args.session_dir) / "prepare.jsonl"
    return Path("lidar-prepare-logs") / f"prepare-{utc_stamp()}.jsonl"


def _make_adapter(args):
    root = args.mtkclient or os.environ.get("MTKCLIENT")
    if not root:
        raise PrepareError(
            "no mtkclient checkout: pass --mtkclient or set MTKCLIENT")
    workdir = args.workdir or (Path(args.session_dir) / "mtk-work"
                               if getattr(args, "session_dir", None)
                               else Path("lidar-prepare-work"))
    return MtkClient(root, python_executable=args.mtkclient_python,
                     workdir=workdir, dry_run=args.dry_run)


def main(argv: list[str] | None = None, *, adapter_factory=None,
         fastboot_runner=None, prompt=input) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    log = JsonlLog(_default_log(args), dry_run=args.dry_run)
    log.event("cli", "start", command=args.command,
              argv=list(sys.argv[1:] if argv is None else argv))
    try:
        if args.command == "stock-boot":
            stage_stock_boot(log, args.report, dry_run=args.dry_run,
                             confirmed=args.confirmed, prompt=prompt)
        elif args.command == "confirm":
            stage_confirm(args.fastboot, log, dry_run=args.dry_run,
                          runner=fastboot_runner)
        else:
            factory = adapter_factory or _make_adapter
            adapter = factory(args)
            if args.command == "identify":
                stage_identify(adapter, log)
            elif args.command == "backup":
                stage_backup(adapter, log, args.backup_dir,
                             args.backup_dir / "backup-manifest.json")
            elif args.command == "drill":
                if not args.yes and not args.dry_run:
                    raise Refusal("the drill writes same-byte data; pass --yes after approval")
                report = args.report or args.backup_dir / "drill-report.json"
                stage_drill(adapter, log, args.backup_dir,
                            args.backup_dir / "backup-manifest.json", report)
            elif args.command == "install":
                if not args.yes and not args.dry_run:
                    raise Refusal("the install writes the chain; pass --yes after approval")
                stage_install(
                    adapter, log, args.backup_dir,
                    args.backup_dir / "backup-manifest.json",
                    args.drill_report, args.stock_boot_report,
                    kaeru_path=args.kaeru, kaeru_sha256=args.kaeru_sha256,
                    koboreru_path=args.koboreru,
                    koboreru_sha256=args.koboreru_sha256,
                    donor_dir=args.donor_dir or (
                        args.backup_dir.parent / "donor-artifacts"))
            elif args.command == "run":
                if not args.yes and not args.dry_run:
                    raise Refusal("the run writes flash; pass --yes after approval")
                stage_run(adapter, log, args.session_dir, args=args,
                          fastboot_runner=fastboot_runner, prompt=prompt)
        log.event("cli", "ok", command=args.command)
        return 0
    except Refusal as error:
        log.event("cli", "refused", command=args.command, error=str(error))
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    except (PrepareError, AdapterError, AdapterWriteRefused,
            backup.BackupSetError, ExpdbGenerationError) as error:
        log.event("cli", "failed", command=args.command, error=str(error))
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    finally:
        print(f"log: {log.path}")


if __name__ == "__main__":
    sys.exit(main())
