#!/usr/bin/env python3
"""The Lidar (Echo Plus 2nd Gen, MT8167) boot-chain backup set and its verifier.

This module is pure data plus host-side file checks.  It performs no USB,
fastboot or BROM operation: the reviewed preparation command that reads these
areas is out of scope, and calls the data and ``verify_backup_set`` defined
here.

The set is derived from the stock GPT and boot-chain layout, not from the
reference kit:

* GPT layout: the primary header is at offset 512 and the entry array at
  LBA 2, in a 0x1C8000000-byte (7650410496) flash.
* Boot areas 1 and 2 are each 2 MiB; the drill pins both and the restore
  manifest marks boot area 2 ``never_write``.
* The primary GPT is read as 0x16000 bytes from LBA 0 (header at offset 512,
  entries at LBA 2).
* The backup GPT is 0x4200 bytes at absolute 0x1C7FFBE00 (entries at
  LBA 0xE3FFDF through the header at LBA 0xE3FFFF).
* ``expdb`` holds the Kaeru LK stage after installation and must never be
  erased or written again (Platform ``AGENTS.md`` "Boot-chain safety").  Its
  stock contents are therefore part of the pre-install backup.
* ``persist`` is a real GPT partition at 0x1980000 and belongs to the
  pre-install backup.  This board has no ``nvram`` partition, so none is
  listed.

The set deliberately excludes ``boot_a`` and ``boot_b``: the normal installer
legitimately rewrites those slots and already hashes them back.  It also
excludes ``kb``/``dkb``/``swdl``/``system_a``/``system_b``/``cache``/
``userdata``, which are not boot-chain state.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA = "libreecho-lidar-backup-v1"
SECTOR_BYTES = 512
FLASH_BYTES = 0x1C8000000  # 7650410496 bytes
BOOT_AREA_BYTES = 0x200000  # 2 MiB per eMMC boot area
GPT_PRIMARY_BYTES = 0x16000  # header plus 32 entry sectors
GPT_BACKUP_OFFSET = 0x1C7FFBE00  # flash_bytes - 0x4200
GPT_BACKUP_BYTES = 0x4200  # 33 sectors: 32 entry sectors + header


@dataclass(frozen=True)
class BackupArea:
    """One area to read before any chain write.

    ``kind`` numbers the boot areas as the eMMC spec does: ``boot1`` is Boot
    Area Partition 1, ``boot2`` is Boot Area Partition 2, and ``user`` is a GPT
    partition.  ``name`` follows the drill manifest and the Amonet CLI, which
    call Boot Area Partition 1 ``boot0``.  ``gpt`` and ``gpt_backup`` are
    absolute user-area reads that are not GPT entries.
    """

    name: str
    kind: str
    offset: int
    size: int


# Order is the read order the preparation command should use: boot areas first,
# then the tables, then the partitions a chain write touches.  Names match the
# restore drill's manifest output names so a backup can be fed to the same
# verifier and, later, the same repair tool.
BACKUP_SET: tuple[BackupArea, ...] = (
    BackupArea("boot0", "boot1", 0, BOOT_AREA_BYTES),
    BackupArea("boot1", "boot2", 0, BOOT_AREA_BYTES),
    BackupArea("gpt", "gpt", 0, GPT_PRIMARY_BYTES),
    BackupArea("gpt_backup", "gpt_backup", GPT_BACKUP_OFFSET, GPT_BACKUP_BYTES),
    BackupArea("lk_a", "user", 0x300000, 0x100000),
    BackupArea("lk_b", "user", 0x900000, 0x100000),
    BackupArea("tee1", "user", 0x400000, 0x500000),
    BackupArea("tee2", "user", 0xA00000, 0x500000),
    BackupArea("expdb", "user", 0xF00000, 0xA00000),
    BackupArea("misc", "user", 0x1900000, 0x80000),
    BackupArea("persist", "user", 0x1980000, 0x1000000),
)

BY_NAME = {area.name: area for area in BACKUP_SET}
_HEX64_LOWER = "0123456789abcdef"


class BackupSetError(Exception):
    """A manifest is malformed or a backup is incomplete or changed."""


@dataclass(frozen=True)
class Finding:
    """One failed check.  ``problem`` is stable for tests and callers."""

    entry: str
    problem: str  # missing | size | sha256 | manifest
    detail: str

    def __str__(self) -> str:
        return f"{self.entry}: {self.problem}: {self.detail}"


def _safe_name(name: Any, where: str) -> str:
    if not isinstance(name, str) or not name or len(name) > 200:
        raise BackupSetError(f"{where}: expected a non-empty file name")
    if name in {".", ".."} or "/" in name or "\\" in name or name.startswith("."):
        raise BackupSetError(f"{where}: refusing unsafe file name {name!r}")
    return name


def _sha256_hex(value: Any, where: str) -> str:
    if (not isinstance(value, str) or len(value) != 64
            or any(character not in _HEX64_LOWER for character in value)):
        raise BackupSetError(f"{where}: expected a lowercase hex64 sha256")
    return value


def parse_manifest(value: Any) -> dict[str, dict[str, Any]]:
    """Validate the manifest shape and return its ``files`` map.

    Every backup-set entry is required.  An unknown entry is an error rather
    than an extra file, so a manifest cannot silently widen the set.
    """
    if not isinstance(value, dict):
        raise BackupSetError("manifest: expected a JSON object")
    if set(value) != {"schema", "device", "files"}:
        raise BackupSetError("manifest: expected exactly schema, device and files")
    if value["schema"] != SCHEMA:
        raise BackupSetError(f"manifest: schema must be {SCHEMA!r}")
    device = value["device"]
    if not isinstance(device, dict) or set(device) != {"hwcode", "flash_bytes", "boot_area_bytes"}:
        raise BackupSetError("manifest: device must name hwcode, flash_bytes and boot_area_bytes")
    if device["hwcode"] != "0x8167":
        raise BackupSetError("manifest: hwcode must be 0x8167")
    if device["flash_bytes"] != FLASH_BYTES or device["boot_area_bytes"] != BOOT_AREA_BYTES:
        raise BackupSetError("manifest: device geometry is not the Lidar geometry")

    files = value["files"]
    if not isinstance(files, dict):
        raise BackupSetError("manifest: files must be an object")
    unknown = set(files) - set(BY_NAME)
    if unknown:
        raise BackupSetError(f"manifest: unknown backup entries: {', '.join(sorted(unknown))}")
    missing = set(BY_NAME) - set(files)
    if missing:
        raise BackupSetError(f"manifest: missing backup entries: {', '.join(sorted(missing))}")

    parsed: dict[str, dict[str, Any]] = {}
    for name, area in ((area.name, area) for area in BACKUP_SET):
        record = files[name]
        if not isinstance(record, dict) or set(record) != {"file", "size", "sha256"}:
            raise BackupSetError(f"manifest: {name} must name file, size and sha256")
        if record["size"] != area.size:
            raise BackupSetError(
                f"manifest: {name} size {record['size']} does not match the backup set size {area.size}")
        parsed[name] = {
            "file": _safe_name(record["file"], f"manifest: {name}"),
            "size": area.size,
            "sha256": _sha256_hex(record["sha256"], f"manifest: {name}"),
        }
    return parsed


def load_manifest(path: Path | str) -> dict[str, dict[str, Any]]:
    path = Path(path)
    try:
        with path.open("r", encoding="utf-8") as stream:
            return parse_manifest(json.load(stream))
    except OSError as error:
        raise BackupSetError(f"cannot read manifest {path}: {error}") from error
    except json.JSONDecodeError as error:
        raise BackupSetError(f"manifest {path} is not JSON: {error}") from error


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_backup_set(
    backup_dir: Path | str, manifest: Path | str | dict[str, dict[str, Any]]
) -> tuple[Finding, ...]:
    """Check presence, exact size and sha256 of every backup-set file.

    ``manifest`` may be a parsed map from :func:`load_manifest` or its path.
    Returns findings in backup-set order; an empty tuple means the backup is
    complete and unchanged.  It never touches a device.
    """
    root = Path(backup_dir)
    files = load_manifest(manifest) if not isinstance(manifest, dict) else manifest
    findings: list[Finding] = []
    for area in BACKUP_SET:
        record = files[area.name]
        path = root / record["file"]
        try:
            stat = path.stat()
        except OSError:
            findings.append(Finding(area.name, "missing", f"{record['file']} is not present"))
            continue
        if not path.is_file():
            findings.append(Finding(area.name, "missing", f"{record['file']} is not a regular file"))
            continue
        if stat.st_size != record["size"]:
            findings.append(Finding(
                area.name, "size",
                f"{record['file']} is {stat.st_size} bytes; expected {record['size']}",
            ))
            continue
        actual = file_sha256(path)
        if actual != record["sha256"]:
            findings.append(Finding(
                area.name, "sha256",
                f"{record['file']} is {actual}; manifest pins {record['sha256']}",
            ))
    return tuple(findings)


def require_complete_backup(
    backup_dir: Path | str, manifest: Path | str | dict[str, dict[str, Any]]
) -> None:
    """Raise :class:`BackupSetError` unless :func:`verify_backup_set` is clean."""
    findings = verify_backup_set(backup_dir, manifest)
    if findings:
        raise BackupSetError("backup set is not usable: " + "; ".join(str(item) for item in findings))
