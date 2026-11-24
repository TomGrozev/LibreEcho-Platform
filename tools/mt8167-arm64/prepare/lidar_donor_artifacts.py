#!/usr/bin/env python3
"""Build the donor-derived Lidar chain artifacts from a verified backup.

The stock chain bytes come from the owner's own dump, so they are never
distributed: this generator writes them only under a checkout's ``private`` or
``local-firmware`` directory (or outside a checkout at all) and records every
digest in one manifest.  The release gate in the product repository refuses any
asset whose digest appears here.

Inputs:

* A backup directory plus its ``libreecho-lidar-backup-v1`` manifest.  The
  whole set must verify against its pins before a byte is written.
* Optionally the source-built Koboreru TEE image and its pinned digest.  With
  that image the generator also emits the composed ``tee1`` stage and the
  stock tail it replaces, so the preparation command consumes generator output
  instead of slicing the backup itself.

Outputs:

* ``boot0-preloader.bin``: the signed preloader from the backup's boot0 area.
* ``tee1-stock.bin``: the stock ``tee1`` partition from the backup.
* ``tee1-stock-tail.bin`` and ``tee1-stage.bin``: only with Koboreru.
* ``donor-artifacts.json``: schema, backup manifest digest, and one record per
  file with size and sha256.

No device access happens here.  Every failure leaves the manifest unwritten.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
INSTALL_DIR = HERE.parent / "install"
sys.path.insert(0, str(INSTALL_DIR))
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

import lidar_backup_set as backup  # noqa: E402
from host_io import (  # noqa: E402
    sha256_bytes,
    sha256_file,
    utc_stamp,
    write_bytes_atomic,
)

SCHEMA = "libreecho-lidar-donor-artifacts-v1"
MANIFEST_NAME = "donor-artifacts.json"
SECTOR_BYTES = backup.SECTOR_BYTES
MTK_IMAGE_MAGIC = b"\x88\x16\x88\x58"
PRELOADER_MAGIC = b"EMMC_BOOT"
STOCK_TEE_TYPE = b"atf"
# The 2019 signed preloader area 1 the Koboreru offsets were derived from
# (lab-notes/phase-03/notes.md).  A different preloader has no reviewed
# patch sites, so it needs an owner decision, not a flag.
REVIEWED_PRELOADER_SHA256 = (
    "fb987ad9cd2af5e4d86e6476f1f154e555795d915d247a23110b80ed0363de45")
LOCAL_ROOTS = frozenset({"private", "local", "local-firmware"})


class DonorArtifactError(RuntimeError):
    """The generator cannot produce a trustworthy artifact."""


class Refusal(DonorArtifactError):
    """The request is unsafe or the inputs are not what they claim."""


def require_local_output(path: Path | str) -> Path:
    """Allow donor output only inside an allowed checkout directory or outside one.

    An absolute path under a git work tree must sit below the ``private``,
    ``local`` or ``local-firmware`` directory; those are the only directories
    allowed to hold donor bytes.  A path outside every work tree (a temp
    directory, a removable volume) is accepted because it is not publishable
    through a repository.
    """
    resolved = Path(path).resolve()
    for ancestor in (resolved, *resolved.parents):
        if (ancestor / ".git").exists():
            try:
                relative = resolved.relative_to(ancestor)
            except ValueError:
                continue
            if not relative.parts or relative.parts[0] not in LOCAL_ROOTS:
                raise Refusal(
                    f"{resolved} is inside the checkout {ancestor} but not under "
                    f"{'/'.join(sorted(LOCAL_ROOTS))}; donor artifacts must stay "
                    "private")
            return resolved
    return resolved


def _read_backup_area(backup_dir: Path, files: dict[str, dict], name: str) -> bytes:
    area = backup.BY_NAME[name]
    path = backup_dir / files[name]["file"]
    try:
        data = path.read_bytes()
    except OSError as error:
        raise Refusal(f"cannot read backup {name}: {error}") from error
    if len(data) != area.size:
        raise Refusal(
            f"backup {name} is {len(data)} bytes, expected {area.size}")
    if sha256_bytes(data) != files[name]["sha256"]:
        raise Refusal(f"backup {name} changed after verification")
    return data


def _check_preloader(preloader: bytes, expected_sha256: str) -> None:
    if not preloader.startswith(PRELOADER_MAGIC):
        raise Refusal("backup boot0 does not start with the preloader magic")
    digest = sha256_bytes(preloader)
    if digest != expected_sha256:
        raise Refusal(
            f"backup boot0 is {digest}, not the reviewed 2019 signed preloader "
            f"{expected_sha256}; its layout is the only one the Koboreru patch "
            "sites were derived from (lab-notes/phase-03/notes.md). A different "
            "preloader needs an owner decision, not a flag")


def _check_stock_tee1(stock_tee1: bytes) -> None:
    if not stock_tee1.startswith(MTK_IMAGE_MAGIC):
        raise Refusal("backup tee1 does not start with the MTK image header")
    if stock_tee1[8:8 + len(STOCK_TEE_TYPE)] != STOCK_TEE_TYPE:
        raise Refusal("backup tee1 is not an MTK ATF/TEE image")


def _artifact_record(name: str, data: bytes, source: str) -> dict:
    return {
        "name": name,
        "size": len(data),
        "sha256": sha256_bytes(data),
        "donor_derived": True,
        "source": source,
    }


def generate(backup_dir: Path | str, manifest_path: Path | str,
             out_dir: Path | str, *, koboreru: bytes | None = None,
             koboreru_sha256: str | None = None,
             preloader_sha256: str = REVIEWED_PRELOADER_SHA256) -> dict:
    """Write the donor artifacts and return the written manifest.

    Refuses unless the backup set verifies against its manifest.  ``koboreru``
    is the already-checked source-built TEE image; with it the composed
    ``tee1`` stage is emitted too.
    """
    out = require_local_output(out_dir)
    backup_dir = Path(backup_dir)
    manifest_path = Path(manifest_path)
    try:
        files = backup.load_manifest(manifest_path)
        backup.require_complete_backup(backup_dir, files)
    except backup.BackupSetError as error:
        raise Refusal(f"no usable verified backup: {error}") from error

    boot0 = _read_backup_area(backup_dir, files, "boot0")
    _check_preloader(boot0, preloader_sha256)
    stock_tee1 = _read_backup_area(backup_dir, files, "tee1")
    _check_stock_tee1(stock_tee1)

    artifacts: list[dict] = []
    payloads: list[tuple[str, bytes, str]] = [
        ("boot0-preloader.bin", boot0, "backup:boot0"),
        ("tee1-stock.bin", stock_tee1, "backup:tee1"),
    ]

    if koboreru is not None or koboreru_sha256 is not None:
        if koboreru is None or not koboreru_sha256:
            raise Refusal("koboreru and koboreru-sha256 must be supplied together")
        digest = sha256_bytes(koboreru)
        if digest != koboreru_sha256:
            raise Refusal(
                f"koboreru is {digest}, pinned digest is {koboreru_sha256}")
        if len(koboreru) < 16 or not koboreru.startswith(MTK_IMAGE_MAGIC):
            raise Refusal("Koboreru input is not an MTK image")
        if koboreru[8:8 + len(STOCK_TEE_TYPE)] != STOCK_TEE_TYPE:
            raise Refusal("Koboreru input is not an MTK ATF/TEE image")
        if len(koboreru) > len(stock_tee1):
            raise Refusal("Koboreru image is larger than the tee1 partition")
        tail = stock_tee1[len(koboreru):]
        payloads.extend([
            ("tee1-stock-tail.bin", tail, "backup:tee1[koboreru-length:]"),
            ("tee1-stage.bin", koboreru + tail, "backup:tee1+koboreru"),
        ])

    for name, data, source in payloads:
        write_bytes_atomic(out / name, data)
        artifacts.append(_artifact_record(name, data, source))

    manifest = {
        "schema": SCHEMA,
        "generated_at": utc_stamp(),
        "device": {
            "hwcode": "0x8167",
            "flash_bytes": backup.FLASH_BYTES,
            "boot_area_bytes": backup.BOOT_AREA_BYTES,
        },
        "backup_manifest_sha256": sha256_file(manifest_path),
        "artifacts": artifacts,
    }
    write_bytes_atomic(
        out / MANIFEST_NAME,
        (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode())
    return manifest


def load_artifact(out_dir: Path | str, manifest: dict, name: str) -> bytes:
    """Read one generated artifact and require it to match the manifest."""
    records = {record["name"]: record for record in manifest.get("artifacts", [])}
    if name not in records:
        raise Refusal(f"{name} is not in the donor artifact manifest")
    record = records[name]
    path = Path(out_dir) / name
    try:
        data = path.read_bytes()
    except OSError as error:
        raise Refusal(f"cannot read generated {name}: {error}") from error
    if len(data) != record["size"] or sha256_bytes(data) != record["sha256"]:
        raise Refusal(f"generated {name} does not match its manifest digest")
    return data


def _read_input(path: Path, expected_sha256: str) -> bytes:
    try:
        data = path.read_bytes()
    except OSError as error:
        raise Refusal(f"cannot read {path}: {error}") from error
    if sha256_bytes(data) != expected_sha256:
        raise Refusal(f"{path} is {sha256_bytes(data)}, pinned digest is {expected_sha256}")
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build donor-derived Lidar chain artifacts from a verified "
                    "backup.")
    parser.add_argument("--backup-dir", required=True, type=Path)
    parser.add_argument("--manifest", type=Path,
                        help="backup manifest (default: <backup-dir>/backup-manifest.json)")
    parser.add_argument("--out", required=True, type=Path,
                        help="output directory allowed by require_local_output")
    parser.add_argument("--koboreru", type=Path,
                        help="source-built Koboreru TEE image")
    parser.add_argument("--koboreru-sha256")
    parser.add_argument("--preloader-sha256", default=REVIEWED_PRELOADER_SHA256,
                        help="reviewed signed preloader pin")
    args = parser.parse_args(argv)
    manifest = args.manifest or args.backup_dir / "backup-manifest.json"
    try:
        koboreru = None
        if args.koboreru or args.koboreru_sha256:
            if not args.koboreru or not args.koboreru_sha256:
                raise Refusal("--koboreru and --koboreru-sha256 must be supplied together")
            koboreru = _read_input(args.koboreru, args.koboreru_sha256)
        result = generate(
            args.backup_dir, manifest, args.out, koboreru=koboreru,
            koboreru_sha256=args.koboreru_sha256,
            preloader_sha256=args.preloader_sha256)
    except DonorArtifactError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    print(f"donor_manifest={args.out / MANIFEST_NAME}")
    for record in result["artifacts"]:
        print(f"{record['sha256']}  {record['name']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
