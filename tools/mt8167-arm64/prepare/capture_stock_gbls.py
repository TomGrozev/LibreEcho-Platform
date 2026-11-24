#!/usr/bin/env python3
"""Capture the stock EFR32 Zigbee GBLs from a host-side dump into local-firmware/.

The Echo Plus 2nd Gen ships two Amazon-signed GBL images in its stock system
partition (lab-notes/phase-06/hw-20261121/step25-efr32/result.md in the
libreecho-lidar-port repository):

    system/vendor/firmware/silabs/xncp-fw.gbl       Zigbee NCP
    system/vendor/firmware/dsr/zb_mux_rcp.gbl       Zigbee/Thread mux RCP

They stay local copies.  This script reads only a directory on the host (a
mounted dump or an extracted rootfs), never adb, fastboot, a serial port or a
device node, verifies the known size and sha256, and writes the files under
``local-firmware/`` with a ``.gitignore`` that keeps them out of git.

Usage:

    python3 capture_stock_gbls.py --source /mnt/dump/stock/system_a_rootfs
"""
from __future__ import annotations

import argparse
import hashlib
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import lidar_donor_artifacts as donor  # noqa: E402

DEFAULT_OUT = Path("local-firmware")
IGNORE_LINES = ("*", "!.gitignore")


@dataclass(frozen=True)
class CaptureEntry:
    source: str
    name: str
    size: int
    sha256: str


# Pins from the read-only system_a read on 2026-11-21.
CAPTURE_SET: tuple[CaptureEntry, ...] = (
    CaptureEntry(
        source="system/vendor/firmware/silabs/xncp-fw.gbl",
        name="xncp-fw.gbl",
        size=186480,
        sha256="1d9ed42ff12168f00394f84685c698e671f158874bc0dd2c7956388ebd212406"),
    CaptureEntry(
        source="system/vendor/firmware/dsr/zb_mux_rcp.gbl",
        name="zb_mux_rcp.gbl",
        size=145216,
        sha256="4e138f84cd2b7f5eaba1835999e98df5b6750f07429fb6ab7e4df8b261f61849"),
)


class CaptureError(RuntimeError):
    """A source file is missing or does not match its known identity."""


class Refusal(CaptureError):
    """The request is unsafe; nothing was written."""


def _regular_file(path: Path, label: str) -> None:
    try:
        mode = path.stat().st_mode
    except OSError as error:
        raise Refusal(f"{label}: {error}") from error
    if stat.S_ISBLK(mode) or stat.S_ISCHR(mode):
        raise Refusal(f"{label}: refusing a device node, not a host file")
    if not stat.S_ISREG(mode):
        raise Refusal(f"{label}: not a regular host file")


def _resolve_source(root: Path, relative: str) -> Path:
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        raise Refusal(f"{relative}: escapes the source directory") from None
    return candidate


def _ensure_ignored(out: Path) -> None:
    ignore = out / ".gitignore"
    if ignore.exists():
        lines = {line.strip() for line in ignore.read_text().splitlines()}
        if "*" not in lines:
            raise Refusal(
                f"{ignore} does not ignore every file; refusing to place "
                "proprietary firmware beside a trackable file")
        return
    ignore.write_text("\n".join(IGNORE_LINES) + "\n")


def capture(source: Path | str, out: Path | str = DEFAULT_OUT, *,
            entries: tuple[CaptureEntry, ...] = CAPTURE_SET) -> list[Path]:
    """Copy and verify the stock GBLs; return the destination paths."""
    source_root = Path(source).resolve()
    if not source_root.is_dir():
        raise Refusal(f"{source_root}: source must be a host directory, not a device")
    try:
        destination = donor.require_local_output(out)
    except donor.Refusal as error:
        raise Refusal(str(error)) from error
    destination.mkdir(parents=True, exist_ok=True)
    _ensure_ignored(destination)

    written: list[Path] = []
    for entry in entries:
        path = _resolve_source(source_root, entry.source)
        _regular_file(path, entry.source)
        try:
            data = path.read_bytes()
        except OSError as error:
            raise CaptureError(f"{entry.source}: {error}") from error
        if len(data) != entry.size:
            raise CaptureError(
                f"{entry.source}: {len(data)} bytes, expected {entry.size}")
        digest = hashlib.sha256(data).hexdigest()
        if digest != entry.sha256:
            raise CaptureError(
                f"{entry.source}: sha256 {digest}, expected {entry.sha256}")
        target = destination / entry.name
        if target.exists() and target.read_bytes() != data:
            raise Refusal(f"{target} already exists with different bytes")
        temporary = target.with_name(target.name + ".tmp")
        try:
            temporary.write_bytes(data)
            temporary.replace(target)
        finally:
            if temporary.exists():
                temporary.unlink()
        written.append(target)
        print(f"{digest}  {entry.size:>8}  {entry.name}  (from {entry.source})")
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Copy the stock Zigbee GBLs from a host dump into "
                    "local-firmware/.")
    parser.add_argument("--source", required=True, type=Path,
                        help="mounted/extracted stock system root (host directory)")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT,
                        help="local-firmware output directory")
    args = parser.parse_args(argv)
    try:
        written = capture(args.source, args.out)
    except CaptureError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    print(f"captured {len(written)} GBL file(s) under {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
