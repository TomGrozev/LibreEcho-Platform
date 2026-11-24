#!/usr/bin/env python3
"""Narrow adapter over the owner's mtkclient checkout.

Only this module knows how the Lidar preparation command talks to BROM.  It is
deliberately the one seam a test replaces, so the command logic never spawns a
process and never parses mtkclient output itself.

The command set is the one the restore drill proved on the unit
(``lab-notes/phase-03/notes.md`` in the public libreecho-lidar-port
repository):

    mtk.py printgpt
    mtk.py r <name> <file> --parttype boot1|boot2     eMMC boot areas
    mtk.py r <name> <file>                            whole user-area partition
    mtk.py ro 0x<abs> 0x<len> <file>                  absolute user-area read
    mtk.py w <name> <file>                            whole user-area write
    mtk.py wo 0x<abs> 0x<len> <file>                  absolute user-area write
    mtk.py wo 0x<off> 0x<len> <file> --parttype boot1 boot area 1 write

No command here erases flash, writes `misc`, or writes boot area 2.  The
caller decides which areas are written; this module only refuses to name boot
area 2.

``--mtkclient`` (or the ``MTKCLIENT`` environment variable) points at the
checkout; there is no built-in default.  The checkout's virtualenv python is
used when present; otherwise the current interpreter.  mtkclient keeps
``.state`` in the working directory, so the preparation command uses one work
directory per BROM session.
"""
from __future__ import annotations

import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

DEFAULT_TIMEOUT = 600

_HWCODE_RE = re.compile(r"HW code:\s*(0x[0-9a-fA-F]+)")
_BOOT1_RE = re.compile(r"EMMC Boot1 Size:\s*(0x[0-9a-fA-F]+)")
_USER_RE = re.compile(r"EMMC USER Size:\s*(0x[0-9a-fA-F]+)")


class AdapterError(RuntimeError):
    """mtkclient is missing, failed, or produced an unusable result."""


class AdapterWriteRefused(RuntimeError):
    """The request would write an area the adapter never writes."""


@dataclass(frozen=True)
class Identity:
    """The part of the BROM identity the command gates on."""

    hwcode: int
    flash_bytes: int
    boot_area_bytes: int
    sector_bytes: int = 512


def parse_printgpt_identity(text: str) -> Identity:
    """Derive the identity from a `mtk.py printgpt` transcript."""
    hwcode = _HWCODE_RE.search(text)
    boot1 = _BOOT1_RE.search(text)
    user = _USER_RE.search(text)
    missing = [name for name, match in
               (("HW code", hwcode), ("EMMC Boot1 Size", boot1), ("EMMC USER Size", user))
               if match is None]
    if missing:
        raise AdapterError(
            "printgpt output is missing " + ", ".join(missing)
            + "; is the unit in BROM mode and is this the mtkclient checkout?")
    flash = int(user.group(1), 16)
    if flash % 512:
        raise AdapterError(f"EMMC USER Size {flash} is not divisible by 512")
    return Identity(
        hwcode=int(hwcode.group(1), 16),
        flash_bytes=flash,
        boot_area_bytes=int(boot1.group(1), 16),
        sector_bytes=512,
    )


class MtkClient:
    """The real adapter.  Every device access goes through ``_run``."""

    dry_run = False

    def __init__(
        self,
        root: Path | str,
        *,
        python_executable: Path | str | None = None,
        workdir: Path | str | None = None,
        dry_run: bool = False,
        runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        self.root = Path(root).expanduser().resolve()
        self.mtk_py = self.root / "mtk.py"
        self.python = (Path(python_executable).expanduser() if python_executable
                       else self.root / ".venv" / "bin" / "python")
        if not self.mtk_py.is_file():
            raise AdapterError(f"mtkclient checkout not found at {self.mtk_py}")
        if not self.python.is_file():
            raise AdapterError(
                f"mtkclient virtualenv python not found at {self.python}; "
                "pass --mtkclient-python")
        self.workdir = Path(workdir).expanduser().resolve() if workdir else None
        if self.workdir is not None:
            self.workdir.mkdir(parents=True, exist_ok=True)
        self.dry_run = dry_run
        self.runner = runner or subprocess.run
        self.timeout = timeout
        self.commands: list[list[str]] = []

    # -- identity ---------------------------------------------------------
    def identity(self) -> Identity | None:
        cmd = self._base() + ["printgpt"]
        if self.dry_run:
            self._print(cmd)
            return None
        out = self._run(cmd, failure_markers=("Failed to", "Error"))
        return parse_printgpt_identity(out.stdout or "")

    # -- reads ------------------------------------------------------------
    def read_area(self, area) -> bytes | None:
        """Read one backup-set area, returning exactly ``area.size`` bytes."""
        if area.kind in ("boot1", "boot2"):
            cmd = self._base() + ["r", area.name, "<file>", "--parttype", area.kind]
            if self.dry_run:
                self._print(cmd)
                return None
            # mtkclient reads a boot parttype from byte 0 of the hardware boot
            # area, so the data still starts at ``area.offset``.
            data = self._read_command(cmd)
            if len(data) < area.offset + area.size:
                raise AdapterError(
                    f"short boot-area read from {area.name!r}: wanted "
                    f"{area.offset + area.size} bytes, got {len(data)}")
            return data[area.offset:area.offset + area.size]
        if area.kind in ("gpt", "gpt_backup"):
            return self.read_absolute(area.offset, area.size)
        cmd = self._base() + ["r", area.name, "<file>"]
        if self.dry_run:
            self._print(cmd)
            return None
        # ``mtk.py r <partition> <file>`` always dumps the whole partition from
        # its first sector, so the result is partition-relative and the
        # absolute BackupArea offset plays no part in the slicing.
        data = self._read_command(cmd)
        if len(data) != area.size:
            raise AdapterError(
                f"read from {area.name!r}: wanted exactly {area.size} bytes, "
                f"got {len(data)}")
        return data

    def read_absolute(self, offset: int, length: int) -> bytes | None:
        cmd = self._base() + ["ro", hex(offset), hex(length), "<file>"]
        if self.dry_run:
            self._print(cmd)
            return None
        data = self._read_command(cmd)
        if len(data) != length:
            raise AdapterError(
                f"short absolute read at 0x{offset:x}: wanted {length} bytes, got {len(data)}")
        return data

    def _read_command(self, cmd: list[str]) -> bytes:
        with tempfile.TemporaryDirectory(prefix="lidar-prepare-") as tmp:
            target = Path(tmp) / "read.bin"
            resolved = [str(target) if part == "<file>" else part for part in cmd]
            self._run(resolved, failure_markers=("Failed to dump", "Error on readflash"))
            try:
                return target.read_bytes()
            except OSError as error:
                raise AdapterError(f"mtkclient did not produce {target}: {error}") from error

    # -- writes -----------------------------------------------------------
    def write_absolute(self, offset: int, data: bytes) -> None:
        if not data:
            raise AdapterWriteRefused("refusing an empty write")
        cmd = self._base() + ["wo", hex(offset), hex(len(data)), "<file>"]
        self._write_command(cmd, data, "user area")

    def write_partition(self, name: str, data: bytes) -> None:
        if not data:
            raise AdapterWriteRefused("refusing an empty write")
        cmd = self._base() + ["w", name, "<file>"]
        self._write_command(cmd, data, f"partition {name!r}")

    def write_boot_area1(self, offset: int, data: bytes) -> None:
        if not data:
            raise AdapterWriteRefused("refusing an empty write")
        cmd = self._base() + [
            "wo", hex(offset), hex(len(data)), "<file>", "--parttype", "boot1"]
        self._write_command(cmd, data, "boot area 1")

    def _write_command(self, cmd: list[str], data: bytes, what: str) -> None:
        if any("boot2" in part for part in cmd):
            raise AdapterWriteRefused("boot area 2 is never writable")
        if len(data) % 512:
            raise AdapterWriteRefused(
                f"{what} write is {len(data)} bytes, not 512-byte aligned; mtkclient "
                "would zero-pad a sector the command never verified")
        if self.dry_run:
            self._print(cmd, size=len(data))
            return
        with tempfile.TemporaryDirectory(prefix="lidar-prepare-") as tmp:
            source = Path(tmp) / "write.bin"
            source.write_bytes(data)
            resolved = [str(source) if part == "<file>" else part for part in cmd]
            self._run(resolved, failure_markers=("Failed to write", "Error on writeflash"))

    # -- process seam -----------------------------------------------------
    def _base(self) -> list[str]:
        return [str(self.python), str(self.mtk_py)]

    def _cwd(self, fallback: str | None) -> str | None:
        return str(self.workdir) if self.workdir is not None else fallback

    def _run(
        self, cmd: Sequence[str], failure_markers: Sequence[str] = ()
    ) -> subprocess.CompletedProcess[str]:
        self.commands.append(list(cmd))
        try:
            proc = self.runner(
                list(cmd), cwd=self._cwd(None),
                capture_output=True, text=True, timeout=self.timeout)
        except OSError as error:
            raise AdapterError(f"cannot run mtkclient: {error}") from error
        except subprocess.TimeoutExpired as error:
            raise AdapterError(f"mtkclient timed out after {self.timeout}s") from error
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        marker = next((item for item in failure_markers if item in stdout), None)
        if proc.returncode != 0 or marker is not None:
            tail = (stdout + stderr).strip().splitlines()[-3:]
            raise AdapterError(
                f"mtkclient command failed (exit {proc.returncode}): {' | '.join(tail)}")
        return proc

    def _print(self, cmd: Sequence[str], size: int | None = None) -> None:
        rendered = " ".join(cmd)
        suffix = f"  # {size} bytes" if size is not None else ""
        print(f"DRY-RUN mtkclient: {rendered}{suffix}")
