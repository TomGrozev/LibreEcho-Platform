#!/usr/bin/env python3
"""Narrow adapter over the Amonet Lidar host tool.

Only this module knows how the Lidar preparation command reaches the Amonet
CLI.  The command logic never spawns a process and never parses the tool's
output itself; it talks to the duck-typed interface this module defines.

The tool is ``modules/lidar_brom.py`` in the Amonet checkout (``--amonet`` or
``AMONET``; there is no built-in default).  Its command set is::

    identity
    read --area NAME --output FILE
    read --offset N --length L --output FILE
    write --area NAME [--offset N] --input FILE --approve-write
    write --offset N --input FILE --approve-write

``--simulate DIR`` makes the tool speak to a simulated BROM built from a
reviewed backup, so the same adapter drives the host and the simulator.  The
tool exits 0 on success, 1 on a failed check and 2 on a refusal.

No command here erases flash, writes `misc`, or writes boot area 2.  The tool
itself refuses boot area 2 (it names it ``boot1``) and any write without
``--approve-write``; this module refuses the same requests before spawning so
the caller sees a stable message.
"""
from __future__ import annotations

import json
import hashlib
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence


class AdapterError(RuntimeError):
    """The Amonet tool is missing, failed, or produced an unusable result."""


class AdapterWriteRefused(RuntimeError):
    """The request would write an area the adapter never writes."""


@dataclass(frozen=True)
class Identity:
    """The part of the BROM identity the command gates on."""

    hwcode: int
    flash_bytes: int
    boot_area_bytes: int
    sector_bytes: int = 512


DEFAULT_TIMEOUT = 600
SECTOR_BYTES = 512
_GPT_KINDS = frozenset({"gpt", "gpt_backup"})
_BOOT_KINDS = frozenset({"boot1", "boot2"})
_CLI_BOOT_AREA_2_NAMES = frozenset({"boot1", "boot2"})


class AmonetClient:
    """The real adapter.  Every device access goes through ``_run``."""

    dry_run = False

    def __init__(
        self,
        checkout: Path | str,
        *,
        python: Path | str | None = None,
        simulate_dir: Path | str | None = None,
        payload: Path | str | None = None,
        dry_run: bool = False,
        runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        self.checkout = Path(checkout).expanduser().resolve()
        self.cli = self.checkout / "modules" / "lidar_brom.py"
        if not self.cli.is_file():
            raise AdapterError(
                f"amonet checkout not found at {self.cli}; pass --amonet or set AMONET")
        self.python = Path(python).expanduser() if python else Path(sys.executable)
        self.simulate_dir = (Path(simulate_dir).expanduser().resolve()
                             if simulate_dir is not None else None)
        self.payload = (Path(payload).expanduser() if payload is not None else None)
        self.dry_run = dry_run
        self.runner = runner or subprocess.run
        self.timeout = timeout
        self.commands: list[list[str]] = []

    # -- identity ---------------------------------------------------------
    def identity(self) -> Identity | None:
        cmd = self._base() + ["identity"]
        if self.dry_run:
            self._print(cmd)
            return None
        out = self._run(cmd).stdout or ""
        try:
            value = json.loads(out)
            hwcode = int(value["hwcode"], 0)
            flash_bytes = int(value["user_bytes"])
            boot_area_bytes = int(value["boot1_bytes"])
            sector_bytes = int(value["sector_bytes"])
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
            excerpt = " | ".join(out.strip().splitlines()[-3:])
            raise AdapterError(
                f"amonet identity output is not the documented JSON ({error}): {excerpt}"
            ) from error
        if flash_bytes % sector_bytes:
            raise AdapterError(
                f"EMMC USER Size {flash_bytes} is not divisible by {sector_bytes}")
        return Identity(
            hwcode=hwcode,
            flash_bytes=flash_bytes,
            boot_area_bytes=boot_area_bytes,
            sector_bytes=sector_bytes,
        )

    # -- reads ------------------------------------------------------------
    def read_area(self, area) -> bytes | None:
        """Read one backup-set area, returning exactly ``area.size`` bytes."""
        if area.kind in _GPT_KINDS:
            return self.read_absolute(area.offset, area.size)
        cmd = self._base() + ["read", "--area", area.name, "--output", "<file>"]
        if self.dry_run:
            self._print(cmd)
            return None
        data = self._read_command(cmd)
        if area.kind in _BOOT_KINDS:
            # ``read --area`` returns the whole hardware boot area from byte 0,
            # so the backup-set offset still has to be applied here.
            if len(data) < area.offset + area.size:
                raise AdapterError(
                    f"short boot-area read from {area.name!r}: wanted "
                    f"{area.offset + area.size} bytes, got {len(data)}")
            return data[area.offset:area.offset + area.size]
        # A user-area read is partition-relative: it starts at the partition's
        # first sector.
        if len(data) != area.size:
            raise AdapterError(
                f"read from {area.name!r}: wanted exactly {area.size} bytes, "
                f"got {len(data)}")
        return data

    def read_absolute(self, offset: int, length: int) -> bytes | None:
        cmd = self._base() + [
            "read", "--offset", hex(offset), "--length", hex(length),
            "--output", "<file>"]
        if self.dry_run:
            self._print(cmd)
            return None
        data = self._read_command(cmd)
        if len(data) != length:
            raise AdapterError(
                f"short absolute read at 0x{offset:x}: wanted {length} bytes, "
                f"got {len(data)}")
        return data

    def _read_command(self, cmd: list[str]) -> bytes:
        with tempfile.TemporaryDirectory(prefix="lidar-prepare-") as tmp:
            target = Path(tmp) / "read.bin"
            self._run(self._resolve(cmd, target))
            try:
                return target.read_bytes()
            except OSError as error:
                raise AdapterError(f"amonet did not produce {target}: {error}") from error

    @staticmethod
    def _resolve(cmd: Sequence[str], path: Path) -> list[str]:
        return [str(path) if part == "<file>" else part for part in cmd]

    # -- writes -----------------------------------------------------------
    def write_absolute(self, offset: int, data: bytes) -> None:
        cmd = self._base() + [
            "write", "--offset", hex(offset), "--input", "<file>", "--approve-write"]
        self._write_command(cmd, data, "user area")

    def write_partition(self, name: str, data: bytes) -> None:
        cmd = self._base() + [
            "write", "--area", name, "--input", "<file>", "--approve-write"]
        self._write_command(cmd, data, f"partition {name!r}", area=name)

    def write_boot_area1(self, offset: int, data: bytes) -> None:
        # The Amonet CLI calls eMMC boot area 1 ``boot0``; ``boot1`` there is
        # boot area 2, which is never writable.
        cmd = self._base() + [
            "write", "--area", "boot0", "--offset", hex(offset),
            "--input", "<file>", "--approve-write"]
        self._write_command(cmd, data, "boot area 1", area="boot0")

    def _write_command(self, cmd: list[str], data: bytes, what: str, *,
                       area: str | None = None) -> None:
        if not data:
            raise AdapterWriteRefused("refusing an empty write")
        if area in _CLI_BOOT_AREA_2_NAMES:
            raise AdapterWriteRefused("boot area 2 is never writable")
        if len(data) % SECTOR_BYTES:
            raise AdapterWriteRefused(
                f"{what} write is {len(data)} bytes, not 512-byte aligned")
        if self.dry_run:
            self._print(cmd, size=len(data),
                        digest=hashlib.sha256(data).hexdigest())
            return
        with tempfile.TemporaryDirectory(prefix="lidar-prepare-") as tmp:
            source = Path(tmp) / "write.bin"
            source.write_bytes(data)
            self._run(self._resolve(cmd, source))

    # -- process seam -----------------------------------------------------
    def _base(self) -> list[str]:
        cmd = [str(self.python), str(self.cli)]
        if self.simulate_dir is not None:
            cmd += ["--simulate", str(self.simulate_dir)]
        if self.payload is not None:
            cmd += ["--payload", str(self.payload)]
        return cmd

    def _run(self, cmd: Sequence[str]) -> subprocess.CompletedProcess[str]:
        self.commands.append(list(cmd))
        try:
            proc = self.runner(
                list(cmd), capture_output=True, text=True, timeout=self.timeout)
        except OSError as error:
            raise AdapterError(f"cannot run amonet: {error}") from error
        except subprocess.TimeoutExpired as error:
            raise AdapterError(f"amonet timed out after {self.timeout}s") from error
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        tail = " | ".join((stdout + stderr).strip().splitlines()[-3:])
        rendered = " ".join(cmd)
        traceback = "Traceback (most recent call last)" in (stdout + stderr)
        if proc.returncode != 0 or traceback:
            if (proc.returncode == 2 and not traceback and "write" in cmd
                    and "refused:" in stderr):
                raise AdapterWriteRefused(
                    f"amonet refused the write ({rendered}): {tail}")
            raise AdapterError(
                f"amonet command failed (exit {proc.returncode}): {rendered}: {tail}")
        return proc

    def _print(self, cmd: Sequence[str], size: int | None = None,
               digest: str | None = None) -> None:
        rendered = " ".join(cmd)
        suffix = f"  # {size} bytes" if size is not None else ""
        if digest is not None:
            suffix += f" sha256:{digest}"
        print(f"DRY-RUN amonet: {rendered}{suffix}")
