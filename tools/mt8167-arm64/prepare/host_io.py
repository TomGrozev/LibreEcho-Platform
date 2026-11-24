#!/usr/bin/env python3
"""Host file helpers shared by the preparation command and the donor generator.

The command stages and the artifact generator both hash inputs and write
outputs atomically, so the implementations live here once.  Nothing in this
module touches a device.
"""
from __future__ import annotations

import hashlib
import tempfile
from datetime import datetime, timezone
from pathlib import Path


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_bytes_atomic(path: Path, data: bytes) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=path.name + ".",
                                     delete=False) as handle:
        temporary = Path(handle.name)
        handle.write(data)
        handle.flush()
    temporary.replace(path)
