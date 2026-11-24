#!/usr/bin/env python3
"""Host-only tests for the stock GBL capture script, with synthetic bytes."""
from __future__ import annotations

import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE.parent / "install"))

import capture_stock_gbls as capture  # noqa: E402


def entry(source: str, data: bytes, name: str | None = None):
    return capture.CaptureEntry(
        source=source,
        name=name or Path(source).name,
        size=len(data),
        sha256=hashlib.sha256(data).hexdigest())


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "dump"
        self.firmware = {
            "system/vendor/firmware/silabs/xncp-fw.gbl": b"zigbee-ncp" * 100,
            "system/vendor/firmware/dsr/zb_mux_rcp.gbl": b"zb-mux-rcp" * 90,
        }
        for relative, data in self.firmware.items():
            path = self.source / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        self.entries = tuple(entry(relative, data)
                             for relative, data in self.firmware.items())
        self.out = self.root / "local-firmware"

    def test_copies_and_verifies_and_whitelists_the_ignore_file(self):
        written = capture.capture(self.source, self.out, entries=self.entries)
        self.assertEqual(len(written), 2)
        for target, data in zip(written, self.firmware.values()):
            self.assertEqual(target.read_bytes(), data)
            self.assertEqual(target.parent, self.out)
        ignore = (self.out / ".gitignore").read_text().splitlines()
        self.assertEqual(ignore, ["*", "!.gitignore"])

    def test_refuses_a_digest_mismatch(self):
        bad = (capture.CaptureEntry(
            source=next(iter(self.firmware)),
            name="xncp-fw.gbl", size=len(b"zigbee-ncp" * 100),
            sha256="0" * 64),)
        with self.assertRaises(capture.CaptureError) as failure:
            capture.capture(self.source, self.out, entries=bad)
        self.assertIn("sha256", str(failure.exception))
        self.assertFalse((self.out / "xncp-fw.gbl").exists())

    def test_refuses_a_size_mismatch(self):
        bad = (capture.CaptureEntry(
            source=next(iter(self.firmware)), name="xncp-fw.gbl",
            size=1, sha256="0" * 64),)
        with self.assertRaises(capture.CaptureError) as failure:
            capture.capture(self.source, self.out, entries=bad)
        self.assertIn("expected", str(failure.exception))

    def test_refuses_a_non_regular_source(self):
        bad = (capture.CaptureEntry(
            source="system/vendor/firmware", name="x.gbl", size=1,
            sha256="0" * 64),)
        with self.assertRaises(capture.Refusal) as failure:
            capture.capture(self.source, self.out, entries=bad)
        self.assertIn("not a regular host file", str(failure.exception))

    def test_refuses_a_source_that_escapes_the_root(self):
        outside = self.root / "outside.gbl"
        outside.write_bytes(b"x")
        bad = (capture.CaptureEntry(
            source="../outside.gbl", name="x.gbl", size=1,
            sha256=hashlib.sha256(b"x").hexdigest()),)
        with self.assertRaises(capture.Refusal) as failure:
            capture.capture(self.source, self.out, entries=bad)
        self.assertIn("escapes the source directory", str(failure.exception))

    def test_refuses_an_existing_different_destination(self):
        self.out.mkdir()
        (self.out / "xncp-fw.gbl").write_bytes(b"someone else")
        with self.assertRaises(capture.Refusal) as failure:
            capture.capture(self.source, self.out, entries=self.entries)
        self.assertIn("different bytes", str(failure.exception))

    def test_refuses_an_output_directory_without_a_full_ignore(self):
        self.out.mkdir()
        (self.out / ".gitignore").write_text("*.tmp\n")
        with self.assertRaises(capture.Refusal) as failure:
            capture.capture(self.source, self.out, entries=self.entries)
        self.assertIn("does not ignore every file", str(failure.exception))

    def test_refuses_a_public_checkout_path(self):
        checkout = self.root / "checkout"
        (checkout / ".git").mkdir(parents=True)
        with self.assertRaises(capture.Refusal) as failure:
            capture.capture(self.source, checkout / "release", entries=self.entries)
        self.assertIn("must stay private", str(failure.exception))


if __name__ == "__main__":
    unittest.main()
