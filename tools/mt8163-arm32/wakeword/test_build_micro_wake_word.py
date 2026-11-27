#!/usr/bin/env python3
"""Build the microWakeWord runtime and smoke it under qemu-arm.

Requires the pinned inputs to be staged by the caller:

    LIBREECHO_MWW_TFLM_SOURCE
    LIBREECHO_MWW_FLATBUFFERS_SOURCE
    LIBREECHO_MWW_KISSFFT_SOURCE
    LIBREECHO_MWW_EYALROZ_PRINTF_SOURCE
    LIBREECHO_MWW_MODELS              v2 model directory with .tflite/.json
    LIBREECHO_MWW_CROSS               optional, defaults to arm-linux-gnueabihf-
    LIBREECHO_MWW_QEMU                optional, defaults to qemu-arm-static

The test is skipped when those inputs are absent. It builds the archives twice
to prove byte-for-byte reproducibility, compiles micro_wake_word_smoke.cc
against the installed interface, then loads and invokes all five models inside
their manifest tensor_arena_size.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
BUILDER = HERE / "build_micro_wake_word.sh"
LOADER = HERE / "micro_wake_word_smoke.cc"
MODELS = ("alexa", "hey_jarvis", "hey_mycroft", "okay_nabu", "vad")
ARCHIVES = ("libtflm-micro.a", "libmicrowakeword-frontend.a")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_inputs() -> dict[str, Path]:
    names = {
        "tflm": "LIBREECHO_MWW_TFLM_SOURCE",
        "flatbuffers": "LIBREECHO_MWW_FLATBUFFERS_SOURCE",
        "kissfft": "LIBREECHO_MWW_KISSFFT_SOURCE",
        "printf": "LIBREECHO_MWW_EYALROZ_PRINTF_SOURCE",
        "models": "LIBREECHO_MWW_MODELS",
    }
    missing = [variable for variable in names.values()
               if not os.environ.get(variable)]
    if missing:
        raise unittest.SkipTest(
            "pinned microWakeWord inputs are not staged: " + ", ".join(missing))
    inputs = {key: Path(os.environ[variable]).resolve()
              for key, variable in names.items()}
    for key, path in inputs.items():
        if not path.is_dir():
            raise AssertionError(f"{key} input is not a directory: {path}")
    return inputs


class MicroWakeWordRuntimeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.inputs = require_inputs()
        cls.cross = os.environ.get("LIBREECHO_MWW_CROSS", "arm-linux-gnueabihf-")
        cls.qemu = shutil.which(os.environ.get("LIBREECHO_MWW_QEMU",
                                               "qemu-arm-static"))
        if cls.qemu is None:
            raise unittest.SkipTest("qemu-arm-static is not on PATH")
        cls.cxx = shutil.which(cls.cross + "g++")
        if cls.cxx is None:
            raise unittest.SkipTest(f"{cls.cross}g++ is not on PATH")
        cls.scratch = tempfile.TemporaryDirectory(prefix="mww-runtime-test-")
        cls.root = Path(cls.scratch.name)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.scratch.cleanup()

    def build(self, output: Path) -> None:
        subprocess.run(
            [
                str(BUILDER),
                "--tflm-source", str(self.inputs["tflm"]),
                "--flatbuffers-source", str(self.inputs["flatbuffers"]),
                "--kissfft-source", str(self.inputs["kissfft"]),
                "--eyalroz-printf-source", str(self.inputs["printf"]),
                "--output", str(output),
                "--toolchain", self.cross,
                "--jobs", str(os.cpu_count() or 1),
            ],
            check=True,
        )

    def test_two_clean_builds_are_identical_and_models_run(self) -> None:
        first = self.root / "build-1"
        second = self.root / "build-2"
        self.build(first)
        self.build(second)

        hashes = {}
        for archive in ARCHIVES:
            first_sha = sha256(first / "lib" / archive)
            second_sha = sha256(second / "lib" / archive)
            self.assertEqual(first_sha, second_sha, archive)
            hashes[archive] = first_sha
            print(f"PASS reproducible archive={archive} sha256={first_sha}")

        for relative in (
            "include/microwakeword/operators.h",
            "include/tensorflow/lite/micro/micro_interpreter.h",
            "include/tensorflow/lite/experimental/microfrontend/lib/frontend.h",
            "include/flatbuffers/flatbuffers.h",
            "share/licenses/TFLM-LICENSE.txt",
            "share/licenses/kissfft-COPYING.txt",
        ):
            path = first / relative
            self.assertTrue(path.is_file(), relative)

        loader = self.root / "micro_wake_word_smoke"
        subprocess.run(
            [
                self.cxx,
                "-std=c++17", "-static", "-Os",
                "-march=armv7-a", "-mfpu=neon-vfpv4", "-mfloat-abi=hard",
                f"-I{first / 'include'}",
                str(LOADER),
                "-Wl,--start-group",
                str(first / "lib" / "libtflm-micro.a"),
                str(first / "lib" / "libmicrowakeword-frontend.a"),
                "-Wl,--end-group",
                "-lm",
                "-o", str(loader),
            ],
            check=True,
        )

        for name in MODELS:
            model = self.inputs["models"] / f"{name}.tflite"
            manifest = self.inputs["models"] / f"{name}.json"
            self.assertTrue(model.is_file(), model)
            metadata = json.loads(manifest.read_text(encoding="utf-8"))
            arena = int(metadata["micro"]["tensor_arena_size"])
            result = subprocess.run(
                [str(self.qemu), str(loader), str(arena), str(model)],
                check=True, capture_output=True, text=True,
            )
            fields = dict(
                field.split("=", 1)
                for field in result.stdout.strip().splitlines()[-1].split()
            )
            self.assertEqual(fields["model"], model.name)
            self.assertEqual(int(fields["arena_size"]), arena)
            self.assertLessEqual(int(fields["arena_used"]), arena)
            self.assertGreater(int(fields["arena_used"]), 0)
            self.assertEqual(int(fields["operators"]), 20)
            print(
                f"PASS model={name} arena_size={arena} "
                f"arena_used={fields['arena_used']} invoke=ok"
            )
        print("PASS two_clean_builds_identical", json.dumps(hashes, sort_keys=True))


if __name__ == "__main__":
    unittest.main(verbosity=2)
