#!/usr/bin/env bash
# Build the static microWakeWord runtime from pinned TensorFlow Lite Micro
# sources: the TFLM reference kernels plus the microfrontend C library.
#
# Usage:
#   build_micro_wake_word.sh --tflm-source DIR --flatbuffers-source DIR \
#     --kissfft-source DIR --eyalroz-printf-source DIR --output DIR \
#     [--toolchain host|armhf|PREFIX] [--jobs N] [--operators-config FILE]
#
# The output directory receives:
#   lib/libtflm-micro.a             TFLM core, reference kernels, operator list
#   lib/libmicrowakeword-frontend.a microfrontend and fixed-point kissfft
#   include/                        headers needed by a consumer
#   share/licenses/                 source licences
#
# Both archives are deterministic: objects are path-mapped to canonical
# prefixes and archives are written with `ar rcsD`.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd -P)"
OPERATORS_CONFIG="$SCRIPT_DIR/micro_wake_word_operators.config"
GENERATOR="$SCRIPT_DIR/generate_micro_wake_word_operators.py"
TOOLCHAIN=armhf
JOBS="$(nproc)"
TFLM_SOURCE=
FLATBUFFERS_SOURCE=
KISSFFT_SOURCE=
EYALROZ_PRINTF_SOURCE=
OUTPUT=
TFLM_COMMIT=

usage() {
  cat >&2 <<'USAGE'
usage: build_micro_wake_word.sh --tflm-source DIR --flatbuffers-source DIR \
  --kissfft-source DIR --eyalroz-printf-source DIR --output DIR \
  [--toolchain host|armhf|PREFIX] [--tflm-commit SHA] [--jobs N] \
  [--operators-config FILE]
USAGE
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tflm-source) TFLM_SOURCE="${2:?}"; shift 2 ;;
    --flatbuffers-source) FLATBUFFERS_SOURCE="${2:?}"; shift 2 ;;
    --kissfft-source) KISSFFT_SOURCE="${2:?}"; shift 2 ;;
    --eyalroz-printf-source) EYALROZ_PRINTF_SOURCE="${2:?}"; shift 2 ;;
    --output) OUTPUT="${2:?}"; shift 2 ;;
    --toolchain) TOOLCHAIN="${2:?}"; shift 2 ;;
    --tflm-commit) TFLM_COMMIT="${2:?}"; shift 2 ;;
    --jobs) JOBS="${2:?}"; shift 2 ;;
    --operators-config) OPERATORS_CONFIG="${2:?}"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "ERROR: unknown argument: $1" >&2; usage ;;
  esac
done

for value in TFLM_SOURCE FLATBUFFERS_SOURCE KISSFFT_SOURCE \
    EYALROZ_PRINTF_SOURCE OUTPUT; do
  [[ -n "${!value}" ]] || {
    echo "ERROR: --$(echo "$value" | tr 'A-Z_' 'a-z-') is required" >&2
    usage
  }
done

# make -C changes directory, so a relative path handed to it resolves against
# the TFLM tree: a relative DOWNLOADS_DIR made the dependency downloader fetch
# into a nonexistent nested directory instead of seeing the staged sources.
OUTPUT="$(realpath -m -- "$OUTPUT")"
TFLM_SOURCE="$(realpath -m -- "$TFLM_SOURCE")"
FLATBUFFERS_SOURCE="$(realpath -m -- "$FLATBUFFERS_SOURCE")"
KISSFFT_SOURCE="$(realpath -m -- "$KISSFFT_SOURCE")"
EYALROZ_PRINTF_SOURCE="$(realpath -m -- "$EYALROZ_PRINTF_SOURCE")"

case "$TOOLCHAIN" in
  host) CROSS="" ;;
  armhf) CROSS="${LIBREECHO_WAKE_CROSS:-arm-linux-gnueabihf-}" ;;
  *) CROSS="$TOOLCHAIN" ;;
esac

for tool in make python3 patch ar; do
  command -v "$tool" >/dev/null || {
    echo "ERROR: required build tool is missing: $tool" >&2
    exit 1
  }
done
CC="${CROSS}gcc"
CXX="${CROSS}g++"
AR="${CROSS}ar"
for compiler in "$CC" "$CXX" "$AR"; do
  command -v "$compiler" >/dev/null || {
    echo "ERROR: toolchain member is missing: $compiler" >&2
    exit 1
  }
done

for source in "$TFLM_SOURCE" "$FLATBUFFERS_SOURCE" "$KISSFFT_SOURCE" \
    "$EYALROZ_PRINTF_SOURCE"; do
  [[ -d "$source" && ! -L "$source" ]] || {
    echo "ERROR: source directory is missing or a symlink: $source" >&2
    exit 1
  }
done
[[ -f "$TFLM_SOURCE/tensorflow/lite/micro/tools/make/Makefile" ]] || {
  echo "ERROR: not a TensorFlow Lite Micro source tree: $TFLM_SOURCE" >&2
  exit 1
}
[[ -f "$TFLM_SOURCE/third_party/kissfft/kissfft.patch" ]] || {
  echo "ERROR: TFLM kissfft patch is missing" >&2
  exit 1
}
[[ -f "$KISSFFT_SOURCE/kiss_fft.c" && -f "$KISSFFT_SOURCE/tools/kiss_fftr.c" ]] || {
  echo "ERROR: not a kissfft source tree: $KISSFFT_SOURCE" >&2
  exit 1
}
[[ -f "$EYALROZ_PRINTF_SOURCE/src/printf/printf.c" ]] || {
  echo "ERROR: not an eyalroz printf source tree: $EYALROZ_PRINTF_SOURCE" >&2
  exit 1
}
[[ -f "$FLATBUFFERS_SOURCE/include/flatbuffers/flatbuffers.h" ]] || {
  echo "ERROR: not a flatbuffers source tree: $FLATBUFFERS_SOURCE" >&2
  exit 1
}
[[ -f "$OPERATORS_CONFIG" && -f "$GENERATOR" ]] || {
  echo "ERROR: operator list or generator is missing" >&2
  exit 1
}
if [[ -n "$TFLM_COMMIT" ]]; then
  [[ "$(git -C "$TFLM_SOURCE" rev-parse HEAD 2>/dev/null)" == "$TFLM_COMMIT" ]] || {
    echo "ERROR: TensorFlow Lite Micro source is not at the pinned commit: $TFLM_COMMIT" >&2
    exit 1
  }
fi
[[ ! -e "$OUTPUT" ]] || {
  echo "ERROR: refusing to overwrite output directory: $OUTPUT" >&2
  exit 1
}

mkdir -p "$OUTPUT/lib" "$OUTPUT/include" "$OUTPUT/share/licenses"
WORK="$(mktemp -d "$OUTPUT/.build.XXXXXX")"
cleanup() {
  if [[ -n "${WORK:-}" && -d "$WORK" && "$WORK" == "$OUTPUT"/.build.* ]]; then
    rm -rf -- "$WORK"
  fi
}
trap cleanup EXIT

case "$TOOLCHAIN" in
  host) TARGET_ARCH="$(uname -m)" ;;
  *) TARGET_ARCH=arm ;;
esac

ARCH_FLAGS=()
if [[ "$TARGET_ARCH" == arm ]]; then
  ARCH_FLAGS=(-march=armv7-a -mfpu=neon-vfpv4 -mfloat-abi=hard)
fi
REPRO_FLAGS=(
  "-ffile-prefix-map=$WORK=build"
  "-ffile-prefix-map=$TFLM_SOURCE=tflm-src"
  "-ffile-prefix-map=$FLATBUFFERS_SOURCE=tflm-flatbuffers"
  "-ffile-prefix-map=$KISSFFT_SOURCE=tflm-kissfft"
  "-ffile-prefix-map=$EYALROZ_PRINTF_SOURCE=tflm-eyalroz-printf"
)
COMMON_FLAGS=(
  -Os
  -ffunction-sections
  -fdata-sections
  -fno-unwind-tables
  -fno-asynchronous-unwind-tables
  -fmessage-length=0
  -DTFLM_REMOVE_VIRTUAL_DELETE
  -DTF_LITE_DISABLE_X86_NEON
  -DTF_LITE_USE_CTIME
  -DFLATBUFFERS_LOCALE_INDEPENDENT=0
  -DFLATBUFFERS_PREFER_PRINTF=1
  "${ARCH_FLAGS[@]}"
  "${REPRO_FLAGS[@]}"
)
CXXFLAGS="${COMMON_FLAGS[*]} -fno-rtti -fno-exceptions -fno-threadsafe-statics -std=c++17"
CCFLAGS="${COMMON_FLAGS[*]} -std=c17"

# TFLM's Makefile downloads its third-party dependencies into the source tree
# at parse time. Build from a private copy and place the pinned trees where it
# expects them, so the caller's checkout stays untouched and no network is used.
SRC="$WORK/tflm-src"
mkdir -p "$SRC"
cp -a "$TFLM_SOURCE/." "$SRC/"
DOWNLOADS="$SRC/tensorflow/lite/micro/tools/make/downloads"
mkdir -p "$DOWNLOADS"
cp -a "$FLATBUFFERS_SOURCE/." "$DOWNLOADS/flatbuffers/"
cp -a "$KISSFFT_SOURCE/." "$DOWNLOADS/kissfft/"
cp -a "$EYALROZ_PRINTF_SOURCE/." "$DOWNLOADS/eyalroz_printf/"
patch -s -p1 -N -d "$DOWNLOADS/flatbuffers" \
  <"$TFLM_SOURCE/tensorflow/lite/micro/tools/make/flatbuffers.patch" || {
  echo "ERROR: TFLM flatbuffers patch does not apply to a pristine flatbuffers source" >&2
  exit 1
}
patch -s -p1 -N -d "$DOWNLOADS/kissfft" \
  <"$TFLM_SOURCE/third_party/kissfft/kissfft.patch" || {
  echo "ERROR: TFLM kissfft patch does not apply to a pristine kissfft source" >&2
  exit 1
}
# TFLM's Makefile calls its dependency downloader at parse time. A dependency
# with the stamp its downloader writes is left untouched, so record the stamp
# for every source staged above instead of reaching the network.
python3 - "$SRC" "$DOWNLOADS" <<'PY'
import importlib.util
import json
import sys
from pathlib import Path

root = Path(sys.argv[1])
downloads = Path(sys.argv[2])
script = root / "tensorflow/lite/micro/tools/make/download_dependencies.py"
spec = importlib.util.spec_from_file_location("tflm_download_dependencies", script)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
for name in module.DEFAULT_DEPENDENCIES:
    metadata = module.compute_stamp_metadata(module.DEPENDENCIES[name], root)
    (downloads / name / module.STAMP_FILENAME).write_text(
        json.dumps(metadata, sort_keys=True), encoding="utf-8")
PY

echo "INFO tflm_configure toolchain=$TOOLCHAIN arch=$TARGET_ARCH"
make -C "$SRC" -f tensorflow/lite/micro/tools/make/Makefile \
  -j"$JOBS" \
  TARGET=linux TARGET_ARCH="$TARGET_ARCH" \
  CC_TOOL="$CC" CXX_TOOL="$CXX" AR_TOOL="$AR" \
  ARFLAGS=-rcsD BUILD_TYPE=default \
  DOWNLOADS_DIR="$DOWNLOADS" BASE_GENDIR="$WORK/tflm-gen" \
  CXXFLAGS="$CXXFLAGS" CCFLAGS="$CCFLAGS" \
  microlite
TFLM_GEN_LIB="$(find "$WORK/tflm-gen" -name libtensorflow-microlite.a -print -quit)"
[[ -f "$TFLM_GEN_LIB" ]] || {
  echo "ERROR: TensorFlow Lite Micro archive was not produced" >&2
  exit 1
}
install -m 0644 "$TFLM_GEN_LIB" "$OUTPUT/lib/libtflm-micro.a"

python3 "$GENERATOR" "$OPERATORS_CONFIG" "$WORK/ops"
"$CXX" "${COMMON_FLAGS[@]}" -fno-rtti -fno-exceptions -fno-threadsafe-statics \
  -std=c++17 -O2 \
  -I"$WORK/ops/include" -I"$SRC" -I"$DOWNLOADS/flatbuffers/include" \
  -c "$WORK/ops/src/operators.cc" -o "$WORK/ops/operators.o"
"$AR" rcsD "$OUTPUT/lib/libtflm-micro.a" "$WORK/ops/operators.o"

FRONTEND="$SRC/tensorflow/lite/experimental/microfrontend/lib"
FE_SOURCES=(
  fft.cc fft_util.cc kiss_fft_int16.cc
  filterbank.c filterbank_util.c
  frontend.c frontend_util.c
  log_lut.c log_scale.c log_scale_util.c
  noise_reduction.c noise_reduction_util.c
  pcan_gain_control.c pcan_gain_control_util.c
  window.c window_util.c
)
FE_OBJECTS=()
for name in "${FE_SOURCES[@]}"; do
  object="$WORK/frontend/${name%.*}.o"
  mkdir -p "$(dirname -- "$object")"
  case "$name" in
    *.cc)
      "$CXX" "${COMMON_FLAGS[@]}" -fno-rtti -fno-exceptions \
        -fno-threadsafe-statics -std=c++17 \
        -DFIXED_POINT=16 \
        -I"$SRC" -I"$DOWNLOADS/kissfft" \
        -c "$FRONTEND/$name" -o "$object"
      ;;
    *.c)
      "$CC" "${COMMON_FLAGS[@]}" -std=c17 \
        -DFIXED_POINT=16 \
        -I"$SRC" -I"$DOWNLOADS/kissfft" \
        -c "$FRONTEND/$name" -o "$object"
      ;;
  esac
  FE_OBJECTS+=("$object")
done
"$AR" rcsD "$OUTPUT/lib/libmicrowakeword-frontend.a" "${FE_OBJECTS[@]}"

# Headers a consumer needs: TFLM, the microfrontend, flatbuffers and the
# generated operator interface. Only .h files are installed.
python3 - "$SRC" "$OUTPUT/include" <<'PY'
import shutil
import sys
from pathlib import Path

source = Path(sys.argv[1])
target = Path(sys.argv[2])
roots = [
    source / "tensorflow/lite/micro",
    source / "tensorflow/lite/experimental/microfrontend/lib",
    source / "signal",
]
for root in roots:
    for path in root.rglob("*.h"):
        relative = path.relative_to(source)
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, destination)
PY
mkdir -p "$OUTPUT/include/flatbuffers" "$OUTPUT/include/microwakeword"
cp -a "$DOWNLOADS/flatbuffers/include/flatbuffers/." "$OUTPUT/include/flatbuffers/"
install -m 0644 "$WORK/ops/include/microwakeword/operators.h" \
  "$OUTPUT/include/microwakeword/operators.h"
install -m 0644 "$OPERATORS_CONFIG" \
  "$OUTPUT/share/microwakeword-operators.config"

install -m 0644 "$TFLM_SOURCE/LICENSE" "$OUTPUT/share/licenses/TFLM-LICENSE.txt"
install -m 0644 "$FLATBUFFERS_SOURCE/LICENSE" \
  "$OUTPUT/share/licenses/flatbuffers-LICENSE.txt"
install -m 0644 "$KISSFFT_SOURCE/COPYING" "$OUTPUT/share/licenses/kissfft-COPYING.txt"
install -m 0644 "$EYALROZ_PRINTF_SOURCE/LICENSE" \
  "$OUTPUT/share/licenses/eyalroz-printf-LICENSE.txt"

for archive in libtflm-micro.a libmicrowakeword-frontend.a; do
  file -b "$OUTPUT/lib/$archive" | grep -q 'current ar archive' || {
    echo "ERROR: $archive is not an ar archive" >&2
    exit 1
  }
done
echo "PASS microwakeword_runtime output=$OUTPUT"
sha256sum "$OUTPUT/lib/libtflm-micro.a" "$OUTPUT/lib/libmicrowakeword-frontend.a"
