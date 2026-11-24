#!/bin/sh
# Build otbr-agent from the pinned source for the armv7 userspace.
#
# Usage:
#   OT_BR_SRC=<checkout> ARM_CC=<arm-linux-gnueabihf-gcc> ./build_otbr.sh <out-dir>
#
# OT_BR_SRC must be a checkout of the commit in SOURCE.lock with its
# third_party submodules present (`git submodule update --init --recursive`).
# The script never fetches on its own: the release input lock owns the bytes.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OUT=${1:?usage: build_otbr.sh <out-dir>}
SRC=${OT_BR_SRC:?set OT_BR_SRC to the pinned ot-br-posix checkout}
ARM_CC=${ARM_CC:-arm-linux-gnueabihf-gcc}
ARM_CXX=${ARM_CXX:-arm-linux-gnueabihf-g++}
JOBS=${JOBS:-$(nproc)}

expected=$(sed -n 's/.*"commit": "\([0-9a-f]\{40\}\)".*/\1/p' "$HERE/SOURCE.lock")
actual=$(git -C "$SRC" rev-parse HEAD)
[ "$expected" = "$actual" ] || {
    echo "ERROR: ot-br-posix is at $actual, SOURCE.lock pins $expected" >&2
    exit 1
}

mkdir -p "$OUT"
cmake -S "$SRC" -B "$OUT" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER="$ARM_CC" \
    -DCMAKE_CXX_COMPILER="$ARM_CXX" \
    -DCMAKE_C_FLAGS="-march=armv7-a -mfloat-abi=hard -mfpu=vfpv3-d16" \
    -DCMAKE_CXX_FLAGS="-march=armv7-a -mfloat-abi=hard -mfpu=vfpv3-d16" \
    -DCMAKE_EXE_LINKER_FLAGS="-static-libstdc++ -static-libgcc" \
    -DBUILD_TESTING=OFF \
    -DOTBR_BORDER_AGENT=ON \
    -DOTBR_BORDER_ROUTING=OFF \
    -DOTBR_DBUS=OFF \
    -DOTBR_MDNS=OFF \
    -DOTBR_REST=OFF \
    -DOTBR_WEB=OFF \
    -DOT_REFERENCE_DEVICE=OFF
cmake --build "$OUT" --target otbr-agent ot-ctl -j "$JOBS"
file "$OUT/src/agent/otbr-agent"
echo "otbr_agent=$OUT/src/agent/otbr-agent"
