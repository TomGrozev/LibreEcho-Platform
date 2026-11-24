#!/bin/sh
# Build otbr-agent from the pinned source for the armv7 userspace.
#
# Usage:
#   OT_BR_SRC=<checkout> OTBR_DEPS=<prefix> ARM_CC=<gcc> ./build_otbr.sh <out-dir>
#
# OT_BR_SRC must be a checkout of the commit in SOURCE.lock with its
# third_party submodules present (`git submodule update --init --recursive`).
# OTBR_DEPS is the prefix build_otbr_deps.sh produced: static D-Bus and Avahi
# for the border agent's mDNS publisher.
# The script never fetches on its own: the release input lock owns the bytes.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OUT=${1:?usage: build_otbr.sh <out-dir>}
SRC=${OT_BR_SRC:?set OT_BR_SRC to the pinned ot-br-posix checkout}
DEPS=${OTBR_DEPS:?set OTBR_DEPS to the build_otbr_deps.sh prefix}
ARM_CC=${ARM_CC:-arm-linux-gnueabihf-gcc}
ARM_CXX=${ARM_CXX:-arm-linux-gnueabihf-g++}
JOBS=${JOBS:-$(nproc)}
for library in libavahi-client.a libavahi-common.a libdbus-1.a; do
    [ -f "$DEPS/lib/$library" ] || {
        echo "ERROR: $DEPS/lib/$library is missing; run build_otbr_deps.sh" >&2
        exit 1
    }
done
# Never let the host pkg-config leak libsystemd (or any other host library)
# into the ARM32 link; only the dependency prefix the border agent needs is
# visible, and the cross sysroot has no systemd.
export PKG_CONFIG_LIBDIR=${PKG_CONFIG_LIBDIR:-$DEPS/lib/pkgconfig}
export PKG_CONFIG_PATH=$DEPS/lib/pkgconfig

expected=$(sed -n 's/.*"commit": "\([0-9a-f]\{40\}\)".*/\1/p' "$HERE/SOURCE.lock")
actual=$(git -C "$SRC" rev-parse HEAD)
[ "$expected" = "$actual" ] || {
    echo "ERROR: ot-br-posix is at $actual, SOURCE.lock pins $expected" >&2
    exit 1
}

mkdir -p "$OUT"
# Ninja is faster where the host has it, but it is not in the build host's
# package baseline (build/ci/provision-host.sh), so a host without it failed
# the configure outright. Fall back to CMake's default generator (Unix
# Makefiles) instead of requiring a tool the baseline never promised.
if command -v ninja >/dev/null 2>&1; then
    set -- -G Ninja
else
    set --
fi
cmake -S "$SRC" -B "$OUT" "$@" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
    -DOT_READLINE=OFF \
    -DCMAKE_C_COMPILER="$ARM_CC" \
    -DCMAKE_CXX_COMPILER="$ARM_CXX" \
    -DCMAKE_C_FLAGS="-march=armv7-a -mfloat-abi=hard -mfpu=vfpv3-d16 -I$DEPS/include -Wno-maybe-uninitialized -Wno-stringop-overflow -Wno-array-bounds -Wno-error" \
    -DCMAKE_CXX_FLAGS="-march=armv7-a -mfloat-abi=hard -mfpu=vfpv3-d16 -I$DEPS/include -Wno-maybe-uninitialized -Wno-stringop-overflow -Wno-array-bounds -Wno-error" \
    -DCMAKE_EXE_LINKER_FLAGS="-static -L$DEPS/lib" \
    -DCMAKE_C_STANDARD_LIBRARIES="-lavahi-client -lavahi-common -ldbus-1 -lexpat -ldaemon -lpthread -lrt -ldl" \
    -DCMAKE_CXX_STANDARD_LIBRARIES="-lavahi-client -lavahi-common -ldbus-1 -lexpat -ldaemon -lpthread -lrt -ldl" \
    -DBUILD_TESTING=OFF \
    -DOTBR_BORDER_AGENT=ON \
    -DOTBR_BORDER_ROUTING=OFF \
    -DOTBR_DBUS=OFF \
    -DOTBR_MDNS=avahi \
    -DOTBR_NOTIFY_UPSTART=OFF \
    -DOTBR_REST=OFF \
    -DOTBR_WEB=OFF \
    -DOT_REFERENCE_DEVICE=OFF
cmake --build "$OUT" --target otbr-agent ot-ctl -j "$JOBS"
file "$OUT/src/agent/otbr-agent"
echo "otbr_agent=$OUT/src/agent/otbr-agent"
