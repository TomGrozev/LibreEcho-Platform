#!/bin/sh
# Build the mDNS publisher stack otbr-agent's border agent needs.
#
# Usage:
#   OTBR_DEPS_ARCHIVES=<dir> ARM_CC=<gcc> ARM_CXX=<g++> \
#       ./build_otbr_deps.sh <out-prefix>
#
# The archives are the release tarballs named in SOURCE.lock; the script
# verifies their sha256 before unpacking and never fetches on its own.  Every
# library is built static for the armv7 hard-float userspace so that
# otbr-agent, dbus-daemon and avahi-daemon stay self-contained, matching the
# static userspace the image already carries.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PREFIX=${1:?usage: build_otbr_deps.sh <out-prefix>}
ARCHIVES=${OTBR_DEPS_ARCHIVES:?set OTBR_DEPS_ARCHIVES to the pinned source directory}
ARM_CC=${ARM_CC:-arm-linux-gnueabihf-gcc}
ARM_CXX=${ARM_CXX:-arm-linux-gnueabihf-g++}
ARM_HOST=${ARM_HOST:-arm-linux-gnueabihf}
JOBS=${JOBS:-$(nproc)}
WORK=${OTBR_DEPS_WORK:-$(mktemp -d "${TMPDIR:-/tmp}/libreecho-otbr-deps.XXXXXX")}
KEEP_WORK=${OTBR_DEPS_KEEP_WORK:-0}

cleanup() {
    [ "$KEEP_WORK" = 1 ] || rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

expected() {
    python3 - "$HERE/SOURCE.lock" "$1" <<'PY'
import json, sys
document = json.load(open(sys.argv[1]))
for dependency in document["dependencies"]:
    if dependency["name"] == sys.argv[2]:
        print(dependency["source_sha256"])
        break
else:
    sys.exit("missing dependency in SOURCE.lock: " + sys.argv[2])
PY
}

archive() {
    name=$1
    version=$2
    suffix=$3
    path=$ARCHIVES/$name-$version.tar.$suffix
    [ -f "$path" ] || {
        echo "ERROR: missing source archive: $path" >&2
        exit 1
    }
    actual=$(sha256sum "$path" | awk '{print $1}')
    wanted=$(expected "$name")
    [ "$actual" = "$wanted" ] || {
        echo "ERROR: $name source hash mismatch: expected=$wanted actual=$actual" >&2
        exit 1
    }
    tar -C "$WORK" -xf "$path"
    echo "$WORK/$name-$version"
}

# The pinned compiler needs its own runtime libraries on the host search path;
# the target headers and libraries come from --sysroot.
case "$ARM_CC" in
    */*) cc_dir=$(CDPATH= cd -- "$(dirname -- "$ARM_CC")" && pwd) ;;
    *) cc_dir=$(dirname -- "$(command -v "$ARM_CC")") ;;
esac
host_libs=$(CDPATH= cd -- "$cc_dir/../lib/$(uname -m)-linux-gnu" 2>/dev/null && pwd) || host_libs=
export LD_LIBRARY_PATH=${host_libs:+$host_libs}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}

mkdir -p "$PREFIX"
PREFIX=$(CDPATH= cd -- "$PREFIX" && pwd)
mkdir -p "$WORK"
export PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig"
export PKG_CONFIG_LIBDIR="$PREFIX/lib/pkgconfig"
export PATH="$PREFIX/bin:$PATH"
# Several of these sources probe dependencies with AC_CHECK_LIB, which reads
# LDFLAGS/CPPFLAGS and ignores pkg-config; without the prefix on both paths
# avahi's expat probe fails even though expat.pc is installed.
export CPPFLAGS="-I$PREFIX/include${CPPFLAGS:+ $CPPFLAGS}"
export LDFLAGS="-L$PREFIX/lib${LDFLAGS:+ $LDFLAGS}"
COMMON="--host=$ARM_HOST --prefix=$PREFIX --disable-shared --enable-static"

echo "== expat"
src=$(archive expat 2.6.4 xz)
( cd "$src" && ./configure $COMMON --without-docbook --without-examples --without-tests \
    CC="$ARM_CC" CXX="$ARM_CXX" >/dev/null && make -j "$JOBS" >/dev/null && make install >/dev/null )

echo "== libdaemon"
# 0.14's AC_FUNC_SETPGRP runs a program to tell setpgrp(void) from
# setpgrp(pid_t, pid_t); the arm glibc takes no arguments.  AC_FUNC_FORK and
# AC_FUNC_SELECT_ARGTYPES fall back to compile-time defaults when cross
# compiling, so the setpgrp answer is the only run test this source needs.
src=$(archive libdaemon 0.14 gz)
( cd "$src" && ac_cv_func_setpgrp_void=yes ./configure $COMMON --disable-examples --disable-lynx \
    CC="$ARM_CC" CXX="$ARM_CXX" >/dev/null && make -j "$JOBS" >/dev/null && make install >/dev/null )

echo "== dbus"
src=$(archive dbus 1.14.10 xz)
( cd "$src" && ./configure $COMMON \
    --disable-systemd --disable-libaudit --disable-selinux \
    --disable-x11-autolaunch --disable-tests --disable-doxygen-docs \
    --disable-xml-docs --disable-ducktype-docs --disable-verbose-mode \
    --with-xml=expat --without-x \
    --with-system-socket=/run/dbus/system_bus_socket \
    --with-session-socket-dir=/run/dbus \
    CC="$ARM_CC" CXX="$ARM_CXX" >/dev/null && make -j "$JOBS" LDFLAGS="$LDFLAGS -all-static" >/dev/null && make install >/dev/null )

echo "== avahi"
src=$(archive avahi 0.8 gz)
( cd "$src" && ./configure $COMMON \
    --disable-glib --disable-gobject --disable-qt3 --disable-qt4 --disable-qt5 \
    --disable-gtk --disable-gtk3 --disable-python --disable-python-dbus \
    --disable-mono --disable-monodoc --disable-dbm --disable-gdbm \
    --disable-libevent \
    --disable-autoipd --disable-doxygen-doc --disable-doxygen-dot \
    --disable-doxygen-xml --disable-doxygen-html --disable-manpages \
    --disable-xmltoman --with-distro=none --with-xml=expat \
    --with-avahi-user=root --with-avahi-group=root \
    CC="$ARM_CC" CXX="$ARM_CXX" >/dev/null && make -j "$JOBS" LDFLAGS="$LDFLAGS -all-static" >/dev/null && make install >/dev/null )

for library in libexpat.a libdaemon.a libdbus-1.a libavahi-common.a libavahi-client.a; do
    found=$(find "$PREFIX" -name "$library" -print -quit)
    [ -n "$found" ] || { echo "ERROR: $library was not built" >&2; exit 1; }
    # `file` reports an archive as "current ar archive", so prove the target
    # architecture from the first member object instead.
    member=$(ar t "$found" | sed -n '1p')
    probe=$(mktemp "${TMPDIR:-/tmp}/libreecho-otbr-probe.XXXXXX")
    ar p "$found" "$member" > "$probe"
    file "$probe" | grep -q 'ELF 32-bit.*ARM' || {
        echo "ERROR: $library is not an ARM32 archive: $found" >&2
        rm -f "$probe"
        exit 1
    }
    rm -f "$probe"
done
for binary in dbus-daemon avahi-daemon; do
    found=$(find "$PREFIX" -name "$binary" -type f -print -quit)
    [ -n "$found" ] || { echo "ERROR: $binary was not built" >&2; exit 1; }
    file "$found" | grep -q 'ELF 32-bit.*ARM.*statically linked' || {
        echo "ERROR: $binary is not a static ARM32 binary: $found" >&2
        exit 1
    }
    echo "$binary=$found"
done
echo "otbr_deps=$PREFIX"
