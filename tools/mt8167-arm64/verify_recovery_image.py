#!/usr/bin/env python3
"""Independent verifier for the LibreEcho Lidar recovery boot image.

Every check is re-derived from the inputs and the manifest, not read back from
the builder.  The userspace archive checks reuse the MT8163 verifier helpers by
import, so the shared initramfs contract has one implementation.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import lzma
import re
import stat
import struct
import sys
import zlib
from pathlib import Path
from typing import Any, cast

HERE = Path(__file__).resolve().parent
SIBLING = HERE.parent / 'mt8163-arm32'


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise SystemExit(f'ERROR: cannot load {path}')
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _load_sibling(name: str, filename: str):
    saved = {key: sys.modules.get(key)
             for key in ('libreecho_platform_targets', 'generate_boot_envelope')}
    sys.path.insert(0, str(SIBLING))
    try:
        return _load_module(name, SIBLING / filename)
    finally:
        sys.path.remove(str(SIBLING))
        for key, previous in saved.items():
            if previous is None:
                sys.modules.pop(key, None)
            else:
                sys.modules[key] = previous


targets = _load_module('mt8167_platform_targets', HERE / 'libreecho_platform_targets.py')
dtb_contract = _load_module('mt8167_verify_lidar_dtb', HERE / 'verify_lidar_dtb.py')
shared = _load_sibling('mt8163_verify_recovery_image', 'verify_recovery_image.py')

ANDROID_MAGIC = b'ANDROID!'
PAGE_SIZE = 2048
IMAGE_SIZE = 16 * 1024 * 1024
BOOT_HEADER_SIZE = 1632
CMDLINE_OFFSET = 64
CMDLINE_SIZE = 512
EXTRA_CMDLINE_OFFSET = 608
EXTRA_CMDLINE_SIZE = BOOT_HEADER_SIZE - EXTRA_CMDLINE_OFFSET

MKIMG_MAGIC = 0x58881688
MKIMG_SIZE = 512
MKIMG_NAME = b'KERNEL\x00\x00'
MKIMG_FILLER_OFFSET = 0x28

ARM64_MAGIC_OFFSET = 0x38
ARM64_MAGIC = b'ARMd'
ARM64_IMAGE_SIZE_OFFSET = 0x10

KERNEL_ADDR = 0x40080000
RAMDISK_ADDR = 0x44000000
SECOND_ADDR = 0x40F00000
TAGS_ADDR = 0x4E000000
OS_VERSION = 0x0E04119C

STOCK_DTB_COUNT = 19
STOCK_DTB_INDEX = 4
STOCK_PVT_SHA256 = 'b5302d9e4a672e7c2d06624d712746fe61fa30ed59183d85f253cec2775a730f'
STOCK_DTB_COLLECTION_SHA256 = (
    '8f56e981e9273a07b0cf54d09a45b3bd827c9a2b2c20134dc0a5be7393ee7fde'
)
LIDAR_PVT_COMPATIBLE = 'amzn,lidar-pvt'
BOOTOPT_PREFIX = b'bootopt=64S3,32N2,64N2'
PROVEN_STOCK_CMDLINE = (
    b'bootopt=64S3,32N2,64N2 buildvariant=user '
    b'veritykeyid=id:f3530e18f64d11fc25eb2dd762979f078de990bf'
)
FORBIDDEN_CMDLINE = b'lidar.autoreboot'
MAX_DTB_SIZE = 0x80000
RAMDISK_COMPRESSION = 'xz-crc32-lzma2-8m'
INIT_SHA256 = shared.INIT_SHA256
WIFI_PATCH_SHA256 = (
    '465ed634c61b46b34bb21240736f33d3d347fefec7cbfbd1cb6e63334aec4cc9'
)
WIFI_PATCH_SIZE = 170990
WIFI_VENDOR_SPEC = SIBLING / 'initramfs/vendor-assets/lidar-mt7668-stock-v1.tsv'
WIFI_FORBIDDEN_MEMBERS = (
    'lib/firmware/WIFI_RAM_CODE',
    'lib/firmware/WIFI_RAM_CODE_8163',
    'lib/firmware/WMT_SOC.cfg',
)


class VerifyError(RuntimeError):
    """The image, manifest or inputs violate the Lidar contract."""


def fail(message: str) -> None:
    raise VerifyError(message)


def require_member(entries: dict[str, Any], name: str, digest: str,
                   mode: int):
    """The shared helper signals with SystemExit; keep one exception type."""
    try:
        return shared.require_member(entries, name, digest, mode)
    except SystemExit as exc:
        raise VerifyError(str(exc)) from exc


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise VerifyError(f'cannot read {path}: {exc}') from exc


def align(value: int) -> int:
    return (value + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)


def decompress_first_gzip(payload: bytes, label: str) -> tuple[bytes, int]:
    try:
        inflater = zlib.decompressobj(31)
        result = inflater.decompress(payload) + inflater.flush()
    except zlib.error as exc:
        raise VerifyError(f'{label} gzip stream is invalid: {exc}') from exc
    if not inflater.eof:
        raise VerifyError(f'{label} gzip stream is truncated')
    consumed = len(payload) - len(inflater.unused_data)
    if consumed <= 0:
        raise VerifyError(f'{label} gzip stream consumed no bytes')
    return result, consumed


def android_id(kernel: bytes, ramdisk: bytes) -> bytes:
    digest = hashlib.sha1()
    for blob in (kernel, ramdisk, b''):
        digest.update(blob)
        digest.update(struct.pack('<I', len(blob)))
    return digest.digest().ljust(32, b'\0')


def split_dtbs(region: bytes, label: str) -> list[bytes]:
    dtbs: list[bytes] = []
    position = 0
    while position < len(region):
        if len(region) - position < 40:
            fail(f'{label}: trailing bytes after the last appended DTB')
        totalsize = struct.unpack_from('>I', region, position + 4)[0]
        if totalsize < 40 or position + totalsize > len(region):
            fail(f'{label}: appended DTB at {position:#x} has an invalid totalsize')
        blob = region[position:position + totalsize]
        dtb_contract.parse_fdt(blob, f'{label} DTB {len(dtbs)}')
        dtbs.append(blob)
        position += totalsize
    return dtbs


def _cmdline_text(field: bytes, label: str) -> bytes:
    text, terminator, remainder = field.partition(b'\x00')
    if not terminator:
        fail(f'{label} is not NUL-terminated')
    if any(remainder):
        fail(f'{label} has bytes after its NUL terminator')
    return text


def effective_cmdline(cmdline: bytes, extra_cmdline: bytes) -> bytes:
    return _cmdline_text(cmdline, 'cmdline') + _cmdline_text(extra_cmdline, 'extra cmdline')


def expected_cmdline_fields(header: bytes, appends: list[str]) -> tuple[bytes, bytes]:
    combined = (_cmdline_text(header[CMDLINE_OFFSET:CMDLINE_OFFSET + CMDLINE_SIZE], 'cmdline')
                + _cmdline_text(header[EXTRA_CMDLINE_OFFSET:EXTRA_CMDLINE_OFFSET + EXTRA_CMDLINE_SIZE],
                                'extra cmdline'))
    for suffix in appends:
        if not suffix:
            fail('cmdline append suffix is empty')
        encoded = suffix.encode('utf-8')
        if b'\x00' in encoded:
            fail('cmdline append suffix contains a NUL byte')
        combined += b' ' + encoded
    if len(combined) > CMDLINE_SIZE - 1 + EXTRA_CMDLINE_SIZE - 1:
        fail('expected cmdline exceeds the v0 header capacity')
    return (combined[:CMDLINE_SIZE - 1].ljust(CMDLINE_SIZE, b'\x00'),
            (combined[CMDLINE_SIZE - 1:] + b'\x00').ljust(EXTRA_CMDLINE_SIZE, b'\x00'))


def validate_mtk_header(header: bytes, kernel_size: int) -> None:
    if len(header) != MKIMG_SIZE:
        fail('MediaTek header is not 512 bytes')
    magic, size = struct.unpack_from('<II', header, 0)
    if magic != MKIMG_MAGIC:
        fail('MediaTek KERNEL magic missing')
    if size != kernel_size - MKIMG_SIZE:
        fail('MediaTek payload size disagrees with the Android kernel size')
    if header[8:16] != MKIMG_NAME:
        fail('MediaTek KERNEL name is not null-terminated')
    if any(header[16:MKIMG_FILLER_OFFSET]):
        fail('MediaTek header name area is not zero')
    if header[MKIMG_FILLER_OFFSET:] != b'\xff' * (MKIMG_SIZE - MKIMG_FILLER_OFFSET):
        fail('MediaTek header filler is not 0xff')


def validate_kernel_config(path: Path) -> None:
    text = read(path).decode('utf-8', 'replace')
    offenders = [line.strip() for line in text.splitlines()
                 if re.match(r'^\s*CONFIG_LIBREECHO_DEV[A-Z0-9_]*\s*=\s*[ym]\s*$', line)]
    if offenders:
        fail('kernel config enables a development marker: ' + ', '.join(offenders))


def validate_physical(kernel_image: bytes, dtb: bytes, ramdisk_size: int) -> dict[str, Any]:
    if kernel_image[ARM64_MAGIC_OFFSET:ARM64_MAGIC_OFFSET + 4] != ARM64_MAGIC:
        fail('kernel image lacks the ARM64 Image magic')
    image_size = struct.unpack_from('<Q', kernel_image, ARM64_IMAGE_SIZE_OFFSET)[0]
    if image_size < 0x40:
        fail('kernel image_size is invalid')
    kernel_end = KERNEL_ADDR + image_size
    record = dtb_contract.validate_lidar_dtb(dtb, label='Lidar DTB')
    lowest = record['lowest_reserved_memory']
    if lowest is not None and kernel_end > int(lowest):
        fail(f'kernel Image ends at {kernel_end:#x}, above the lowest reserved-memory '
             f'region {int(lowest):#x}')
    if kernel_end >= RAMDISK_ADDR:
        fail('kernel Image overlaps ramdisk_addr')
    ramdisk_end = RAMDISK_ADDR + ramdisk_size
    if ramdisk_end >= TAGS_ADDR:
        fail('ramdisk reaches tags_addr')
    return {'lowest_reserved_memory': None if lowest is None else f'0x{int(lowest):08x}',
            'kernel_end': f'0x{kernel_end:08x}',
            'ramdisk_end': f'0x{ramdisk_end:08x}'}


def load_stock(source: Path, collection: bool, expected_collection: str,
               expected_pvt: str) -> tuple[bytes, list[bytes], str]:
    data = read(source)
    if collection:
        dtbs = split_dtbs(data, 'stock DTB collection')
        header = bytearray(BOOT_HEADER_SIZE)
        header[:8] = ANDROID_MAGIC
        struct.pack_into('<10I', header, 8, 0, KERNEL_ADDR, 0, RAMDISK_ADDR, 0,
                         SECOND_ADDR, TAGS_ADDR, PAGE_SIZE, 0, OS_VERSION)
        header[CMDLINE_OFFSET:CMDLINE_OFFSET + len(PROVEN_STOCK_CMDLINE) + 1] = (
            PROVEN_STOCK_CMDLINE + b'\x00')
        header = bytes(header)
    else:
        if len(data) != IMAGE_SIZE or data[:8] != ANDROID_MAGIC:
            fail('stock boot image is not a 16 MiB Android image')
        fields = struct.unpack_from('<10I', data, 8)
        kernel_size, kernel_addr, _ramdisk_size, ramdisk_addr, second_size, \
            second_addr, tags_addr, page_size, header_version, os_version = fields
        if (kernel_addr, ramdisk_addr, second_addr, tags_addr, page_size,
                header_version, os_version, second_size) != (
                KERNEL_ADDR, RAMDISK_ADDR, SECOND_ADDR, TAGS_ADDR, PAGE_SIZE,
                0, OS_VERSION, 0):
            fail('stock boot header geometry is not the Lidar contract')
        if kernel_size <= MKIMG_SIZE or PAGE_SIZE + kernel_size > IMAGE_SIZE:
            fail('stock kernel section is out of range')
        section = data[PAGE_SIZE:PAGE_SIZE + kernel_size]
        if struct.unpack_from('<I', section, 0)[0] != MKIMG_MAGIC:
            fail('stock kernel section lacks the MediaTek magic')
        _image, consumed = decompress_first_gzip(section[MKIMG_SIZE:], 'stock kernel')
        dtbs = split_dtbs(section[MKIMG_SIZE + consumed:], 'stock kernel')
        header = data[:BOOT_HEADER_SIZE]
    if len(dtbs) != STOCK_DTB_COUNT:
        fail(f'stock source has {len(dtbs)} DTBs, expected {STOCK_DTB_COUNT}')
    if sha256(dtbs[STOCK_DTB_INDEX]) != expected_pvt:
        fail('stock PVT DTB hash mismatch')
    if LIDAR_PVT_COMPATIBLE not in dtb_contract.fdt_compatible(
            dtb_contract.parse_fdt(dtbs[STOCK_DTB_INDEX], 'stock PVT DTB')):
        fail('stock DTB index 4 is not a Lidar PVT tree')
    actual_collection = sha256(b''.join(dtbs))
    if actual_collection != expected_collection:
        fail('stock DTB collection hash mismatch')
    for index, blob in enumerate(dtbs):
        if len(blob) > MAX_DTB_SIZE:
            fail(f'stock DTB {index} exceeds the LK copy cap')
    return header, dtbs, sha256(data)


def _mode(record: object) -> int:
    if not isinstance(record, dict):
        fail('manifest overlay record is not an object')
    text = record.get('mode')
    if not isinstance(text, str):
        fail('manifest overlay record lacks a mode')
    try:
        return int(text, 8)
    except ValueError as exc:
        raise VerifyError('manifest overlay mode is not octal') from exc


THREAD_INIT = 'etc/init.d/libreecho-threadd.init'
THREAD_FILES = ('lidar-efr32', 'otbr-agent')
THREAD_PRIVATE_OWNERS = (
    'usr/local/sbin/dbus-daemon',
    'usr/local/sbin/avahi-daemon',
    'etc/dbus-1/system.conf',
    'etc/avahi/avahi-daemon.conf',
)


def validate_thread(entries: dict[str, Any], manifest: dict[str, Any]) -> None:
    """The Thread border router ships only with the EFR32 radio, and only once.

    otbr-agent must publish through the single platform Avahi/D-Bus responder,
    so a second daemon or daemon config in the same image is a contract
    violation, not an alternative layout.
    """
    raw_thread = manifest.get('thread', {'enabled': False})
    if (not isinstance(raw_thread, dict)
            or not isinstance(raw_thread.get('enabled'), bool)):
        fail('manifest has a malformed thread record')
    thread = cast(dict[str, Any], raw_thread)
    if not thread.get('enabled'):
        if THREAD_INIT in entries:
            fail('the Thread init entry is staged but the manifest disables it')
        return
    if thread.get('activation') != 'thread-radio-only':
        fail('thread runtime activation differs from the contract')
    if thread.get('discovery') != 'shared-avahi-dbus':
        fail('thread runtime must use the shared Avahi/D-Bus responder')
    if thread.get('start_order') != list(THREAD_FILES):
        fail('thread runtime start order differs from the contract')
    files = thread.get('files')
    if not isinstance(files, dict):
        fail('manifest lacks the thread runtime records')
    init = files.get('libreecho-threadd')
    if not isinstance(init, dict):
        fail('manifest lacks the thread init record')
    shared.require_member(entries, THREAD_INIT, str(init.get('sha256')), 0o755)
    for name in THREAD_FILES:
        record = files.get(name)
        if not isinstance(record, dict):
            fail(f'manifest lacks the thread record for {name}')
        digest = str(record.get('sha256'))
        entry = shared.require_member(entries, f'usr/local/sbin/{name}',
                                      digest, 0o755)
        if record.get('size') != len(entry.data):
            fail(f'{name} size differs from the manifest')
        if shared.elf_info(entry.data) != (1, 40, 0x05000400, None, (), False):
            fail(f'{name} is not a static ARM32 hard-float executable')
    for relative in THREAD_PRIVATE_OWNERS:
        if relative in entries:
            fail(f'Thread runtime stages a private mDNS owner: {relative}')


def validate_initramfs(ramdisk: bytes, manifest: dict[str, Any], target: str,
                       digest: str | None, expected: dict[str, Any]) -> None:
    initramfs = manifest.get('initramfs')
    if not isinstance(initramfs, dict):
        fail('manifest lacks the initramfs record')
    if initramfs.get('compression') != RAMDISK_COMPRESSION:
        fail('manifest compression is not the kernel-supported xz contract')
    if initramfs.get('ramdisk_sha256') != sha256(ramdisk):
        fail('ramdisk hash differs from the manifest')
    cpio = shared.decompress_ramdisk(ramdisk)
    if initramfs.get('cpio_sha256') != sha256(cpio):
        fail('decompressed cpio hash differs from the manifest')
    entries = shared.parse_newc(cpio)
    shared.validate_archive_tree(entries)
    shared.validate_symlinks(entries)

    for name, entry in entries.items():
        if not stat.S_ISREG(entry.mode) or entry.data[:4] != b'\x7fELF':
            continue
        info = shared.elf_info(entry.data)
        if info is None:
            continue
        elf_class, machine = info[0], info[1]
        if (elf_class, machine) != (1, 40):
            fail(f'non-ARM32 ELF in initramfs: {name}')

    init_entry = shared.require_member(entries, 'init', INIT_SHA256, 0o755)
    if target == 'lidar':
        # An intact target file with a loader that lacks the lidar case boots
        # without Wi-Fi. Exercise every shipped target parser against this
        # image's own target file.
        try:
            shared.validate_target_identity_parsers(entries, init_entry.data)
        except SystemExit as exc:
            raise VerifyError(str(exc)) from exc
    shared.require_member(entries, 'bin/busybox', expected['busybox'], 0o755)
    shared.require_member(entries, 'lib/ld-musl-armhf.so.1', expected['loader'], 0o755)

    adbd = manifest.get('adbd')
    if not isinstance(adbd, dict):
        fail('manifest lacks the adbd record')
    shared.require_member(entries, 'sbin/adbd', str(adbd.get('sha256')), 0o750)

    ota = manifest.get('ota')
    if not isinstance(ota, dict) or not isinstance(ota.get('tools'), dict):
        fail('manifest lacks OTA tool records')
    for name, pin in (('bootctl', expected['bootctl']),
                      ('verifier', expected['update_verifier'])):
        record = ota['tools'].get(name)
        if not isinstance(record, dict) or record.get('sha256') != pin:
            fail(f'OTA {name} hash differs from the manifest or caller pin')
        path = str(record.get('path', '')).lstrip('/')
        shared.require_member(entries, path, pin, 0o755)

    shared.require_member(entries, 'etc/libreecho/ota-public-key.hex',
                          expected['ota_key'], 0o644)
    shared.require_member(entries, 'etc/libreecho/target',
                          sha256(targets.identity_bytes(target, digest)), 0o644)
    if manifest.get('board') != target or ota.get('board') != target:
        fail('image target manifest mismatch')
    profile = targets.audio_profile_bytes(target)
    audio_record = manifest.get('audio_profile')
    if (not isinstance(audio_record, dict)
            or audio_record.get('sha256') != sha256(profile)
            or audio_record.get('size') != len(profile)):
        fail('manifest audio profile differs from the target renderer')
    audio_entry = require_member(
        entries, 'etc/libreecho/audio-profile', sha256(profile), 0o644)
    if audio_entry.data != profile:
        fail('audio profile differs from the target renderer')
    audio_manifest = manifest.get('audio')
    if not isinstance(audio_manifest, dict) or audio_manifest.get('enabled') is not True:
        fail('manifest does not enable the staged audio profile')

    wifi = manifest.get('wifi_firmware')
    if not isinstance(wifi, dict) or not isinstance(wifi.get('files'), dict):
        fail('manifest lacks the Wi-Fi firmware records')
    patch = wifi.get('patch')
    if (not isinstance(patch, dict)
            or patch.get('sha256') != WIFI_PATCH_SHA256
            or patch.get('size') != WIFI_PATCH_SIZE):
        fail('manifest does not pin the linux-firmware MT7668 patch')
    spec = read(WIFI_VENDOR_SPEC)
    expected_files = {
        'lib/firmware/mediatek/mt7668pr2h.bin': WIFI_PATCH_SHA256,
        'lib/firmware/mt7668_patch_e2_hdr.bin': WIFI_PATCH_SHA256,
        'lib/firmware/LICENCE.mediatek': None,
        'etc/libreecho/vendor-assets/lidar-mt7668-stock-v1.tsv': sha256(spec),
    }
    for relative, digest in expected_files.items():
        record = wifi['files'].get(relative)
        if not isinstance(record, dict):
            fail(f'manifest lacks the Wi-Fi record for {relative}')
        if digest is not None and record.get('sha256') != digest:
            fail(f'Wi-Fi member {relative} differs from the pinned bytes')
        member = require_member(
            entries, relative, str(record.get('sha256')), 0o644)
        if record.get('size') != len(member.data):
            fail(f'Wi-Fi member {relative} size differs from the manifest')
        if relative.endswith('mt7668pr2h.bin') or \
                relative.endswith('mt7668_patch_e2_hdr.bin'):
            if len(member.data) != WIFI_PATCH_SIZE or \
                    sha256(member.data) != WIFI_PATCH_SHA256:
                fail(f'Wi-Fi patch member {relative} is not the pinned blob')
        if relative.endswith('LICENCE.mediatek') and not member.data:
            fail('Wi-Fi licence member is empty')
    for name in entries:
        base = name.rsplit('/', 1)[-1]
        if name in WIFI_FORBIDDEN_MEMBERS or (
                name.startswith('lib/firmware/') and base.startswith('ROMv2_')):
            fail(f'MT8163 Wi-Fi member in a Lidar image: {name}')

    network = manifest.get('network')
    if network is not None:
        if not isinstance(network, dict) or not isinstance(
                network.get('wpa_supplicant'), dict):
            fail('manifest has a malformed network record')
        supplicant = network['wpa_supplicant']
        pin = expected.get('wpa_supplicant')
        digest = str(supplicant.get('sha256'))
        if pin is not None and digest != pin:
            fail('wpa_supplicant hash differs from the caller pin')
        entry = require_member(entries, 'sbin/wpa_supplicant', digest, 0o755)
        if supplicant.get('size') != len(entry.data):
            fail('wpa_supplicant size differs from the manifest')
        info = shared.elf_info(entry.data)
        if info != (1, 40, 0x05000400, None, (), False):
            fail(f'wpa_supplicant is not a static ARM32 hard-float executable: {info!r}')
    elif expected.get('wpa_supplicant') is not None:
        fail('a wpa_supplicant pin was given but the image stages none')

    validate_thread(entries, manifest)

    for relative, text in (
        ('etc/libreecho/image-profile', expected['image_profile'] + '\n'),
        ('etc/libreecho/service-profile', expected['service_profile'] + '\n'),
        ('etc/libreecho/feature-policy', expected['feature_policy'] + '\n'),
        ('etc/libreecho/update-channel', expected['update_channel'] + '\n'),
        ('etc/libreecho/first-install-confirm',
         f'schema=1\nmode=first-install\nboard={target}\n'),
    ):
        entry = shared.require_member(entries, relative,
                                      sha256(text.encode()), 0o644)
        if entry.data != text.encode():
            fail(f'{relative} content differs from the expected text')

    # The shared checks report contract violations with SystemExit; this
    # verifier keeps one exception type for every rejection.
    try:
        shared.validate_ui(
            entries, manifest, expected.get('ui_manifest'),
            expected.get('ui_commit'), expected.get('ui_diff_sha256'),
        )
        shared.validate_mdns(
            entries, manifest, expected.get('mdns_manifest'),
            expected['service_profile'],
        )
    except SystemExit as exc:
        raise VerifyError(str(exc)) from exc

    overlay = manifest.get('overlay')
    if not isinstance(overlay, dict):
        fail('manifest lacks the overlay record')
    for source_key, staged in shared.OVERLAY_TARGETS.items():
        record = overlay.get(source_key)
        if not isinstance(record, dict):
            fail(f'manifest lacks the overlay record for {source_key}')
        shared.require_member(entries, staged, str(record.get('sha256')),
                              _mode(record))
    default_prop = overlay.get('default.prop')
    if not isinstance(default_prop, dict):
        fail('manifest lacks the default.prop record')
    shared.require_member(entries, 'default.prop', str(default_prop.get('sha256')),
                          _mode(default_prop))

    symlinks = manifest.get('symlinks')
    if not isinstance(symlinks, dict):
        fail('manifest lacks the symlink record')
    for name, target_name in symlinks.items():
        entry = entries.get(name)
        if entry is None or not stat.S_ISLNK(entry.mode):
            fail(f'initramfs lacks symlink {name}')
        if entry.data.decode('utf-8', 'replace') != target_name:
            fail(f'initramfs symlink {name} differs from the manifest')

    applets = manifest.get('busybox_applets')
    if not isinstance(applets, dict) or not isinstance(applets.get('names'), list):
        fail('manifest lacks the BusyBox applet inventory')
    names = applets['names']
    if applets.get('count') != len(names) or len(names) < 250:
        fail('BusyBox applet inventory is inconsistent or short')
    for applet in names:
        entry = entries.get(f'bin/{applet}')
        if entry is None or not stat.S_ISLNK(entry.mode):
            fail(f'initramfs lacks BusyBox applet link bin/{applet}')
        if entry.data != b'busybox':
            fail(f'BusyBox applet link bin/{applet} has the wrong target')

    ota_source = entries.get('etc/libreecho/ota-source.conf')
    if ota_source is None:
        fail('initramfs lacks ota-source.conf')
    text = ota_source.data.decode('utf-8', 'replace')
    record = targets.get_target(target)
    if f'channel={expected["update_channel"]}' not in text.splitlines():
        fail('ota-source.conf channel differs from the manifest')
    if f'libreecho-{record["release_slug"]}-{expected["update_channel"]}.ota.tar' not in text:
        fail('ota-source.conf URL does not name this target release')


def verify_image(stock: Path, collection: bool, kernel_image: Path, dtb: Path,
                 ramdisk: Path, manifest_path: Path, boot_image: Path,
                 expected_boot_sha256: str, expected_dtb_sha256: str,
                 appends: list[str], expected: dict[str, Any],
                 target: str, digest: str | None) -> dict[str, Any]:
    header, stock_dtbs, stock_sha = load_stock(
        stock, collection, expected['stock_collection'], expected['stock_pvt'])
    kernel = read(kernel_image)
    dtb_data = read(dtb)
    ramdisk_data = read(ramdisk)
    boot = read(boot_image)
    manifest = json.loads(read(manifest_path).decode())
    if not isinstance(manifest, dict):
        fail('manifest is not a JSON object')
    if manifest.get('status') != 'PREPARED_NOT_FLASHED':
        fail('manifest deployment status changed')
    if sha256(boot) != expected_boot_sha256:
        fail('boot image hash differs from the caller pin')
    if manifest.get('output', {}).get('sha256') != expected_boot_sha256:
        fail('manifest boot image hash differs from the caller pin')
    if sha256(dtb_data) != expected_dtb_sha256:
        fail('Lidar DTB hash differs from the caller pin')

    if len(boot) != IMAGE_SIZE or boot[:8] != ANDROID_MAGIC:
        fail('boot image is not the 16 MiB Android v0 envelope')
    fields = struct.unpack_from('<10I', boot, 8)
    (kernel_size, kernel_addr, ramdisk_size, ramdisk_addr, second_size,
     second_addr, tags_addr, page_size, header_version, os_version) = fields
    if (kernel_addr, ramdisk_addr, second_addr, tags_addr, page_size,
            header_version, os_version, second_size) != (
            KERNEL_ADDR, RAMDISK_ADDR, SECOND_ADDR, TAGS_ADDR, PAGE_SIZE,
            0, OS_VERSION, 0):
        fail('Android header geometry is not the Lidar contract')
    if boot[48:64] != header[48:64]:
        fail('boot header name differs from the stock source')
    expected_cmdline, expected_extra = expected_cmdline_fields(header, appends)
    if boot[CMDLINE_OFFSET:CMDLINE_OFFSET + CMDLINE_SIZE] != expected_cmdline:
        fail('boot cmdline differs from the stock source and appends')
    if boot[EXTRA_CMDLINE_OFFSET:EXTRA_CMDLINE_OFFSET + EXTRA_CMDLINE_SIZE] != expected_extra:
        fail('boot extra cmdline differs from the stock source and appends')
    combined = effective_cmdline(expected_cmdline, expected_extra)
    if not combined.startswith(BOOTOPT_PREFIX):
        fail('cmdline does not select the AArch64 handover')
    if FORBIDDEN_CMDLINE in combined:
        fail('cmdline carries lidar.autoreboot')

    kernel_section = boot[PAGE_SIZE:PAGE_SIZE + kernel_size]
    validate_mtk_header(kernel_section[:MKIMG_SIZE], kernel_size)
    payload = kernel_section[MKIMG_SIZE:]
    output_kernel, gzip_size = decompress_first_gzip(payload, 'output kernel')
    if output_kernel != kernel:
        fail('output kernel payload does not match --kernel-image')
    dtbs = split_dtbs(payload[gzip_size:], 'output kernel')
    if len(dtbs) != len(stock_dtbs):
        fail('output appended DTB count differs from stock')
    packed_dtb = dtb_contract.set_chosen_initrd(dtb_data, ramdisk_addr,
                                                ramdisk_size, 'Lidar DTB')
    for index, (actual, stock_dtb) in enumerate(zip(dtbs, stock_dtbs)):
        if len(actual) > MAX_DTB_SIZE:
            fail(f'output DTB {index} exceeds the LK copy cap')
        if index == STOCK_DTB_INDEX:
            if actual != packed_dtb:
                fail('output DTB index 4 is not the Lidar DTB plus initrd properties')
            dtb_contract.validate_chosen_initrd(
                dtb_contract.parse_fdt(actual, 'output DTB index 4'),
                ramdisk_addr, ramdisk_size, 'output DTB index 4')
            compatible = dtb_contract.validate_board_compatible(
                dtb_contract.parse_fdt(actual, 'output DTB index 4'), 'output DTB index 4')
            if LIDAR_PVT_COMPATIBLE not in compatible:
                fail('output DTB index 4 is not a Lidar PVT tree')
        elif actual != stock_dtb:
            fail(f'output DTB index {index} changed from stock')
    collection_data = payload[gzip_size:]

    ramdisk_offset = PAGE_SIZE + align(kernel_size)
    ramdisk_end = ramdisk_offset + ramdisk_size
    trailer_offset = ramdisk_offset + align(ramdisk_size)
    if ramdisk_end > IMAGE_SIZE or trailer_offset > IMAGE_SIZE:
        fail('ramdisk section exceeds the 16 MiB envelope')
    actual_ramdisk = boot[ramdisk_offset:ramdisk_end]
    if actual_ramdisk != ramdisk_data:
        fail('boot ramdisk is not byte-identical to --ramdisk')
    if any(boot[PAGE_SIZE + kernel_size:ramdisk_offset]):
        fail('kernel page padding is nonzero')
    if any(boot[ramdisk_end:trailer_offset]):
        fail('ramdisk page padding is nonzero')
    if any(boot[trailer_offset:]):
        fail('trailer is not zero; a signature may be retained')
    if boot[576:608] != android_id(kernel_section, actual_ramdisk):
        fail('Android v0 id does not match the sections')

    physical = validate_physical(kernel, dtb_data, ramdisk_size)
    validate_initramfs(ramdisk_data, manifest, target, digest, expected)

    record = manifest.get('package')
    if not isinstance(record, dict):
        fail('manifest lacks the package record')
    budget = record.get('size_budget')
    expected_budget = {
        'gzip_kernel_bytes': gzip_size,
        'dtb_collection_bytes': len(collection_data),
        'ramdisk_bytes': ramdisk_size,
        'used_bytes': trailer_offset,
        'margin_to_16mib_bytes': IMAGE_SIZE - trailer_offset,
    }
    if not isinstance(budget, dict):
        fail('manifest lacks the size budget')
    for key, value in expected_budget.items():
        if budget.get(key) != value:
            fail(f'manifest size budget {key} is {budget.get(key)!r}, expected {value}')
    if record.get('cmdline') != combined.decode('utf-8'):
        fail('manifest cmdline differs from the image')
    mtk = record.get('mtk')
    if not isinstance(mtk, dict) or mtk.get('gzip_kernel_size') != gzip_size:
        fail('manifest gzip kernel size differs from the image')
    if mtk.get('gzip_kernel_sha256') != sha256(payload[:gzip_size]):
        fail('manifest gzip kernel hash differs from the image')
    if record.get('dtb', {}).get('packed_dtb_sha256') != sha256(dtbs[STOCK_DTB_INDEX]):
        fail('manifest packed DTB hash differs from the image')
    if record.get('memory', {}).get('lowest_reserved_memory') != physical['lowest_reserved_memory']:
        fail('manifest reserved-memory result differs from the DTB')

    return {
        'stock_sha256': stock_sha,
        'cmdline': combined.decode('utf-8'),
        'size_budget': expected_budget,
        'physical': physical,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description='Verify a LibreEcho Lidar recovery image.')
    stock = parser.add_mutually_exclusive_group(required=True)
    stock.add_argument('--stock-boot', type=Path)
    stock.add_argument('--stock-dtb-collection', type=Path)
    parser.add_argument('--expected-stock-dtb-collection-sha256',
                        default=STOCK_DTB_COLLECTION_SHA256)
    parser.add_argument('--expected-stock-pvt-sha256', default=STOCK_PVT_SHA256)
    parser.add_argument('--kernel-image', type=Path, required=True)
    parser.add_argument('--kernel-config', type=Path, required=True)
    parser.add_argument('--dtb', type=Path, required=True)
    parser.add_argument('--expected-dtb-sha256', required=True)
    parser.add_argument('--ramdisk', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--boot-image', type=Path, required=True)
    parser.add_argument('--expected-boot-sha256', required=True)
    parser.add_argument('--cmdline-append', action='append', default=[])
    parser.add_argument('--expected-busybox-sha256', required=True)
    parser.add_argument('--expected-musl-loader-sha256', required=True)
    parser.add_argument('--expected-bootctl-sha256', required=True)
    parser.add_argument('--expected-update-verifier-sha256', required=True)
    parser.add_argument('--expected-ota-public-key-sha256', required=True)
    parser.add_argument('--expected-ui-manifest-sha256',
                        help='require this pinned LibreEcho-UI file manifest')
    parser.add_argument('--expected-ui-commit',
                        help='require this LibreEcho-UI source commit')
    parser.add_argument('--expected-ui-diff-sha256',
                        help='require this LibreEcho-UI source diff identity')
    parser.add_argument('--expected-mdns-runtime-manifest-sha256',
                        help='require this shared mDNS runtime manifest hash when '
                             'the boot-contained discovery runtime is staged')
    parser.add_argument('--expected-wpa-supplicant-sha256',
                        help='require this staged static ARM32 wpa_supplicant')
    parser.add_argument('--image-profile', choices=('development', 'ota'), required=True)
    parser.add_argument('--service-profile', choices=('diagnostic', 'production'),
                        required=True)
    parser.add_argument('--feature-policy',
                        choices=('exclude', 'preserve', 'redistributable',
                                 'community-noncommercial'),
                        required=True)
    parser.add_argument('--update-channel', choices=('dev', 'stable'), required=True)
    targets.add_target_arguments(parser)
    args = parser.parse_args()
    targets.validate_target_arguments(parser, args)
    validate_kernel_config(args.kernel_config)

    expected = {
        'busybox': args.expected_busybox_sha256,
        'loader': args.expected_musl_loader_sha256,
        'bootctl': args.expected_bootctl_sha256,
        'update_verifier': args.expected_update_verifier_sha256,
        'ota_key': args.expected_ota_public_key_sha256,
        'ui_manifest': args.expected_ui_manifest_sha256,
        'ui_commit': args.expected_ui_commit,
        'ui_diff_sha256': args.expected_ui_diff_sha256,
        'mdns_manifest': args.expected_mdns_runtime_manifest_sha256,
        'image_profile': args.image_profile,
        'service_profile': args.service_profile,
        'feature_policy': args.feature_policy,
        'update_channel': args.update_channel,
        'wpa_supplicant': args.expected_wpa_supplicant_sha256,
        'stock_collection': args.expected_stock_dtb_collection_sha256,
        'stock_pvt': args.expected_stock_pvt_sha256,
    }
    result = verify_image(
        args.stock_boot or args.stock_dtb_collection,
        args.stock_boot is None,
        args.kernel_image, args.dtb, args.ramdisk, args.manifest,
        args.boot_image, args.expected_boot_sha256, args.expected_dtb_sha256,
        args.cmdline_append, expected, args.target,
        args.target_descriptor_sha256,
    )
    budget = result['size_budget']
    print('lidar_recovery_image_contract=PASS android_v0=yes mtk_wrapper=yes '
          'arm64_kernel=yes lidar_dtb=yes initramfs_arm32=yes '
          f'image_profile={args.image_profile} service_profile={args.service_profile} '
          f'feature_policy={args.feature_policy} ota=yes '
          f'gzip_kernel_bytes={budget["gzip_kernel_bytes"]} '
          f'dtb_collection_bytes={budget["dtb_collection_bytes"]} '
          f'ramdisk_bytes={budget["ramdisk_bytes"]} '
          f'margin_to_16mib_bytes={budget["margin_to_16mib_bytes"]} '
          'status=PREPARED_NOT_FLASHED')


if __name__ == '__main__':
    try:
        main()
    except (VerifyError, dtb_contract.ContractError) as error:
        raise SystemExit(f'ERROR: {error}') from error
