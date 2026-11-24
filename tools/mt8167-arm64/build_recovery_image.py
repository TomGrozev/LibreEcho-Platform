#!/usr/bin/env python3
"""Build the LibreEcho Lidar recovery boot image.

The kernel side follows the proven boot envelope: a raw ARM64 Image inside a
deterministic gzip stream, the 19 stock appended DTBs with index 4 replaced by
ours, and a MediaTek KERNEL wrapper.  The userspace side is the shared ARM32
initramfs from ``tools/mt8163-arm32``, imported rather than copied.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import lzma
import os
import re
import shutil
import struct
import sys
import tempfile
import zlib
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

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
    """Load a shared MT8163 tool without leaving its imports in sys.modules.

    Both profiles have a module named ``libreecho_platform_targets`` and the
    MT8163 verifier has the same filename as this one.  Loading the sibling by
    path and restoring the plain module names keeps each profile's table.
    """
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
shared = _load_sibling('mt8163_build_recovery_image', 'build_recovery_image.py')

ANDROID_MAGIC = b'ANDROID!'
PAGE_SIZE = 2048
IMAGE_SIZE = 16 * 1024 * 1024
BOOT_HEADER_SIZE = 1632
CMDLINE_OFFSET = 64
CMDLINE_SIZE = 512
EXTRA_CMDLINE_OFFSET = 608
EXTRA_CMDLINE_SIZE = BOOT_HEADER_SIZE - EXTRA_CMDLINE_OFFSET
MAX_CMDLINE_TEXT = CMDLINE_SIZE - 1 + EXTRA_CMDLINE_SIZE - 1

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
# The stock boot_a header carries this exact command line; when only the
# appended DTB collection is supplied the builder reuses it verbatim so the
# stock bootopt and verity key id stay unchanged.
PROVEN_STOCK_CMDLINE = (
    b'bootopt=64S3,32N2,64N2 buildvariant=user '
    b'veritykeyid=id:f3530e18f64d11fc25eb2dd762979f078de990bf'
)
FORBIDDEN_CMDLINE = b'lidar.autoreboot'
MAX_DTB_SIZE = 0x80000
RAMDISK_COMPRESSION = 'xz-crc32-lzma2-8m'
# The redistributable linux-firmware MT7668 ROM patch.  Both drivers request
# the same bytes, one under the MediaTek directory and btmtksdio at the top.
WIFI_PATCH_SHA256 = (
    '465ed634c61b46b34bb21240736f33d3d347fefec7cbfbd1cb6e63334aec4cc9'
)
WIFI_PATCH_SIZE = 170990
WIFI_VENDOR_SPEC = SIBLING / 'initramfs/vendor-assets/lidar-mt7668-stock-v1.tsv'


class BuildError(RuntimeError):
    """An input does not satisfy the proven Lidar envelope."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read(path: Path) -> bytes:
    try:
        return path.read_bytes()
    except OSError as exc:
        raise BuildError(f'cannot read {path}: {exc}') from exc


def require_hash(label: str, data: bytes, expected: str) -> None:
    actual = sha256(data)
    if actual != expected:
        raise BuildError(f'{label} SHA-256 mismatch: expected {expected}, got {actual}')


def align(value: int, size: int = PAGE_SIZE) -> int:
    return (value + size - 1) & ~(size - 1)


def gzip_deterministic(data: bytes) -> bytes:
    deflater = zlib.compressobj(9, zlib.DEFLATED, -15, 9, zlib.Z_DEFAULT_STRATEGY)
    body = deflater.compress(data) + deflater.flush()
    header = b'\x1f\x8b\x08\x00' + struct.pack('<I', 0) + b'\x02\xff'
    trailer = struct.pack('<II', zlib.crc32(data) & 0xFFFFFFFF, len(data) & 0xFFFFFFFF)
    return header + body + trailer


def decompress_first_gzip(payload: bytes, label: str) -> tuple[bytes, int]:
    try:
        inflater = zlib.decompressobj(31)
        result = inflater.decompress(payload) + inflater.flush()
    except zlib.error as exc:
        raise BuildError(f'{label} gzip stream is invalid: {exc}') from exc
    if not inflater.eof:
        raise BuildError(f'{label} gzip stream is truncated')
    consumed = len(payload) - len(inflater.unused_data)
    if consumed <= 0:
        raise BuildError(f'{label} gzip stream consumed no bytes')
    return result, consumed


def android_id(kernel: bytes, ramdisk: bytes) -> bytes:
    digest = hashlib.sha1()
    digest.update(kernel)
    digest.update(struct.pack('<I', len(kernel)))
    digest.update(ramdisk)
    digest.update(struct.pack('<I', len(ramdisk)))
    digest.update(struct.pack('<I', 0))
    return digest.digest().ljust(32, b'\0')


def validate_arm64_image(data: bytes, label: str) -> int:
    if len(data) < ARM64_IMAGE_SIZE_OFFSET + 8:
        raise BuildError(f'{label} is shorter than the ARM64 Image header')
    if data[ARM64_MAGIC_OFFSET:ARM64_MAGIC_OFFSET + 4] != ARM64_MAGIC:
        raise BuildError(f'{label} lacks the ARM64 Image magic at 0x38')
    image_size = struct.unpack_from('<Q', data, ARM64_IMAGE_SIZE_OFFSET)[0]
    if image_size < 0x40:
        raise BuildError(f'{label} header image_size {image_size:#x} is invalid')
    return image_size


def mtk_header(payload_size: int, template: bytes | None = None) -> bytes:
    if template is None:
        header = bytearray(MKIMG_SIZE)
        struct.pack_into('<II', header, 0, MKIMG_MAGIC, payload_size)
        header[8:16] = MKIMG_NAME
        header[MKIMG_FILLER_OFFSET:] = b'\xff' * (MKIMG_SIZE - MKIMG_FILLER_OFFSET)
    else:
        if len(template) != MKIMG_SIZE:
            raise BuildError('stock MediaTek header is not 512 bytes')
        header = bytearray(template)
        struct.pack_into('<I', header, 4, payload_size)
    validate_mtk_header(bytes(header), MKIMG_SIZE + payload_size)
    return bytes(header)


def validate_mtk_header(header: bytes, kernel_size: int) -> None:
    if len(header) != MKIMG_SIZE:
        raise BuildError('MediaTek header is not 512 bytes')
    magic, size = struct.unpack_from('<II', header, 0)
    if magic != MKIMG_MAGIC:
        raise BuildError(f'unexpected MediaTek magic {magic:#x}')
    if size != kernel_size - MKIMG_SIZE:
        raise BuildError('MediaTek payload size does not match the kernel section')
    if header[8:16] != MKIMG_NAME:
        raise BuildError('MediaTek kernel name is not KERNEL with a NUL')
    if any(header[16:MKIMG_FILLER_OFFSET]):
        raise BuildError('MediaTek header name area is not zero')
    if header[MKIMG_FILLER_OFFSET:] != b'\xff' * (MKIMG_SIZE - MKIMG_FILLER_OFFSET):
        raise BuildError('MediaTek header filler is not 0xff')


def _cmdline_text(field: bytes, label: str) -> bytes:
    text, terminator, remainder = field.partition(b'\x00')
    if not terminator:
        raise BuildError(f'{label} is not NUL-terminated')
    if any(remainder):
        raise BuildError(f'{label} has bytes after its NUL terminator')
    return text


def effective_cmdline(cmdline: bytes, extra_cmdline: bytes) -> bytes:
    return cmdline.split(b'\x00', 1)[0] + extra_cmdline.split(b'\x00', 1)[0]


def append_cmdline(cmdline: bytes, extra_cmdline: bytes,
                   suffixes: Sequence[str]) -> tuple[bytes, bytes]:
    combined = _cmdline_text(cmdline, 'cmdline') + _cmdline_text(extra_cmdline, 'extra_cmdline')
    for suffix in suffixes:
        if not suffix:
            raise BuildError('cmdline append suffix is empty')
        encoded = suffix.encode('utf-8')
        if b'\x00' in encoded:
            raise BuildError('cmdline append suffix contains a NUL byte')
        combined += b' ' + encoded
    if len(combined) > MAX_CMDLINE_TEXT:
        raise BuildError(f'cmdline overflows the boot header: {len(combined)} > '
                         f'{MAX_CMDLINE_TEXT} bytes')
    return (combined[:CMDLINE_SIZE - 1].ljust(CMDLINE_SIZE, b'\x00'),
            (combined[CMDLINE_SIZE - 1:] + b'\x00').ljust(EXTRA_CMDLINE_SIZE, b'\x00'))


def validate_cmdline(cmdline: bytes, extra_cmdline: bytes) -> bytes:
    combined = effective_cmdline(cmdline, extra_cmdline)
    if not combined.startswith(BOOTOPT_PREFIX):
        raise BuildError(f'cmdline must open with {BOOTOPT_PREFIX.decode()}, '
                         f'got {combined[:32]!r}')
    if FORBIDDEN_CMDLINE in combined:
        raise BuildError('cmdline must not carry lidar.autoreboot')
    return combined


@dataclass(frozen=True)
class StockSource:
    header: bytes
    dtbs: tuple[bytes, ...]
    mtk_template: bytes | None
    path: str
    source_sha256: str
    collection_sha256: str


def split_dtbs(region: bytes, label: str) -> list[bytes]:
    dtbs: list[bytes] = []
    position = 0
    while position < len(region):
        if len(region) - position < 40:
            raise BuildError(f'{label}: trailing bytes after the last appended DTB')
        totalsize = struct.unpack_from('>I', region, position + 4)[0]
        if totalsize < 40 or position + totalsize > len(region):
            raise BuildError(f'{label}: appended DTB at {position:#x} has an invalid totalsize')
        blob = region[position:position + totalsize]
        dtb_contract.parse_fdt(blob, f'{label} DTB {len(dtbs)}')
        dtbs.append(blob)
        position += totalsize
    return dtbs


def validate_stock_dtbs(dtbs: Sequence[bytes], expected_collection: str,
                        expected_pvt: str) -> str:
    if len(dtbs) != STOCK_DTB_COUNT:
        raise BuildError(f'stock image has {len(dtbs)} appended DTBs, expected '
                         f'{STOCK_DTB_COUNT}')
    for index, blob in enumerate(dtbs):
        if len(blob) > MAX_DTB_SIZE:
            raise BuildError(f'stock DTB {index} exceeds the {MAX_DTB_SIZE:#x} byte cap')
    pvt = sha256(dtbs[STOCK_DTB_INDEX])
    if pvt != expected_pvt:
        raise BuildError(f'stock DTB index 4 is not the expected PVT blob: {pvt}')
    compatible = dtb_contract.fdt_compatible(
        dtb_contract.parse_fdt(dtbs[STOCK_DTB_INDEX], 'stock PVT DTB'),
        'stock PVT DTB')
    if LIDAR_PVT_COMPATIBLE not in compatible:
        raise BuildError('stock DTB index 4 is not a Lidar PVT tree')
    collection = sha256(b''.join(dtbs))
    if collection != expected_collection:
        raise BuildError(f'stock DTB collection hash is {collection}, expected '
                         f'{expected_collection}')
    return collection


def load_stock_boot(path: Path, expected_collection: str,
                    expected_pvt: str) -> StockSource:
    data = read(path)
    if len(data) != IMAGE_SIZE:
        raise BuildError(f'stock boot image is {len(data)} bytes, expected {IMAGE_SIZE}')
    if data[:8] != ANDROID_MAGIC:
        raise BuildError('stock boot image lacks ANDROID! magic')
    fields = struct.unpack_from('<10I', data, 8)
    (kernel_size, kernel_addr, ramdisk_size, ramdisk_addr, second_size,
     second_addr, tags_addr, page_size, header_version, os_version) = fields
    expected = {
        'kernel_addr': (kernel_addr, KERNEL_ADDR),
        'ramdisk_addr': (ramdisk_addr, RAMDISK_ADDR),
        'second_addr': (second_addr, SECOND_ADDR),
        'tags_addr': (tags_addr, TAGS_ADDR),
        'page_size': (page_size, PAGE_SIZE),
        'header_version': (header_version, 0),
        'second_size': (second_size, 0),
        'os_version': (os_version, OS_VERSION),
    }
    for name, (actual, wanted) in expected.items():
        if actual != wanted:
            raise BuildError(f'stock boot header {name} is {actual:#x}, expected {wanted:#x}')
    if kernel_size <= MKIMG_SIZE or PAGE_SIZE + kernel_size > IMAGE_SIZE:
        raise BuildError('stock kernel section is out of range')
    kernel_section = data[PAGE_SIZE:PAGE_SIZE + kernel_size]
    if kernel_section[:4] != struct.pack('<I', MKIMG_MAGIC):
        raise BuildError('stock kernel section lacks the MediaTek magic')
    payload = kernel_section[MKIMG_SIZE:]
    _image, consumed = decompress_first_gzip(payload, 'stock kernel')
    dtbs = split_dtbs(payload[consumed:], 'stock kernel')
    collection = validate_stock_dtbs(dtbs, expected_collection, expected_pvt)
    ramdisk_offset = PAGE_SIZE + align(kernel_size)
    if ramdisk_offset + ramdisk_size > IMAGE_SIZE:
        raise BuildError('stock ramdisk section is out of range')
    return StockSource(
        header=data[:BOOT_HEADER_SIZE],
        dtbs=tuple(dtbs),
        mtk_template=kernel_section[:MKIMG_SIZE],
        path=str(path),
        source_sha256=sha256(data),
        collection_sha256=collection,
    )


def load_stock_dtb_collection(path: Path, expected_collection: str,
                              expected_pvt: str) -> StockSource:
    data = read(path)
    dtbs = split_dtbs(data, 'stock DTB collection')
    collection = validate_stock_dtbs(dtbs, expected_collection, expected_pvt)
    header = bytearray(BOOT_HEADER_SIZE)
    header[:8] = ANDROID_MAGIC
    struct.pack_into('<10I', header, 8, 0, KERNEL_ADDR, 0, RAMDISK_ADDR, 0,
                     SECOND_ADDR, TAGS_ADDR, PAGE_SIZE, 0, OS_VERSION)
    header[CMDLINE_OFFSET:CMDLINE_OFFSET + len(PROVEN_STOCK_CMDLINE) + 1] = (
        PROVEN_STOCK_CMDLINE + b'\x00')
    return StockSource(
        header=bytes(header),
        dtbs=tuple(dtbs),
        mtk_template=None,
        path=str(path),
        source_sha256=sha256(data),
        collection_sha256=collection,
    )


def validate_kernel_config(path: Path) -> str:
    text = read(path).decode('utf-8', 'replace')
    offenders = []
    for line in text.splitlines():
        if re.match(r'^\s*CONFIG_LIBREECHO_DEV[A-Z0-9_]*\s*=\s*[ym]\s*$', line):
            offenders.append(line.strip())
    if offenders:
        raise BuildError('kernel config enables a development marker: '
                         + ', '.join(offenders))
    return sha256(text.encode())


def validate_physical_layout(kernel_image: bytes, dtb: bytes,
                             ramdisk: bytes) -> dict[str, object]:
    image_size = validate_arm64_image(kernel_image, 'kernel Image')
    kernel_end = KERNEL_ADDR + image_size
    dtb_record = dtb_contract.validate_lidar_dtb(dtb, label='Lidar DTB')
    lowest = dtb_record['lowest_reserved_memory']
    if lowest is not None and kernel_end > int(lowest):
        raise BuildError(f'kernel Image ends at {kernel_end:#x}, above the lowest '
                         f'reserved-memory region {int(lowest):#x}')
    if kernel_end >= RAMDISK_ADDR:
        raise BuildError(f'kernel Image ends at {kernel_end:#x}, at or above '
                         f'ramdisk_addr {RAMDISK_ADDR:#x}')
    ramdisk_end = RAMDISK_ADDR + len(ramdisk)
    if ramdisk_end >= TAGS_ADDR:
        raise BuildError(f'ramdisk ends at {ramdisk_end:#x}, at or above tags_addr '
                         f'{TAGS_ADDR:#x}')
    return {
        'image_size': image_size,
        'kernel_end': f'0x{kernel_end:08x}',
        'ramdisk': [f'0x{RAMDISK_ADDR:08x}', f'0x{ramdisk_end:08x}'],
        'tags_addr': f'0x{TAGS_ADDR:08x}',
        'lowest_reserved_memory': None if lowest is None else f'0x{int(lowest):08x}',
        'reserved_memory': dtb_record['reserved_memory'],
        'reboot_mode_node': dtb_record['reboot_mode_node'],
    }


def build_image(stock: StockSource, kernel_image: bytes, dtb: bytes,
                ramdisk: bytes, cmdline_appends: Sequence[str] = ()) -> tuple[bytes, dict[str, object]]:
    if not ramdisk:
        raise BuildError('ramdisk is empty')
    if lzma.decompress(ramdisk, format=lzma.FORMAT_XZ)[:6] != b'070701':
        raise BuildError('ramdisk is not a newc cpio archive')
    physical = validate_physical_layout(kernel_image, dtb, ramdisk)

    gzip_kernel = gzip_deterministic(kernel_image)
    packed_dtb = dtb_contract.set_chosen_initrd(dtb, RAMDISK_ADDR, len(ramdisk),
                                                'Lidar DTB')
    dtbs = list(stock.dtbs)
    dtbs[STOCK_DTB_INDEX] = packed_dtb
    for index, blob in enumerate(dtbs):
        if len(blob) > MAX_DTB_SIZE:
            raise BuildError(f'appended DTB {index} exceeds the {MAX_DTB_SIZE:#x} cap')
    collection = b''.join(dtbs)

    payload = gzip_kernel + collection
    kernel_section = mtk_header(len(payload), stock.mtk_template) + payload
    kernel_size = len(kernel_section)
    if PAGE_SIZE + kernel_size > IMAGE_SIZE:
        raise BuildError('kernel section exceeds the 16 MiB envelope')

    header = bytearray(stock.header)
    if header[:8] != ANDROID_MAGIC or len(header) != BOOT_HEADER_SIZE:
        raise BuildError('stock boot header template is invalid')
    cmdline, extra_cmdline = append_cmdline(
        header[CMDLINE_OFFSET:CMDLINE_OFFSET + CMDLINE_SIZE],
        header[EXTRA_CMDLINE_OFFSET:EXTRA_CMDLINE_OFFSET + EXTRA_CMDLINE_SIZE],
        cmdline_appends,
    )
    combined_cmdline = validate_cmdline(cmdline, extra_cmdline)
    header[CMDLINE_OFFSET:CMDLINE_OFFSET + CMDLINE_SIZE] = cmdline
    header[EXTRA_CMDLINE_OFFSET:EXTRA_CMDLINE_OFFSET + EXTRA_CMDLINE_SIZE] = extra_cmdline
    struct.pack_into('<I', header, 8, kernel_size)
    struct.pack_into('<I', header, 16, len(ramdisk))
    header[576:608] = android_id(kernel_section, ramdisk)

    ramdisk_offset = PAGE_SIZE + align(kernel_size)
    ramdisk_end = ramdisk_offset + len(ramdisk)
    if ramdisk_end > IMAGE_SIZE:
        raise BuildError(f'kernel and ramdisk exceed the 16 MiB envelope: '
                         f'{ramdisk_end} > {IMAGE_SIZE}')
    trailer_offset = ramdisk_offset + align(len(ramdisk))
    output = bytearray(IMAGE_SIZE)
    output[:BOOT_HEADER_SIZE] = header
    output[PAGE_SIZE:PAGE_SIZE + kernel_size] = kernel_section
    output[ramdisk_offset:ramdisk_end] = ramdisk
    if any(output[trailer_offset:]):
        raise AssertionError('zero trailer was not preserved')

    record: dict[str, object] = {
        'android': {
            'image_size': IMAGE_SIZE,
            'page_size': PAGE_SIZE,
            'kernel_size': kernel_size,
            'kernel_addr': f'0x{KERNEL_ADDR:08x}',
            'ramdisk_size': len(ramdisk),
            'ramdisk_addr': f'0x{RAMDISK_ADDR:08x}',
            'ramdisk_file_offset': f'0x{ramdisk_offset:x}',
            'tags_addr': f'0x{TAGS_ADDR:08x}',
            'second_addr': f'0x{SECOND_ADDR:08x}',
            'id': bytes(header[576:608]).hex(),
        },
        'cmdline': combined_cmdline.decode('utf-8'),
        'mtk': {
            'header_sha256': sha256(kernel_section[:MKIMG_SIZE]),
            'payload_size': len(payload),
            'gzip_kernel_size': len(gzip_kernel),
            'gzip_kernel_sha256': sha256(gzip_kernel),
        },
        'dtb': {
            'collection_size': len(collection),
            'collection_sha256': sha256(collection),
            'index': STOCK_DTB_INDEX,
            'packed_dtb_size': len(packed_dtb),
            'packed_dtb_sha256': sha256(packed_dtb),
        },
        'memory': physical,
        'size_budget': {
            'image_size': IMAGE_SIZE,
            'gzip_kernel_bytes': len(gzip_kernel),
            'dtb_collection_bytes': len(collection),
            'ramdisk_bytes': len(ramdisk),
            'used_bytes': trailer_offset,
            'margin_to_16mib_bytes': IMAGE_SIZE - trailer_offset,
        },
        'trailer_offset': f'0x{trailer_offset:x}',
    }
    return bytes(output), record


def compress_ramdisk(cpio: bytes) -> bytes:
    return shared.compress_ramdisk(cpio)


def add_lidar_identity(stage: Path, manifest: dict[str, object], target: str,
                       digest: str | None) -> None:
    identity = targets.identity_bytes(target, digest)
    path = stage / 'etc/libreecho/target'
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(identity)
    path.chmod(0o644)
    profile = targets.audio_profile_bytes(target)
    manifest['board'] = target
    manifest['audio_profile'] = None
    audio = stage / 'etc/libreecho/audio-profile'
    audio.write_bytes(profile)
    audio.chmod(0o644)
    record = {'sha256': sha256(profile), 'size': len(profile)}
    manifest['audio_profile'] = record
    manifest['audio'] = {'enabled': True, 'path': '/etc/libreecho/audio-profile',
                         **record}
    if digest is not None:
        manifest['target_descriptor_sha256'] = digest
    props = stage / 'default.prop'
    if props.is_file() and target != 'radar_puffin':
        data = props.read_bytes().replace(b'=radar_puffin\n',
                                          b'=' + target.encode('ascii') + b'\n')
        props.write_bytes(data)
        overlay = manifest.get('overlay')
        if isinstance(overlay, dict):
            overlay['default.prop'] = {'sha256': sha256(data), 'size': len(data),
                                       'mode': '0644'}


def add_lidar_wifi_firmware(stage: Path, manifest: dict[str, object],
                            patch_source: Path, licence_source: Path) -> None:
    """Stage the redistributable MT7668 patch both drivers ask for.

    The RAM codes and the per-unit calibration come from the owner's stock
    system_a through the boot importer; they are never baked into the image.
    """
    patch = read(patch_source)
    if len(patch) != WIFI_PATCH_SIZE or sha256(patch) != WIFI_PATCH_SHA256:
        raise BuildError(f'{patch_source} is not the pinned linux-firmware '
                         f'MT7668 patch ({WIFI_PATCH_SIZE} bytes, '
                         f'{WIFI_PATCH_SHA256})')
    licence = read(licence_source)
    if not licence:
        raise BuildError(f'{licence_source} is empty')
    spec = read(WIFI_VENDOR_SPEC)
    files = (
        ('lib/firmware/mediatek/mt7668pr2h.bin', patch),
        ('lib/firmware/mt7668_patch_e2_hdr.bin', patch),
        ('lib/firmware/LICENCE.mediatek', licence),
        ('etc/libreecho/vendor-assets/lidar-mt7668-stock-v1.tsv', spec),
    )
    records: dict[str, object] = {}
    for relative, data in files:
        destination = stage / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        destination.chmod(0o644)
        records[relative] = {'sha256': sha256(data), 'size': len(data)}
    manifest['wifi_firmware'] = {
        'patch': {'sha256': WIFI_PATCH_SHA256, 'size': WIFI_PATCH_SIZE,
                  'source': 'linux-firmware'},
        'licence': {'sha256': sha256(licence), 'size': len(licence)},
        'vendor_spec': {'sha256': sha256(spec), 'size': len(spec)},
        'files': records,
    }


def add_lidar_ota_tools(stage: Path, bootctl: Path, verifier: Path,
                        public_key: Path, image_profile: str, service_profile: str,
                        feature_policy: str, update_channel: str,
                        manifest: dict[str, object], target: str,
                        digest: str | None) -> None:
    add_lidar_identity(stage, manifest, target, digest)
    sources = (
        ('bootctl', bootctl, 'usr/local/sbin/libreecho-bootctl',
         '/lib/ld-musl-armhf.so.1', ('libc.musl-armv7.so.1',), True),
        ('verifier', verifier, 'usr/local/libexec/libreecho-update-verify',
         None, (), False),
    )
    records: dict[str, object] = {}
    for name, source, relative, interpreter, needed, dynamic in sources:
        if source.is_symlink() or not source.is_file():
            raise BuildError(f'OTA {name} is not a regular file: {source}')
        data = read(source)
        destination = stage / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        destination.chmod(0o755)
        records[name] = {
            'sha256': sha256(data),
            'size': len(data),
            'path': '/' + relative,
            'elf': shared.require_elf_contract(destination, 0x05000400,
                                               interpreter, needed, dynamic),
        }
    key_data = read(public_key)
    if not re.fullmatch(rb'[0-9a-f]{64}\n', key_data):
        raise BuildError('OTA Ed25519 public key must be 32-byte lowercase hex')
    key_target = stage / 'etc/libreecho/ota-public-key.hex'
    key_target.parent.mkdir(parents=True, exist_ok=True)
    key_target.write_bytes(key_data)
    key_target.chmod(0o644)

    for relative, text in (
        ('etc/libreecho/image-profile', image_profile + '\n'),
        ('etc/libreecho/service-profile', service_profile + '\n'),
        ('etc/libreecho/feature-policy', feature_policy + '\n'),
        ('etc/libreecho/update-channel', update_channel + '\n'),
        ('etc/libreecho/first-install-confirm',
         f'schema=1\nmode=first-install\nboard={target}\n'),
    ):
        path = stage / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        path.chmod(0o644)

    ota_source = stage / 'etc/libreecho/ota-source.conf'
    if ota_source.is_file() and not ota_source.is_symlink():
        source_text = ota_source.read_text()
        source_text = re.sub(r'^channel=.*$', f'channel={update_channel}',
                             source_text, count=1, flags=re.MULTILINE)
        slug = targets.get_target(target)['release_slug']
        source_text = re.sub(
            r'libreecho-[a-z0-9-]+-(?:dev|stable)\.ota\.tar',
            f'libreecho-{slug}-{update_channel}.ota.tar', source_text)
        ota_source.write_text(source_text)
        overlay = manifest.get('overlay')
        if not isinstance(overlay, dict):
            raise BuildError('OTA source rewrite requires the overlay manifest')
        data = source_text.encode()
        overlay['ota-source.conf'] = {'sha256': sha256(data), 'size': len(data),
                                      'mode': '0644'}

    record = targets.get_target(target)
    manifest['image_profile'] = image_profile
    manifest['service_profile'] = service_profile
    manifest['feature_policy'] = feature_policy
    manifest['update_channel'] = update_channel
    manifest['ota'] = {
        'enabled': True,
        'format': 'libreecho-ota-v1',
        'board': target,
        'payload_slots': {'a': targets.partition_device(target, 'boot_a').rsplit('/', 1)[1],
                          'b': targets.partition_device(target, 'boot_b').rsplit('/', 1)[1]},
        'wrapper_partitions': [],
        'bcb': {'partition': record['bcb']['device'].rsplit('/', 1)[1],
                'offset': record['bcb']['offset'],
                'record_size': record['bcb']['record_size']},
        'persistent_configuration': '/data/libreecho/config',
        'public_key_sha256': sha256(key_data),
        'tools': records,
    }


def add_lidar_radio_helpers(stage: Path, manifest: dict[str, object],
                            efr32: Path, otbr_agent: Path) -> None:
    """Stage the two binaries the thread service executes.

    ``libreecho-threadd`` starts the EFR32 tool to bring the radio up and then
    execs otbr-agent.  Neither the OpenThread RCP GBL nor any per-unit radio
    payload belongs in an image, so only these two reviewed binaries are
    copied and only for target ``lidar``.
    """
    records: dict[str, object] = {}
    sources = (('lidar-efr32', efr32), ('otbr-agent', otbr_agent))
    for name, source in sources:
        if source.is_symlink() or not source.is_file():
            raise BuildError(f'{name} is not a regular file: {source}')
        if source.suffix == '.gbl':
            raise BuildError(f'{name} must be the host tool, not a GBL: {source}')
    for name, source in sources:
        data = read(source)
        relative = f'usr/local/sbin/{name}'
        destination = stage / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        destination.chmod(0o755)
        elf = shared.require_elf_contract(destination, 0x05000400, None, (), False)
        records[name] = {'sha256': sha256(data), 'size': len(data),
                         'path': '/' + relative, 'elf': elf}
    manifest['radio_helpers'] = {'activation': 'radio-setting-thread-only',
                                 'files': records}


def add_lidar_network(stage: Path, manifest: dict[str, object],
                      supplicant: Path) -> None:
    """Stage the WLAN client supplicant the initramfs scripts start.

    Lidar has no MT8163 WMT connectivity bundle: the MT7668 driver is
    mac80211/nl80211, so a plain static wpa_supplicant is all that the shared
    initramfs needs.  udhcpc is the bundled BusyBox applet and is already
    linked at build time.
    """
    if supplicant.is_symlink() or not supplicant.is_file():
        raise BuildError(f'wpa_supplicant is not a regular file: {supplicant}')
    data = read(supplicant)
    relative = 'sbin/wpa_supplicant'
    destination = stage / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)
    destination.chmod(0o755)
    elf = shared.require_elf_contract(destination, 0x05000400, None, (), False)
    manifest['network'] = {
        'wpa_supplicant': {
            'sha256': sha256(data),
            'size': len(data),
            'path': '/' + relative,
            'elf': elf,
        },
    }


def add_lidar_audio_tools(stage: Path, manifest: dict[str, object],
                          tools: dict[str, Path]) -> None:
    """Stage the static tinyalsa utilities the mic path executes.

    micd captures through /sbin/tinycap and the UI uses tinyplay/tinymix, so
    the same pinned ARM32 musl build the MT8163 profile uses is staged here.
    """
    records: dict[str, object] = {}
    for name, source in tools.items():
        if source.is_symlink() or not source.is_file():
            raise BuildError(f'{name} is not a regular file: {source}')
        data = read(source)
        relative = f'sbin/{name}'
        destination = stage / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        destination.chmod(0o755)
        elf = shared.require_elf_contract(destination, 0x05000400, None, (), False)
        records[name] = {'sha256': sha256(data), 'size': len(data),
                         'path': '/' + relative, 'elf': elf}
    manifest['audio_tools'] = records


def validate_ui_and_mdns_inputs(args: argparse.Namespace) -> bool:
    """Apply the shared UI and discovery input rules; return whether UI is staged."""
    ui_options = {
        'ui_bundle': args.ui_bundle,
        'ui_source': args.ui_source,
        'expected_ui_commit': args.expected_ui_commit,
        'expected_ui_diff_sha256': args.expected_ui_diff_sha256,
    }
    ui_enabled = args.ui_bundle is not None
    if ui_enabled and not all(value is not None for value in ui_options.values()):
        missing = ', '.join(
            '--' + name.replace('_', '-')
            for name, value in ui_options.items() if value is None
        )
        raise BuildError(f'UI bundle is enabled but missing {missing}')
    if not ui_enabled and any(value is not None for value in ui_options.values()):
        raise BuildError('UI inputs require the explicit --ui-bundle opt-in')
    if args.service_profile == 'production' and args.mdns_runtime is None:
        # Shared discovery is boot-contained Platform infrastructure; an ota
        # image without it can never pass its own OTA health probes.
        raise BuildError('the production service profile requires --mdns-runtime '
                         '(boot-contained shared discovery runtime)')
    return ui_enabled


def validate_ssh_inputs(args: argparse.Namespace) -> bool:
    """Apply the shared opt-in SSH bundle rules; return whether SSH is staged."""
    ssh_options = {
        'dropbear': args.dropbear,
        'dropbearkey': args.dropbearkey,
        'scp': args.scp,
    }
    ssh_enabled = args.ssh_enabled
    if ssh_enabled and not all(value is not None for value in ssh_options.values()):
        missing = ', '.join(
            '--' + name.replace('_', '-')
            for name, value in ssh_options.items() if value is None
        )
        raise BuildError(f'SSH bundle is explicitly enabled but missing {missing}')
    if not ssh_enabled and any(value is not None for value in ssh_options.values()):
        raise BuildError('SSH inputs require the explicit --ssh-enabled opt-in')
    return ssh_enabled


def disabled_ssh_record() -> dict[str, object]:
    """The manifest record for an image built without the SSH opt-in."""
    return {
        'enabled': False,
        'activation': 'saved-ssh-setting-and-webui-users',
        'autostart': False,
        'authentication': 'webui-users-sha256',
        'account_source': '/data/libreecho/config/users',
        'privilege_policy': 'non-root-ephemeral-users',
        'public_key_auth': False,
        'root_login': False,
        'host_keys': 'persistent-/data/libreecho/config/ssh-host-ed25519-key',
        'files': {},
    }


def validate_lidar_radio_inputs(parser: argparse.ArgumentParser,
                                args: argparse.Namespace) -> bool:
    """Radio helpers belong to Lidar only and are staged as a pair."""
    values = (args.lidar_efr32, args.otbr_agent)
    if any(value is not None for value in values) and not all(
            value is not None for value in values):
        parser.error('--lidar-efr32 and --otbr-agent must be given together')
    if any(value is not None for value in values) and args.target != 'lidar':
        parser.error('--lidar-efr32/--otbr-agent are refused outside target lidar')
    return values[0] is not None


def reject_mt8163_payload(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    refused = {
        'audio_probe': '--audio-probe (no Lidar audio profile exists yet)',
        'wifi_dtb': '--wifi-dtb (Wi-Fi DTB belongs to the MT8163 profile)',
        'connectivity_bundle': '--connectivity-bundle (MT8163 WMT bundle)',
    }
    for attribute, flag in refused.items():
        if getattr(args, attribute, None) is not None:
            parser.error(f'{flag} is refused for target lidar')


def main() -> None:
    parser = argparse.ArgumentParser(description='Build a LibreEcho Lidar recovery boot image.')
    stock = parser.add_mutually_exclusive_group(required=True)
    stock.add_argument('--stock-boot', type=Path,
                       help='read-only stock 16 MiB boot_a image')
    stock.add_argument('--stock-dtb-collection', type=Path,
                       help='raw concatenation of the 19 stock appended DTBs')
    parser.add_argument('--expected-stock-dtb-collection-sha256',
                        default=STOCK_DTB_COLLECTION_SHA256)
    parser.add_argument('--expected-stock-pvt-sha256', default=STOCK_PVT_SHA256)
    parser.add_argument('--kernel-image', type=Path, required=True,
                        help='raw ARM64 Image with the ARMd magic')
    parser.add_argument('--kernel-config', type=Path, required=True,
                        help='kernel .config used for the Image')
    parser.add_argument('--dtb', type=Path, required=True,
                        help='compiled Lidar DTB')
    parser.add_argument('--expected-dtb-sha256', required=True)
    parser.add_argument('--cmdline-append', action='append', default=[],
                        help='text appended to the proven stock command line')
    parser.add_argument('--adbd', type=Path, required=True,
                        help='source-built static ARM32 adbd')
    parser.add_argument('--adbd-source-metadata', type=Path, required=True)
    parser.add_argument('--busybox', type=Path, required=True)
    parser.add_argument('--expected-busybox-sha256', required=True)
    parser.add_argument('--musl-loader', type=Path, required=True)
    parser.add_argument('--expected-musl-loader-sha256', required=True)
    parser.add_argument('--image-profile', choices=('development', 'ota'), required=True)
    parser.add_argument('--service-profile', choices=('diagnostic', 'production'),
                        default='diagnostic')
    parser.add_argument('--feature-policy',
                        choices=('exclude', 'preserve', 'redistributable',
                                 'community-noncommercial'),
                        default='preserve')
    parser.add_argument('--update-channel', choices=('dev', 'stable'), required=True)
    parser.add_argument('--bootctl', type=Path, required=True)
    parser.add_argument('--update-verifier', type=Path, required=True)
    parser.add_argument('--ota-public-key', type=Path, required=True)
    parser.add_argument('--wifi-patch', type=Path, required=True,
                        help='linux-firmware mediatek/mt7668pr2h.bin')
    parser.add_argument('--wifi-licence', type=Path, required=True,
                        help='linux-firmware LICENCE.mediatek')
    parser.add_argument('--ui-bundle', type=Path,
                        help='staged static ARM32 LibreEcho-UI bundle')
    parser.add_argument('--mdns-runtime', type=Path,
                        help='boot-contained shared ARMHF Avahi/D-Bus discovery runtime')
    parser.add_argument('--ui-source', type=Path,
                        help='LibreEcho-UI source checkout used for the bundle')
    parser.add_argument('--expected-ui-commit',
                        help='expected LibreEcho-UI source commit')
    parser.add_argument('--expected-ui-diff-sha256',
                        help='expected LibreEcho-UI source diff identity')
    parser.add_argument('--qemu-arm', default='qemu-arm-static',
                        help='user-mode ARM emulator used to inventory BusyBox applets')
    parser.add_argument('--wpa-supplicant', type=Path,
                        help='staged static ARM32 wpa_supplicant for the WLAN client')
    parser.add_argument('--tinyplay', type=Path,
                        help='staged static ARM32 tinyplay')
    parser.add_argument('--tinycap', type=Path,
                        help='staged static ARM32 tinycap')
    parser.add_argument('--tinymix', type=Path,
                        help='staged static ARM32 tinymix')
    parser.add_argument('--ssh-enabled', action='store_true',
                        help='explicitly enable deferred WebUI-account SSH')
    parser.add_argument('--dropbear', type=Path,
                        help='static ARM32 Dropbear server with WebUI auth')
    parser.add_argument('--dropbearkey', type=Path,
                        help='static ARM32 Dropbear host-key utility')
    parser.add_argument('--scp', type=Path,
                        help='static ARM32 scp server-side transfer executable')
    parser.add_argument('--audio-probe', type=Path,
                        help='MT8163-only optional payload; refused for lidar')
    parser.add_argument('--wifi-dtb', type=Path,
                        help='MT8163-only optional payload; refused for lidar')
    parser.add_argument('--connectivity-bundle', type=Path,
                        help='MT8163-only optional payload; refused for lidar')
    parser.add_argument('--lidar-efr32', type=Path,
                        help='reviewed ARM32 EFR32 radio tool for the thread service')
    parser.add_argument('--otbr-agent', type=Path,
                        help='reviewed ARM32 OpenThread border router agent')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--ramdisk-output', type=Path)
    parser.add_argument('--manifest', type=Path)
    targets.add_target_arguments(parser)
    args = parser.parse_args()
    targets.validate_target_arguments(parser, args)
    reject_mt8163_payload(parser, args)
    thread_runtime_enabled = validate_lidar_thread_inputs(parser, args)
    ui_enabled = validate_ui_and_mdns_inputs(args)
    ssh_enabled = validate_ssh_inputs(args)

    output = args.output.resolve()
    ramdisk_output = (args.ramdisk_output or output.with_suffix('.ramdisk.cpio.xz')).resolve()
    manifest_output = (args.manifest or output.with_suffix('.manifest.json')).resolve()
    for path in (output, ramdisk_output, manifest_output):
        if path.exists():
            raise BuildError(f'refusing to overwrite {path}')

    if args.stock_boot is not None:
        stock_source = load_stock_boot(args.stock_boot, args.expected_stock_dtb_collection_sha256,
                                       args.expected_stock_pvt_sha256)
    else:
        stock_source = load_stock_dtb_collection(
            args.stock_dtb_collection, args.expected_stock_dtb_collection_sha256,
            args.expected_stock_pvt_sha256)
    config_sha = validate_kernel_config(args.kernel_config)

    kernel_image = read(args.kernel_image)
    dtb = read(args.dtb)
    require_hash('Lidar DTB', dtb, args.expected_dtb_sha256)
    dtb_contract.validate_lidar_dtb(dtb, label='Lidar DTB')

    qemu_arm = shutil.which(args.qemu_arm)
    if qemu_arm is None:
        raise BuildError(f'ARM user-mode emulator not found: {args.qemu_arm}')

    manifest: dict[str, object] = {
        'schema_version': 2,
        'name': 'libreecho-lidar-arm64-v1-recovery',
        'status': 'PREPARED_NOT_FLASHED',
        'inputs': {
            'stock': {'path': stock_source.path,
                      'sha256': stock_source.source_sha256,
                      'dtb_collection_sha256': stock_source.collection_sha256,
                      'pvt_dtb_sha256': args.expected_stock_pvt_sha256},
            'kernel_image': {'path': str(args.kernel_image.resolve()),
                             'sha256': sha256(kernel_image),
                             'size': len(kernel_image)},
            'kernel_config': {'path': str(args.kernel_config.resolve()),
                              'sha256': config_sha},
            'dtb': {'path': str(args.dtb.resolve()), 'sha256': sha256(dtb),
                    'size': len(dtb)},
        },
        'audio': {'enabled': False, 'reason': 'no Lidar audio profile staged'},
        'ssh': disabled_ssh_record(),
        'ui': {
            'enabled': False,
            'activation': 'manual-only',
            'autostart': False,
            'hardware_ownership': 'existing-control-plane',
            'files': {},
        },
        'mdns': {
            'enabled': False,
            'component': 'libreecho-mdns',
            'activation': 'manual-only',
            'autostart': False,
            'ownership': 'platform-boot-contained',
            'discovery': 'shared-avahi-dbus',
            'protocol': 'mdns',
            'feature_payload_dependency': False,
            'airplay_payload_dependency': False,
            'single_responder': True,
            'runtime_dirs': {},
            'files': {},
        },
    }
    overlay = SIBLING / 'initramfs'
    with tempfile.TemporaryDirectory(prefix='libreecho-lidar-initramfs-') as temporary:
        stage = Path(temporary)
        shared.copy_adbd(args.adbd.resolve(), args.adbd_source_metadata.resolve(),
                         stage, manifest, args.update_channel)
        shared.add_overlay(stage, overlay, args.busybox.resolve(),
                           args.musl_loader.resolve(),
                           args.expected_busybox_sha256,
                           args.expected_musl_loader_sha256,
                           qemu_arm, manifest)
        add_lidar_ota_tools(stage, args.bootctl.resolve(),
                            args.update_verifier.resolve(),
                            args.ota_public_key.resolve(), args.image_profile,
                            args.service_profile, args.feature_policy,
                            args.update_channel, manifest, args.target,
                            args.target_descriptor_sha256)
        add_lidar_wifi_firmware(stage, manifest, args.wifi_patch.resolve(),
                                args.wifi_licence.resolve())
        if radio_helpers_enabled:
            add_lidar_radio_helpers(stage, manifest, args.lidar_efr32.resolve(),
                                    args.otbr_agent.resolve())
        if args.wpa_supplicant is not None:
            add_lidar_network(stage, manifest, args.wpa_supplicant.resolve())
        audio_labels = ('tinyplay', 'tinycap', 'tinymix')
        audio_paths = [getattr(args, name) for name in audio_labels]
        if any(path is not None for path in audio_paths):
            if not all(path is not None for path in audio_paths):
                raise BuildError('tinyplay, tinycap and tinymix must be given together')
            add_lidar_audio_tools(stage, manifest,
                                  {name: path.resolve()
                                   for name, path in zip(audio_labels, audio_paths)})
        if ui_enabled:
            shared.add_ui_bundle(
                stage, args.ui_bundle.resolve(), args.ui_source.resolve(),
                args.expected_ui_commit, args.expected_ui_diff_sha256, manifest,
            )
        if args.mdns_runtime is not None:
            shared.add_mdns_runtime(stage, args.mdns_runtime.resolve(), manifest)
        if ssh_enabled:
            shared.add_ssh_bundle(
                stage, args.dropbear.resolve(), args.dropbearkey.resolve(),
                args.scp.resolve(), manifest,
            )
        shared.validate_stage(stage)
        cpio = shared.build_cpio(stage, 0)
    ramdisk = compress_ramdisk(cpio)
    if lzma.decompress(ramdisk, format=lzma.FORMAT_XZ) != cpio:
        raise BuildError('deterministic xz round trip failed')

    boot, record = build_image(stock_source, kernel_image, dtb, ramdisk,
                               args.cmdline_append)
    ramdisk_output.parent.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    manifest_output.parent.mkdir(parents=True, exist_ok=True)
    ramdisk_output.write_bytes(ramdisk)
    output.write_bytes(boot)
    manifest['initramfs'] = {
        'cpio_sha256': sha256(cpio),
        'cpio_size': len(cpio),
        'compression': RAMDISK_COMPRESSION,
        'ramdisk_sha256': sha256(ramdisk),
        'ramdisk_size': len(ramdisk),
        'path': str(ramdisk_output),
    }
    manifest['package'] = record
    manifest['output'] = {'path': str(output), 'sha256': sha256(boot),
                          'size': len(boot)}
    manifest_output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')

    budget = record['size_budget']
    print(f'boot_image={output}')
    print(f'boot_sha256={sha256(boot)}')
    print(f'ramdisk={ramdisk_output}')
    print(f'ramdisk_sha256={sha256(ramdisk)}')
    print(f'manifest={manifest_output}')
    print(f'gzip_kernel_bytes={budget["gzip_kernel_bytes"]}')
    print(f'dtb_collection_bytes={budget["dtb_collection_bytes"]}')
    print(f'ramdisk_bytes={budget["ramdisk_bytes"]}')
    print(f'margin_to_16mib_bytes={budget["margin_to_16mib_bytes"]}')
    print('status=PREPARED_NOT_FLASHED')


if __name__ == '__main__':
    try:
        main()
    except (BuildError, dtb_contract.ContractError) as error:
        raise SystemExit(f'ERROR: {error}') from error
