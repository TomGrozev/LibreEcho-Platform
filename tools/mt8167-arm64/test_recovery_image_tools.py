#!/usr/bin/env python3
"""Host tests for the MT8167 ARM64 Lidar image tools. No device access."""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import lzma
import os
import shutil
import stat
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import build_recovery_image as builder
import libreecho_platform_targets as targets
import verify_recovery_image as verifier
import verify_lidar_dtb as dtb_contract

HERE = Path(__file__).resolve().parent
SIBLING_OVERLAY = HERE.parent / 'mt8163-arm32' / 'initramfs'
DTC_CANDIDATES = (
    Path(os.environ['LIDAR_DTC']) if os.environ.get('LIDAR_DTC') else None,
    Path(shutil.which('dtc')) if shutil.which('dtc') else None,
)


def dtc_path() -> Path | None:
    for candidate in DTC_CANDIDATES:
        if candidate is not None and candidate.is_file():
            return candidate
    return None


def compile_dts(directory: Path, text: str, name: str = 'lidar.dtb') -> bytes:
    tool = dtc_path()
    if tool is None:
        raise unittest.SkipTest('dtc is not available')
    source = directory / (name + '.dts')
    output = directory / name
    source.write_text(text)
    completed = subprocess.run([str(tool), '-I', 'dts', '-O', 'dtb', '-o',
                                str(output), str(source)],
                               text=True, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    if completed.returncode:
        raise AssertionError(completed.stderr)
    return output.read_bytes()


def lidar_dts(reserved_base: str = '0x48000000',
              first_compatible: str = 'amzn,lidar-pvt',
              restart_offset: str = '0x24',
              include_pvt: bool = True) -> str:
    compatible = f'"{first_compatible}", "amzn,lidar"'
    if include_pvt and 'amzn,lidar-pvt' not in compatible:
        compatible += ', "amzn,lidar-pvt"'
    return f'''/dts-v1/;
/ {{
    model = "Amazon Lidar PVT test";
    compatible = {compatible};
    #address-cells = <2>;
    #size-cells = <2>;

    reserved-memory {{
        #address-cells = <2>;
        #size-cells = <2>;
        ranges;
        ram_console: ram-console {{
            reg = <0x0 {reserved_base} 0x0 0x100000>;
        }};
    }};

    watchdog@10007000 {{
        compatible = "mediatek,mt8167-wdt", "syscon", "simple-mfd";
        reg = <0x0 0x10007000 0x0 0x1000>;
        reboot-mode {{
            compatible = "syscon-reboot-mode";
            offset = <{restart_offset}>;
            mask = <0x4>;
            mode-bootloader = <0x4>;
        }};
    }};
}};
'''


def simple_dts(index: int) -> str:
    return f'''/dts-v1/;
/ {{
    model = "Amazon stock tree {index}";
    compatible = "amzn,lidar", "amzn,stock-{index}";
    #address-cells = <2>;
    #size-cells = <2>;
}};
'''


WIFI_VENDOR_SPEC = (HERE.parent / 'mt8163-arm32' / 'initramfs' /
                    'vendor-assets' / 'lidar-mt7668-stock-v1.tsv')
# The redistributable linux-firmware MT7668 patch is fixed at 170990 bytes and
# one SHA-256.  The contract under test is the staged layout and inventory, not
# the vendor payload, so the fixture is the same size and each test pins its
# own digest for the duration of the test.
WIFI_PATCH_PUBLISHED_SIZE = 170990
WIFI_PATCH_PUBLISHED_SHA256 = (
    '465ed634c61b46b34bb21240736f33d3d347fefec7cbfbd1cb6e63334aec4cc9'
)
WIFI_LICENCE_FIXTURE = b'MT7668 firmware licence fixture\n'


def synthetic_wifi_patch() -> bytes:
    block = b'MT7668 synthetic firmware fixture\n'
    repeats = WIFI_PATCH_PUBLISHED_SIZE // len(block) + 1
    return (block * repeats)[:WIFI_PATCH_PUBLISHED_SIZE]


def wifi_patch_bytes() -> bytes:
    return synthetic_wifi_patch()


def wifi_licence_bytes() -> bytes:
    return WIFI_LICENCE_FIXTURE


def wifi_staging() -> dict[str, bytes]:
    patch = wifi_patch_bytes()
    return {
        'lib/firmware/mediatek/mt7668pr2h.bin': patch,
        'lib/firmware/mt7668_patch_e2_hdr.bin': patch,
        'lib/firmware/LICENCE.mediatek': wifi_licence_bytes(),
        'etc/libreecho/vendor-assets/lidar-mt7668-stock-v1.tsv':
            WIFI_VENDOR_SPEC.read_bytes(),
    }


def make_elf32_arm() -> bytes:
    ident = bytearray(16)
    ident[:4] = b'\x7fELF'
    ident[4] = 1
    ident[5] = 1
    ident[6] = 1
    header = bytearray(52)
    header[:16] = ident
    struct.pack_into('<HHIIIIIHHHHHH', header, 16,
                     2, 40, 1, 0, 52, 0, 0x05000400, 52, 0, 0, 0, 0, 0)
    return bytes(header)


def make_arm64_image(size: int = 0x2000) -> bytes:
    image = bytearray(size)
    struct.pack_into('<Q', image, 0x10, size)
    image[0x38:0x3C] = b'ARMd'
    image[0x1000:] = b'kernel' * ((size - 0x1000) // 6)
    return bytes(image[:size])


def make_cpio(entries: list[tuple[str, int, bytes]]) -> bytes:
    archive = bytearray()
    for ino, (name, mode, data) in enumerate(entries, 1):
        encoded = name.encode() + b'\0'
        fields = (ino, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(encoded), 0)
        archive += b'070701' + b''.join(f'{value:08X}'.encode() for value in fields)
        archive += encoded
        archive += b'\0' * (-len(archive) % 4)
        archive += data + b'\0' * (-len(data) % 4)
    trailer = b'TRAILER!!!\0'
    fields = (len(entries) + 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, len(trailer), 0)
    archive += b'070701' + b''.join(f'{value:08X}'.encode() for value in fields)
    archive += trailer
    archive += b'\0' * (-len(archive) % 4)
    return bytes(archive)


def staged_overlay(directory: Path) -> tuple[list[tuple[str, int, bytes]],
                                             dict[str, dict[str, object]],
                                             dict[str, str]]:
    entries: list[tuple[str, int, bytes]] = []
    overlay: dict[str, dict[str, object]] = {}
    directories: set[str] = {'bin', 'dev', 'etc', 'lib', 'proc', 'sbin', 'sys',
                             'system', 'system/bin', 'tmp', 'usr', 'usr/local',
                             'usr/local/sbin', 'usr/local/libexec',
                             'etc/libreecho', 'etc/init.d',
                             'etc/libreecho/vendor-assets', 'lib/firmware',
                             'lib/firmware/mediatek'}

    errored = False
    for key, staged in verifier.shared.OVERLAY_TARGETS.items():
        data = (SIBLING_OVERLAY / key).read_bytes()
        if key == 'ota-source.conf':
            text = data.decode()
            text = text.replace('libreecho-radar-puffin-dev.ota.tar',
                                'libreecho-lidar-dev.ota.tar')
            data = text.encode()
        mode = 0o755 if (
            staged.startswith('usr/local/sbin/') or staged.endswith('.init')
            or staged == 'etc/profile'
        ) else 0o644
        entries.append((staged, stat.S_IFREG | mode, data))
        overlay[key] = {'sha256': builder.sha256(data), 'size': len(data),
                        'mode': f'{mode:04o}'}
        parts = staged.split('/')[:-1]
        for count in range(1, len(parts) + 1):
            directories.add('/'.join(parts[:count]))

    default_prop = (SIBLING_OVERLAY / 'default.prop').read_bytes()
    entries.append(('default.prop', stat.S_IFREG | 0o644, default_prop))
    overlay['default.prop'] = {'sha256': builder.sha256(default_prop),
                               'size': len(default_prop), 'mode': '0644'}

    init = (SIBLING_OVERLAY / 'libreecho-init').read_bytes()
    entries.append(('init', stat.S_IFREG | 0o755, init))

    elf = make_elf32_arm()
    entries.append(('bin/busybox', stat.S_IFREG | 0o755, elf))
    entries.append(('lib/ld-musl-armhf.so.1', stat.S_IFREG | 0o755, elf))
    entries.append(('sbin/adbd', stat.S_IFREG | 0o750, elf))
    entries.append(('usr/local/sbin/libreecho-bootctl', stat.S_IFREG | 0o755, elf))
    entries.append(('usr/local/libexec/libreecho-update-verify',
                    stat.S_IFREG | 0o755, elf))
    entries.append(('etc/libreecho/ota-public-key.hex', stat.S_IFREG | 0o644,
                    b'a' * 64 + b'\n'))
    entries.append(('etc/libreecho/target', stat.S_IFREG | 0o644,
                    targets.identity_bytes('lidar')))
    entries.append(('etc/libreecho/audio-profile', stat.S_IFREG | 0o644,
                    targets.audio_profile_bytes('lidar')))
    for relative, data in wifi_staging().items():
        entries.append((relative, stat.S_IFREG | 0o644, data))
    for relative, text in (
        ('etc/libreecho/image-profile', 'development\n'),
        ('etc/libreecho/service-profile', 'diagnostic\n'),
        ('etc/libreecho/feature-policy', 'preserve\n'),
        ('etc/libreecho/update-channel', 'dev\n'),
        ('etc/libreecho/first-install-confirm',
         'schema=1\nmode=first-install\nboard=lidar\n'),
    ):
        entries.append((relative, stat.S_IFREG | 0o644, text.encode()))

    symlinks = {
        'lib/libc.musl-armv7.so.1': 'ld-musl-armhf.so.1',
        'sbin/sh': '../bin/busybox',
        'sbin/ueventd': '../init',
        'sbin/watchdogd': '../init',
        'system/bin/sh': '../../bin/busybox',
    }
    for name, target in symlinks.items():
        entries.append((name, stat.S_IFLNK | 0o777, target.encode()))

    applets = [f'applet{i:03d}' for i in range(260)]
    for applet in applets:
        entries.append((f'bin/{applet}', stat.S_IFLNK | 0o777, b'busybox'))

    entries = [(name, mode, data) for name, mode, data in entries]
    for directory in sorted(directories):
        entries.append((directory, stat.S_IFDIR | 0o755, b''))
    entries.sort(key=lambda item: item[0])
    return entries, overlay, symlinks


def make_ui_elf(dynamic: bool = False) -> bytes:
    """Synthetic ARM ELF identity only, never a runnable target executable."""
    data = bytearray(512)
    data[:7] = b'\x7fELF\x01\x01\x01'
    struct.pack_into('<H', data, 18, 40)
    struct.pack_into('<I', data, 36, 0x05000400)
    if dynamic:
        interpreter = b'/lib/ld-musl-armhf.so.1\0'
        needed = b'libc.musl-armv7.so.1\0'
        data[128:128 + len(interpreter)] = interpreter
        data[160:160 + len(needed)] = needed
        struct.pack_into('<II', data, 28, 52, 256)
        struct.pack_into('<HHHH', data, 42, 32, 2, 40, 2)
        struct.pack_into('<II', data, 52, 3, 128)
        struct.pack_into('<I', data, 68, len(interpreter))
        struct.pack_into('<II', data, 84, 2, 192)
        struct.pack_into('<II', data, 192, 1, 0)
        struct.pack_into('<I', data, 260, 6)
        struct.pack_into('<III', data, 272, 192, 16, 1)
        struct.pack_into('<I', data, 292, 8)
        struct.pack_into('<I', data, 300, 3)
        struct.pack_into('<III', data, 312, 160, len(needed), 0)
    return bytes(data)


UI_COMMIT = 'a' * 40
UI_DIFF_SHA256 = 'b' * 64
MDNS_PACKAGES_SHA256 = 'c' * 64


def ui_fixture(directory: Path) -> tuple[Path, Path, dict[str, str]]:
    bundle = directory / 'ui-bundle'
    source = directory / 'ui-source'
    source.mkdir()
    names = verifier.shared.UI_FIXED_NAMES | {
        'usr/local/share/libreecho/web/index.html',
    }
    lines = ['schema=1', f'source_commit={UI_COMMIT}',
             f'source_diff_sha256={UI_DIFF_SHA256}']
    for name in sorted(names - {'usr/local/share/libreecho/ui-manifest.txt'}):
        relative = name.removeprefix('usr/local/')
        path = bundle / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        content = (make_ui_elf(name.endswith(('sttd-wyoming', 'ttsd-wyoming')))
                   if name in verifier.shared.UI_BINARY_NAMES else b'fixture\n')
        path.write_bytes(content)
        lines.append(f'file={relative} sha256={builder.sha256(content)}')
    manifest = bundle / 'share/libreecho/ui-manifest.txt'
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text('\n'.join(lines) + '\n')
    return bundle, source, {
        'ui_manifest': builder.sha256(manifest.read_bytes()),
        'ui_commit': UI_COMMIT,
        'ui_diff_sha256': UI_DIFF_SHA256,
    }


def mdns_fixture(directory: Path) -> tuple[Path, dict[str, str]]:
    contract = json.loads(
        (HERE.parent / 'mt8163-arm32' / 'mdns' / 'runtime-contract.json').read_text())
    runtime = directory / 'mdns-runtime'
    contents = {contract['loader']: make_elf32_arm()}
    for relative in (contract['executables'] + contract['libraries'] +
                     contract['config'] + contract['accounts'] +
                     contract['licenses']):
        contents[relative] = b'mdns runtime fixture\n'
    records: dict[str, dict[str, object]] = {}
    for relative, content in contents.items():
        mode = 0o755 if (relative == contract['loader'] or
                         relative in contract['executables']) else 0o644
        path = runtime / 'root' / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        records[relative] = {'sha256': builder.sha256(content),
                             'size': len(content), 'mode': mode}
    (runtime / 'manifest.json').write_text(json.dumps({
        'schema': 'libreecho-mdns-runtime/v1',
        'files': records,
        'packages_sha256': MDNS_PACKAGES_SHA256,
    }, indent=2, sort_keys=True))
    (runtime / 'packages.json').write_text(json.dumps({
        'schema': 'libreecho-mdns-packages/v1',
        'packages': [{'package': name} for name in contract['packages']],
    }, indent=2, sort_keys=True))
    return runtime, {
        'mdns_manifest': builder.sha256((runtime / 'manifest.json').read_bytes()),
    }


def ssh_fixture(directory: Path) -> tuple[Path, Path, Path]:
    binaries = directory / 'ssh-binaries'
    binaries.mkdir(exist_ok=True)
    paths = []
    for name in ('dropbear', 'dropbearkey', 'scp'):
        path = binaries / name
        path.write_bytes(make_elf32_arm())
        path.chmod(0o755)
        paths.append(path)
    return paths[0], paths[1], paths[2]


def ssh_staged(directory: Path) -> tuple[Path, dict[str, object]]:
    stage = directory / 'ssh-stage'
    stage.mkdir(exist_ok=True)
    dropbear, dropbearkey, scp = ssh_fixture(directory)
    manifest: dict[str, object] = {}
    with mock.patch.object(
            builder.shared, 'require_elf_contract',
            return_value={'class': 1, 'machine': 40, 'flags': '0x05000400',
                          'interpreter': None, 'needed': [], 'dynamic': False}):
        builder.shared.add_ssh_bundle(stage, dropbear, dropbearkey, scp, manifest)
    return stage, manifest


def stage_entries(stage: Path) -> dict[str, object]:
    staged: list[tuple[str, int, bytes]] = []
    for path in sorted(stage.rglob('*')):
        relative = path.relative_to(stage).as_posix()
        if path.is_dir():
            staged.append((relative, stat.S_IFDIR | 0o755, b''))
        else:
            staged.append((relative, stat.S_IFREG |
                           stat.S_IMODE(path.stat().st_mode),
                           path.read_bytes()))
    return verifier.shared.parse_newc(make_cpio(staged))


def build_manifest(record: dict[str, object], ramdisk: bytes,
                   symlinks: dict[str, str], overlay: dict[str, dict[str, object]],
                   applets: list[str], elf_sha: str,
                   ota_key_sha: str) -> dict[str, object]:
    cpio = lzma.decompress(ramdisk, format=lzma.FORMAT_XZ)
    profile = targets.audio_profile_bytes('lidar')
    wifi = wifi_staging()
    return {
        'schema_version': 2,
        'name': 'libreecho-lidar-arm64-v1-recovery',
        'status': 'PREPARED_NOT_FLASHED',
        'board': 'lidar',
        'audio_profile': {'sha256': builder.sha256(profile),
                          'size': len(profile)},
        'audio': {'enabled': True, 'path': '/etc/libreecho/audio-profile',
                  'sha256': builder.sha256(profile), 'size': len(profile)},
        'ssh': builder.disabled_ssh_record(),
        'wifi_firmware': {
            'patch': {'sha256': builder.WIFI_PATCH_SHA256,
                      'size': builder.WIFI_PATCH_SIZE,
                      'source': 'linux-firmware'},
            'licence': {'sha256': builder.sha256(wifi['lib/firmware/LICENCE.mediatek']),
                        'size': len(wifi['lib/firmware/LICENCE.mediatek'])},
            'vendor_spec': {
                'sha256': builder.sha256(
                    wifi['etc/libreecho/vendor-assets/lidar-mt7668-stock-v1.tsv']),
                'size': len(
                    wifi['etc/libreecho/vendor-assets/lidar-mt7668-stock-v1.tsv'])},
            'files': {relative: {'sha256': builder.sha256(data),
                                 'size': len(data)}
                      for relative, data in wifi.items()},
        },
        'adbd': {'sha256': elf_sha, 'size': len(make_elf32_arm())},
        'ota': {
            'board': 'lidar',
            'tools': {
                'bootctl': {'sha256': elf_sha,
                            'path': '/usr/local/sbin/libreecho-bootctl'},
                'verifier': {'sha256': elf_sha,
                             'path': '/usr/local/libexec/libreecho-update-verify'},
            },
            'public_key_sha256': ota_key_sha,
        },
        'overlay': overlay,
        'symlinks': symlinks,
        'busybox_applets': {'count': len(applets), 'names': applets},
        'initramfs': {
            'compression': builder.RAMDISK_COMPRESSION,
            'cpio_sha256': builder.sha256(cpio),
            'cpio_size': len(cpio),
            'ramdisk_sha256': builder.sha256(ramdisk),
            'ramdisk_size': len(ramdisk),
        },
        'output': {'sha256': '', 'size': builder.IMAGE_SIZE},
        'package': record,
    }


class LidarImageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if dtc_path() is None:
            raise unittest.SkipTest('dtc is not available for synthetic DTBs')

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.directory = Path(self.tempdir.name)
        self.wifi_sha = builder.sha256(synthetic_wifi_patch())
        self.published_wifi = {builder: builder.WIFI_PATCH_SHA256,
                               verifier: verifier.WIFI_PATCH_SHA256}
        for module in (builder, verifier):
            patcher = mock.patch.object(module, 'WIFI_PATCH_SHA256', self.wifi_sha)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.kernel = make_arm64_image()
        self.dtb = compile_dts(self.directory, lidar_dts())
        self.stock_dtbs = []
        for index in range(builder.STOCK_DTB_COUNT):
            if index == builder.STOCK_DTB_INDEX:
                self.stock_dtbs.append(self.dtb)
            else:
                self.stock_dtbs.append(
                    compile_dts(self.directory, simple_dts(index), f'stock{index}.dtb'))
        self.collection = b''.join(self.stock_dtbs)
        self.pvt_sha = builder.sha256(self.dtb)
        self.stock_path = self.directory / 'stock-boot.img'
        self.stock_path.write_bytes(self.make_stock_image())
        self.stock = builder.load_stock_boot(
            self.stock_path, builder.sha256(self.collection), self.pvt_sha)

        entries, self.overlay, self.symlinks = staged_overlay(self.directory)
        cpio = make_cpio(entries)
        self.ramdisk = builder.compress_ramdisk(cpio)
        self.applets = [f'applet{i:03d}' for i in range(260)]
        self.elf_sha = builder.sha256(make_elf32_arm())
        self.ota_key_sha = builder.sha256(b'a' * 64 + b'\n')
        self.kernel_path = self.directory / 'Image'
        self.kernel_path.write_bytes(self.kernel)
        self.dtb_path = self.directory / 'lidar.dtb'
        self.dtb_path.write_bytes(self.dtb)

    def tearDown(self):
        self.tempdir.cleanup()

    def make_stock_image(self) -> bytes:
        gzip_kernel = builder.gzip_deterministic(self.kernel)
        payload = gzip_kernel + self.collection
        section = builder.mtk_header(len(payload)) + payload
        stock_ramdisk = builder.gzip_deterministic(
            make_cpio([('init', stat.S_IFREG | 0o755, b'#!/bin/sh\n')]))
        header = bytearray(builder.BOOT_HEADER_SIZE)
        header[:8] = builder.ANDROID_MAGIC
        struct.pack_into('<10I', header, 8, len(section), builder.KERNEL_ADDR,
                         len(stock_ramdisk), builder.RAMDISK_ADDR, 0,
                         builder.SECOND_ADDR, builder.TAGS_ADDR, builder.PAGE_SIZE,
                         0, builder.OS_VERSION)
        header[64:64 + len(builder.PROVEN_STOCK_CMDLINE) + 1] = (
            builder.PROVEN_STOCK_CMDLINE + b'\0')
        header[576:608] = builder.android_id(section, stock_ramdisk)
        image = bytearray(builder.IMAGE_SIZE)
        image[:builder.BOOT_HEADER_SIZE] = header
        image[builder.PAGE_SIZE:builder.PAGE_SIZE + len(section)] = section
        offset = builder.PAGE_SIZE + builder.align(len(section))
        image[offset:offset + len(stock_ramdisk)] = stock_ramdisk
        return bytes(image)

    def package(self, appends: list[str] | None = None) -> tuple[bytes, dict, dict]:
        appends = appends or []
        boot, record = builder.build_image(self.stock, self.kernel, self.dtb,
                                           self.ramdisk, appends)
        manifest = build_manifest(record, self.ramdisk, self.symlinks,
                                  self.overlay, self.applets, self.elf_sha,
                                  self.ota_key_sha)
        manifest['output']['sha256'] = builder.sha256(boot)
        return boot, record, manifest

    def write_package(self, boot: bytes, manifest: dict,
                      ramdisk: bytes | None = None) -> tuple[Path, Path, Path]:
        boot_path = self.directory / 'boot.img'
        ramdisk_path = self.directory / 'ramdisk.cpio.xz'
        manifest_path = self.directory / 'boot.manifest.json'
        boot_path.write_bytes(boot)
        ramdisk_path.write_bytes(self.ramdisk if ramdisk is None else ramdisk)
        manifest_path.write_text(json.dumps(manifest))
        return boot_path, ramdisk_path, manifest_path

    def verify(self, boot: bytes, manifest: dict, appends: list[str] | None = None,
               ramdisk: bytes | None = None,
               expected_extra: dict[str, str] | None = None):
        boot_path, ramdisk_path, manifest_path = self.write_package(
            boot, manifest, ramdisk)
        expected = {
            'busybox': self.elf_sha,
            'loader': self.elf_sha,
            'bootctl': self.elf_sha,
            'update_verifier': self.elf_sha,
            'ota_key': self.ota_key_sha,
            'image_profile': 'development',
            'service_profile': 'diagnostic',
            'feature_policy': 'preserve',
            'update_channel': 'dev',
            'stock_collection': builder.sha256(self.collection),
            'stock_pvt': self.pvt_sha,
        }
        expected.update(expected_extra or {})
        # The staged busybox is an ELF identity only, so qemu cannot execute
        # it.  The target-parser contract is shell logic, so run it under the
        # host busybox the way CI does when no emulator is installed.
        real_which = shutil.which

        def which(name, *args, **kwargs):
            if name == 'qemu-arm-static':
                return None
            return real_which(name, *args, **kwargs)

        with mock.patch.object(verifier.shared.shutil, 'which', which):
            return verifier.verify_image(
                self.stock_path, False, self.kernel_path, self.dtb_path,
                ramdisk_path, manifest_path, boot_path, builder.sha256(boot),
                self.pvt_sha, appends or [], expected, 'lidar', None)

    def staged_build(self, tamper: str | None = None
                     ) -> tuple[bytes, dict, bytes, dict[str, str], Path]:
        stage = self.directory / 'stage'
        entries, overlay, symlinks = staged_overlay(self.directory)
        for name, mode, data in entries:
            path = stage / name
            if stat.S_ISDIR(mode):
                path.mkdir(parents=True, exist_ok=True)
            elif stat.S_ISLNK(mode):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.symlink_to(data.decode())
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
                path.chmod(stat.S_IMODE(mode))

        bundle, source, ui_expected = ui_fixture(self.directory)
        runtime, mdns_expected = mdns_fixture(self.directory)
        staging: dict[str, object] = {}
        # Startup script content and the readelf ABI probe have their own gates
        # in the MT8163 suite; this test covers staging, records and verify.
        with mock.patch.object(builder.shared, 'validate_ui_startup_contract'), \
             mock.patch.object(builder.shared, 'require_elf_contract',
                               return_value={}):
            builder.shared.add_ui_bundle(stage, bundle, source, UI_COMMIT,
                                         UI_DIFF_SHA256, staging)
        builder.shared.add_mdns_runtime(stage, runtime, staging)

        if tamper is not None:
            target = stage / tamper
            data = bytearray(target.read_bytes())
            data[0] ^= 0xFF
            target.write_bytes(bytes(data))

        staged: list[tuple[str, int, bytes]] = []
        for path in sorted(stage.rglob('*')):
            relative = path.relative_to(stage).as_posix()
            if path.is_symlink():
                staged.append((relative, stat.S_IFLNK | 0o777,
                               os.readlink(path).encode()))
            elif path.is_dir():
                staged.append((relative, stat.S_IFDIR | 0o755, b''))
            else:
                staged.append((relative, stat.S_IFREG |
                               stat.S_IMODE(path.stat().st_mode),
                               path.read_bytes()))
        cpio = make_cpio(staged)
        ramdisk = builder.compress_ramdisk(cpio)
        boot, record = builder.build_image(self.stock, self.kernel, self.dtb,
                                           ramdisk)
        manifest = build_manifest(record, ramdisk, symlinks, overlay,
                                  self.applets, self.elf_sha, self.ota_key_sha)
        manifest.update({key: staging[key] for key in ('ui', 'mdns')})
        manifest['output']['sha256'] = builder.sha256(boot)
        expected = {**ui_expected, **mdns_expected}
        return boot, manifest, ramdisk, expected, stage


    def test_production_requires_mdns_runtime(self):
        args = mock.Mock(ui_bundle=None, ui_source=None, expected_ui_commit=None,
                         expected_ui_diff_sha256=None, mdns_runtime=None,
                         service_profile='production')
        with self.assertRaises(builder.BuildError) as caught:
            builder.validate_ui_and_mdns_inputs(args)
        self.assertIn('--mdns-runtime', str(caught.exception))
        args.mdns_runtime = Path('runtime')
        self.assertFalse(builder.validate_ui_and_mdns_inputs(args))

    def test_ui_inputs_require_ui_bundle(self):
        args = mock.Mock(ui_bundle=None, ui_source=Path('source'),
                         expected_ui_commit=UI_COMMIT,
                         expected_ui_diff_sha256=UI_DIFF_SHA256,
                         mdns_runtime=None, service_profile='diagnostic')
        with self.assertRaises(builder.BuildError) as caught:
            builder.validate_ui_and_mdns_inputs(args)
        self.assertIn('--ui-bundle', str(caught.exception))
        args.ui_bundle = Path('bundle')
        self.assertTrue(builder.validate_ui_and_mdns_inputs(args))

    def test_ui_and_mdns_staging_passes_verifier(self):
        boot, manifest, ramdisk, expected, stage = self.staged_build()
        self.assertTrue((stage / 'usr/local/sbin/libreecho-web').is_file())
        self.assertTrue((stage / 'etc/init.d/libreecho-web.init').is_file())
        self.assertTrue(
            (stage / 'usr/local/lib/libreecho-mdns/root/lib/ld-linux-armhf.so.3').is_file())
        self.assertTrue(
            (stage / 'usr/local/lib/libreecho-mdns/root/etc/avahi/services').is_dir())
        self.assertTrue((stage / 'etc/libreecho/mdns-runtime.json').is_file())
        self.assertTrue(manifest['ui']['enabled'])
        self.assertTrue(manifest['mdns']['enabled'])
        result = self.verify(boot, manifest, ramdisk=ramdisk,
                             expected_extra=expected)
        self.assertGreater(result['size_budget']['margin_to_16mib_bytes'], 0)

    def test_verifier_rejects_tampered_ui_member(self):
        boot, manifest, ramdisk, expected, _stage = self.staged_build(
            tamper='usr/local/share/libreecho/web/index.html')
        with self.assertRaises(verifier.VerifyError) as caught:
            self.verify(boot, manifest, ramdisk=ramdisk, expected_extra=expected)
        self.assertIn('hash mismatch', str(caught.exception))

    def test_verifier_rejects_tampered_mdns_member(self):
        boot, manifest, ramdisk, expected, _stage = self.staged_build(
            tamper='usr/local/lib/libreecho-mdns/root/etc/avahi/avahi-daemon.conf')
        with self.assertRaises(verifier.VerifyError) as caught:
            self.verify(boot, manifest, ramdisk=ramdisk, expected_extra=expected)
        self.assertIn('hash mismatch', str(caught.exception))

    def test_ssh_bundle_is_opt_in_and_verified(self):
        stage, manifest = ssh_staged(self.directory)
        for name in ('sbin/dropbear', 'sbin/dropbearkey', 'usr/bin/scp',
                     'etc/init.d/libreecho-ssh.init', 'etc/passwd'):
            self.assertTrue((stage / name).is_file(), name)
        self.assertTrue(manifest['ssh']['enabled'])
        entries = stage_entries(stage)
        self.assertTrue(verifier.shared.validate_ssh(
            entries, manifest, self.elf_sha, self.elf_sha, self.elf_sha))

    def test_ssh_bundle_disabled_by_default(self):
        manifest = {'ssh': builder.disabled_ssh_record()}
        self.assertFalse(manifest['ssh']['enabled'])
        self.assertEqual(manifest['ssh']['files'], {})
        entries = verifier.shared.parse_newc(make_cpio([]))
        self.assertFalse(verifier.shared.validate_ssh(
            entries, manifest, None, None, None))

    def test_verifier_rejects_a_bad_ssh_pin(self):
        stage, manifest = ssh_staged(self.directory)
        entries = stage_entries(stage)
        with self.assertRaises(SystemExit) as caught:
            verifier.shared.validate_ssh(
                entries, manifest, '0' * 64, self.elf_sha, self.elf_sha)
        self.assertIn('hash mismatch', str(caught.exception))

    def test_verifier_rejects_an_ssh_pin_without_a_bundle(self):
        manifest = {'ssh': builder.disabled_ssh_record()}
        entries = verifier.shared.parse_newc(make_cpio([]))
        with self.assertRaises(SystemExit) as caught:
            verifier.shared.validate_ssh(entries, manifest, self.elf_sha,
                                         self.elf_sha, self.elf_sha)
        self.assertIn('expectation mismatch', str(caught.exception))

    def test_ssh_inputs_require_the_explicit_opt_in(self):
        args = mock.Mock(ssh_enabled=False, dropbear=Path('dropbear'),
                         dropbearkey=None, scp=None)
        with self.assertRaises(builder.BuildError) as caught:
            builder.validate_ssh_inputs(args)
        self.assertIn('--ssh-enabled', str(caught.exception))
        args = mock.Mock(ssh_enabled=True, dropbear=Path('dropbear'),
                         dropbearkey=Path('dropbearkey'), scp=None)
        with self.assertRaises(builder.BuildError) as caught:
            builder.validate_ssh_inputs(args)
        self.assertIn('--scp', str(caught.exception))
        args.scp = Path('scp')
        self.assertTrue(builder.validate_ssh_inputs(args))

    def test_target_table_renders_the_lidar_audio_profile(self):
        record = targets.get_target('lidar')
        self.assertEqual(record['soc'], 'mt8167')
        self.assertEqual(record['userspace_architecture'], 'armv7')
        self.assertEqual(len(record['partitions']), 16)
        self.assertEqual(targets.partition_device('lidar', 'boot_a'),
                         '/dev/mmcblk0p10')
        profile = targets.audio_profile_bytes('lidar').decode()
        self.assertTrue(profile.startswith('schema=1\ntarget_id=lidar\n'))
        lines = profile.splitlines()
        self.assertEqual(lines.count('schema=1'), 1)
        self.assertIn('speaker_chain=lidar', lines)
        self.assertIn('codec_profile=Flat', lines)
        self.assertIn('pre_gain_db=0', lines)
        self.assertIn('playback_format=s16_le', lines)
        self.assertIn('capture_channels=8', lines)
        self.assertIn('capture_format=s32_le', lines)
        self.assertIn('capture_roles=mic0,mic1,mic2,mic3,mic4,mic5,mic6,line-in',
                      lines)
        self.assertIn('aec_source=separate-pcm', lines)
        self.assertIn('aec_device=2', lines)
        self.assertEqual([line.split('=', 1)[0] for line in lines[2:]],
                         list(targets.AUDIO_KEYS))
        with self.assertRaises(ValueError):
            targets.validate_audio({**record['audio'], 'speaker_chain': 'biscuit'})
        with self.assertRaises(ValueError):
            targets.validate_audio({**record['audio'], 'extra': 1})

    def test_add_lidar_identity_writes_the_profile(self):
        stage = self.directory / 'identity-stage'
        stage.mkdir()
        manifest: dict[str, object] = {}
        builder.add_lidar_identity(stage, manifest, 'lidar', None)
        profile = targets.audio_profile_bytes('lidar')
        audio = stage / 'etc/libreecho/audio-profile'
        self.assertEqual(audio.read_bytes(), profile)
        self.assertEqual(stat.S_IMODE(audio.stat().st_mode), 0o644)
        self.assertEqual(manifest['audio_profile'],
                         {'sha256': builder.sha256(profile), 'size': len(profile)})
        self.assertTrue(manifest['audio']['enabled'])

    def test_add_lidar_wifi_firmware_stages_both_driver_names(self):
        stage = self.directory / 'wifi-stage'
        stage.mkdir()
        patch_path = self.directory / 'mt7668pr2h.bin'
        patch_path.write_bytes(synthetic_wifi_patch())
        licence = self.directory / 'LICENCE.mediatek'
        licence.write_bytes(wifi_licence_bytes())
        manifest: dict[str, object] = {}
        builder.add_lidar_wifi_firmware(
            stage, manifest, patch_path, licence)
        patch = wifi_patch_bytes()
        for relative in ('lib/firmware/mediatek/mt7668pr2h.bin',
                         'lib/firmware/mt7668_patch_e2_hdr.bin'):
            member = stage / relative
            self.assertEqual(member.read_bytes(), patch)
            self.assertEqual(stat.S_IMODE(member.stat().st_mode), 0o644)
        self.assertTrue((stage / 'lib/firmware/LICENCE.mediatek').is_file())
        spec = stage / 'etc/libreecho/vendor-assets/lidar-mt7668-stock-v1.tsv'
        self.assertEqual(spec.read_bytes(), WIFI_VENDOR_SPEC.read_bytes())
        self.assertEqual(manifest['wifi_firmware']['patch']['sha256'],
                         self.wifi_sha)
        self.assertEqual(manifest['wifi_firmware']['patch']['size'],
                         WIFI_PATCH_PUBLISHED_SIZE)
        self.assertEqual(set(manifest['wifi_firmware']['files']),
                         set(wifi_staging()))

    def test_wifi_patch_pins_the_published_linux_firmware_blob(self):
        # The per-test fixture substitutes only the digest; the image must
        # otherwise stage the exact published linux-firmware blob.
        self.assertEqual(builder.WIFI_PATCH_SIZE, WIFI_PATCH_PUBLISHED_SIZE)
        self.assertEqual(verifier.WIFI_PATCH_SIZE, WIFI_PATCH_PUBLISHED_SIZE)
        for module, digest in self.published_wifi.items():
            self.assertEqual(digest, WIFI_PATCH_PUBLISHED_SHA256, module.__name__)
        self.assertEqual(len(synthetic_wifi_patch()), builder.WIFI_PATCH_SIZE)

    def test_add_lidar_wifi_firmware_rejects_an_unpinned_patch(self):
        stage = self.directory / 'bad-wifi-stage'
        stage.mkdir()
        bad = self.directory / 'bad-patch.bin'
        bad.write_bytes(b'not the linux-firmware patch')
        licence = self.directory / 'bad-licence'
        licence.write_bytes(b'licence\n')
        with self.assertRaises(builder.BuildError):
            builder.add_lidar_wifi_firmware(stage, {}, bad, licence)
        self.assertEqual(list(stage.iterdir()), [])

    def test_verifier_rejects_lidar_init_without_the_target_case(self):
        # An intact target file can still sit beside a loader without the
        # lidar case, so the slot boots without Wi-Fi.
        original = (SIBLING_OVERLAY / 'libreecho-init').read_bytes()
        broken = original.replace(b'        lidar) TARGET_SLUG=lidar ;;\n', b'')
        self.assertNotEqual(broken, original)
        entries, overlay, symlinks = staged_overlay(self.directory)
        entries = [(name, mode, broken if name == 'init' else data)
                   for name, mode, data in entries]
        ramdisk = builder.compress_ramdisk(make_cpio(entries))
        boot, record = builder.build_image(self.stock, self.kernel, self.dtb,
                                           ramdisk)
        manifest = build_manifest(record, ramdisk, symlinks, overlay,
                                  self.applets, self.elf_sha, self.ota_key_sha)
        manifest['output']['sha256'] = builder.sha256(boot)
        with mock.patch.object(verifier, 'INIT_SHA256', builder.sha256(broken)):
            with self.assertRaises(verifier.VerifyError) as caught:
                self.verify(boot, manifest, ramdisk=ramdisk)
        self.assertIn('image target parser does not map lidar: libreecho-init',
                      str(caught.exception))

    def test_verifier_rejects_lidar_init_without_the_wifi_radio_gate(self):
        original = (SIBLING_OVERLAY / 'libreecho-init').read_bytes()
        broken = original.replace(b'last_check=wifi-radio', b'last_check=wifi-radix')
        self.assertNotEqual(broken, original)
        entries, overlay, symlinks = staged_overlay(self.directory)
        entries = [(name, mode, broken if name == 'init' else data)
                   for name, mode, data in entries]
        ramdisk = builder.compress_ramdisk(make_cpio(entries))
        boot, record = builder.build_image(self.stock, self.kernel, self.dtb,
                                           ramdisk)
        manifest = build_manifest(record, ramdisk, symlinks, overlay,
                                  self.applets, self.elf_sha, self.ota_key_sha)
        manifest['output']['sha256'] = builder.sha256(boot)
        with mock.patch.object(verifier, 'INIT_SHA256', builder.sha256(broken)):
            with self.assertRaises(verifier.VerifyError) as caught:
                self.verify(boot, manifest, ramdisk=ramdisk)
        self.assertIn('Lidar wifi-radio health gate is missing', str(caught.exception))

    def test_verifier_rejects_an_mt8163_wifi_member(self):
        entries, overlay, symlinks = staged_overlay(self.directory)
        entries.append(('lib/firmware/WIFI_RAM_CODE_8163',
                        stat.S_IFREG | 0o644, b'mt8163-code'))
        ramdisk = builder.compress_ramdisk(make_cpio(entries))
        boot, record = builder.build_image(self.stock, self.kernel, self.dtb,
                                           ramdisk)
        manifest = build_manifest(record, ramdisk, symlinks, overlay,
                                  self.applets, self.elf_sha, self.ota_key_sha)
        manifest['output']['sha256'] = builder.sha256(boot)
        with self.assertRaises(verifier.VerifyError) as caught:
            self.verify(boot, manifest, ramdisk=ramdisk)
        self.assertIn('MT8163 Wi-Fi member', str(caught.exception))

    def test_verifier_rejects_a_missing_audio_profile(self):
        entries, overlay, symlinks = staged_overlay(self.directory)
        entries = [entry for entry in entries
                   if entry[0] != 'etc/libreecho/audio-profile']
        ramdisk = builder.compress_ramdisk(make_cpio(entries))
        boot, record = builder.build_image(self.stock, self.kernel, self.dtb,
                                           ramdisk)
        manifest = build_manifest(record, ramdisk, symlinks, overlay,
                                  self.applets, self.elf_sha, self.ota_key_sha)
        manifest['output']['sha256'] = builder.sha256(boot)
        with self.assertRaises(verifier.VerifyError) as caught:
            self.verify(boot, manifest, ramdisk=ramdisk)
        self.assertIn('audio-profile', str(caught.exception))

    def test_verifier_rejects_a_tampered_wifi_patch(self):
        entries, overlay, symlinks = staged_overlay(self.directory)
        entries = [(name, mode, (bytes([data[0] ^ 0xFF]) + data[1:])
                    if name == 'lib/firmware/mt7668_patch_e2_hdr.bin' else data)
                   for name, mode, data in entries]
        ramdisk = builder.compress_ramdisk(make_cpio(entries))
        boot, record = builder.build_image(self.stock, self.kernel, self.dtb,
                                           ramdisk)
        manifest = build_manifest(record, ramdisk, symlinks, overlay,
                                  self.applets, self.elf_sha, self.ota_key_sha)
        manifest['output']['sha256'] = builder.sha256(boot)
        with self.assertRaises(verifier.VerifyError) as caught:
            self.verify(boot, manifest, ramdisk=ramdisk)
        self.assertIn('hash mismatch', str(caught.exception))

    def test_round_trip_passes_independent_verifier(self):
        boot, record, manifest = self.package()
        result = self.verify(boot, manifest)
        budget = record['size_budget']
        self.assertEqual(result['size_budget']['margin_to_16mib_bytes'],
                         budget['margin_to_16mib_bytes'])
        self.assertGreater(budget['margin_to_16mib_bytes'], 0)

    def test_output_is_deterministic_and_stock_is_untouched(self):
        before = self.stock_path.read_bytes()
        first, _record, _manifest = self.package()
        second, _record, _manifest = self.package()
        self.assertEqual(first, second)
        self.assertEqual(self.stock_path.read_bytes(), before)

    def test_trailer_is_zero(self):
        boot, record, _manifest = self.package()
        self.assertFalse(any(boot[int(record['trailer_offset'], 16):]))

    def test_cmdline_append_and_verifier_mismatch(self):
        suffix = 'console=ttyS0,921600n1'
        boot, record, manifest = self.package([suffix])
        self.assertIn(suffix, record['cmdline'])
        self.verify(boot, manifest, [suffix])
        with self.assertRaises(verifier.VerifyError):
            self.verify(boot, manifest, [])

    def test_cmdline_append_across_header_boundary(self):
        suffix = 'x' * 600
        boot, record, manifest = self.package([suffix])
        header = boot[:builder.BOOT_HEADER_SIZE]
        self.assertEqual(header[builder.CMDLINE_OFFSET + 511], 0)
        self.assertGreater(len(record['cmdline']), 512)
        self.verify(boot, manifest, [suffix])

    def test_cmdline_forbids_autoreboot(self):
        with self.assertRaises(builder.BuildError):
            self.package(['lidar.autoreboot=240'])

    def test_kernel_config_rejects_development_marker(self):
        path = self.directory / 'config'
        path.write_text('CONFIG_MTK=y\nCONFIG_LIBREECHO_DEV_RECOVERY_MARKER=y\n')
        with self.assertRaises(builder.BuildError):
            builder.validate_kernel_config(path)
        path.write_text('# CONFIG_LIBREECHO_DEV_RECOVERY_MARKER is not set\n')
        builder.validate_kernel_config(path)

    def test_kernel_above_reserved_memory_is_refused(self):
        dtb = compile_dts(self.directory, lidar_dts(reserved_base='0x40081000'),
                          'low-reserved.dtb')
        with self.assertRaises(builder.BuildError) as caught:
            builder.build_image(self.stock, self.kernel, dtb, self.ramdisk)
        self.assertIn('reserved-memory', str(caught.exception))

    def test_refuses_mt8163_only_payloads(self):
        args = mock.Mock(audio_probe=Path('x'), wifi_dtb=None,
                         connectivity_bundle=None)
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                builder.reject_mt8163_payload(argparse.ArgumentParser(), args)

    def test_verifier_rejects_tampered_kernel(self):
        boot, _record, manifest = self.package()
        tampered = bytearray(boot)
        tampered[builder.PAGE_SIZE + builder.MKIMG_SIZE + 40] ^= 0xFF
        with self.assertRaises(verifier.VerifyError):
            self.verify(bytes(tampered), manifest)

    def test_verifier_rejects_tampered_ramdisk(self):
        boot, _record, manifest = self.package()
        tampered = bytearray(boot)
        offset = int(json.loads(json.dumps(manifest))['package']['android']
                     ['ramdisk_file_offset'], 16)
        tampered[offset + 8] ^= 0xFF
        with self.assertRaises(verifier.VerifyError):
            self.verify(bytes(tampered), manifest)

    def test_verifier_rejects_wrong_size_budget(self):
        boot, _record, manifest = self.package()
        manifest['package']['size_budget']['margin_to_16mib_bytes'] -= 1
        with self.assertRaises(verifier.VerifyError) as caught:
            self.verify(boot, manifest)
        self.assertIn('size budget', str(caught.exception))

    def test_verifier_rejects_audio_profile_claim(self):
        boot, _record, manifest = self.package()
        manifest['audio_profile'] = {'sha256': '0' * 64, 'size': 1}
        with self.assertRaises(verifier.VerifyError):
            self.verify(boot, manifest)

    def test_stock_dtb_change_is_detected(self):
        boot, _record, manifest = self.package()
        stock = bytearray(self.stock_path.read_bytes())
        stock[builder.PAGE_SIZE + builder.MKIMG_SIZE + 40] ^= 0x01
        self.stock_path.write_bytes(bytes(stock))
        with self.assertRaises(verifier.VerifyError):
            self.verify(boot, manifest)


if __name__ == '__main__':
    unittest.main()
