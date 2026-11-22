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
                             'etc/libreecho/vendor-assets'}

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


def build_manifest(record: dict[str, object], ramdisk: bytes,
                   symlinks: dict[str, str], overlay: dict[str, dict[str, object]],
                   applets: list[str], elf_sha: str,
                   ota_key_sha: str) -> dict[str, object]:
    cpio = lzma.decompress(ramdisk, format=lzma.FORMAT_XZ)
    return {
        'schema_version': 2,
        'name': 'libreecho-lidar-arm64-v1-recovery',
        'status': 'PREPARED_NOT_FLASHED',
        'board': 'lidar',
        'audio_profile': None,
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

    def test_target_table_has_no_audio_profile(self):
        record = targets.get_target('lidar')
        self.assertIsNone(record['audio'])
        self.assertIsNone(targets.audio_profile_bytes('lidar'))
        self.assertEqual(record['soc'], 'mt8167')
        self.assertEqual(record['userspace_architecture'], 'armv7')
        self.assertEqual(len(record['partitions']), 16)
        self.assertEqual(targets.partition_device('lidar', 'boot_a'),
                         '/dev/mmcblk0p10')

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
