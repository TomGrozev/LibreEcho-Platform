#!/usr/bin/env python3
"""Tests for the Lidar host installer, driven through its CLI and a fake Kaeru."""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOL = HERE / 'lidar_install.py'
FAKE = HERE / 'fake_fastboot.py'
sys.path.insert(0, str(HERE))
import lidar_install as li  # noqa: E402
import expdb_guard  # noqa: E402

# The reviewed v2.0.0 expdb prefix: an MTK LK image header (magic, LE32 data
# size, "LK").  The size differs between builds, so only the magic is compared.
EXPDB_V2_PREFIX = bytes.fromhex('88168858d0400300') + b'LK\0\0\0\0\0\0'
EXPDB_BROKEN_PREFIX = b'FASTBOOT_PLEASE\0'


def expand_sparse_over(image: Path, target: Path, junk: int = 0xA5) -> None:
    """Expand ``image`` over ``target`` pre-filled with ``junk``.

    DONT_CARE regions keep the junk, so ext4-free blocks stay stale exactly
    like an eMMC block the sparse writer skipped; any allocated block the
    encoder wrongly skipped then makes ``e2fsck -fn`` fail.
    """
    data = image.read_bytes()
    (magic, _major, _minor, file_header, chunk_header, block_size,
     total_blocks, total_chunks, _checksum) = struct.unpack_from('<IHHHHIIII', data, 0)
    if magic != li.SPARSE_MAGIC:
        raise ValueError('not an Android sparse image')
    with open(target, 'wb') as handle:
        filler = bytes([junk]) * (1024 * 1024)
        remaining = total_blocks * block_size
        while remaining:
            take = min(remaining, len(filler))
            handle.write(filler[:take])
            remaining -= take
        offset = file_header
        written = 0
        for _ in range(total_chunks):
            chunk_type, _reserved, blocks, total_size = struct.unpack_from(
                '<HHII', data, offset)
            payload = data[offset + chunk_header:offset + total_size]
            length = blocks * block_size
            if chunk_type == li.SPARSE_RAW:
                handle.seek(written)
                handle.write(payload)
            elif chunk_type == li.SPARSE_FILL:
                handle.seek(written)
                handle.write(payload * (length // len(payload)))
            elif chunk_type != li.SPARSE_DONT_CARE:
                raise ValueError('unexpected sparse chunk')
            written += length
            offset += total_size


class InstallerCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix='lidar-install-test-'))
        self.state = self.tmp / 'state'
        self.state.mkdir()
        self.parts = self.state / 'parts'
        self.parts.mkdir()
        self.logdir = self.tmp / 'logs'
        self.expdb_prefix = EXPDB_V2_PREFIX
        (self.state / 'sizes.json').write_text(json.dumps(li.PARTITION_BYTES))
        os.chmod(FAKE, 0o755)
        for name in ('boot_a', 'boot_b'):
            (self.parts / f'{name}.img').write_bytes(bytes(li.BOOT_BYTES))
        self.make_misc(li.FRESH_BCB)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_cli(self, *args: str, env: dict[str, str] | None = None,
                timeout: float = 300):
        environment = dict(os.environ)
        environment['FAKE_FASTBOOT_STATE'] = str(self.state)
        environment.update(env or {})
        return subprocess.run(
            [sys.executable, str(TOOL), '--fastboot', str(FAKE),
             '--log-dir', str(self.logdir), *args],
            capture_output=True, text=True, env=environment, timeout=timeout)

    def run_main(self, *args: str, fetch_range=None,
                 env: dict[str, str] | None = None) -> tuple[int, str, str]:
        """Run the CLI in this process, with a fake ``fetch_range`` if given.

        The stock client is replaced by ``fake_fastboot.py``, which cannot
        answer a USB fetch, so ``Fastboot.fetch_range`` is patched for the
        userdata readback tests.
        """
        environment = dict(os.environ)
        environment['FAKE_FASTBOOT_STATE'] = str(self.state)
        environment.update(env or {})
        out, err = io.StringIO(), io.StringIO()
        with contextlib.ExitStack() as stack:
            stack.enter_context(unittest.mock.patch.dict(os.environ, environment))
            if fetch_range is not None:
                stack.enter_context(unittest.mock.patch.object(
                    li.Fastboot, 'fetch_range', fetch_range))
            stack.enter_context(contextlib.redirect_stdout(out))
            stack.enter_context(contextlib.redirect_stderr(err))
            code = li.main(['--fastboot', str(FAKE), '--log-dir', str(self.logdir),
                            *args])
        return code, out.getvalue(), err.getvalue()

    def fetch_range_from_parts(self, partition: str, offset: int,
                               length: int) -> bytes:
        """Serve ``fetch_range`` from the fake client's flashed partition."""
        if partition == 'expdb':
            return self.expdb_prefix[offset:offset + length]
        data = (self.parts / f'{partition}.img').read_bytes()
        return data[offset:offset + length]

    def make_misc(self, record: bytes | None = None) -> bytes:
        data = bytearray(bytes(range(256)) * (li.MISC_BYTES // 256))
        if record is not None:
            data[li.BCB_OFFSET:li.BCB_OFFSET + li.BCB_SIZE] = record
        (self.parts / 'misc.img').write_bytes(data)
        return bytes(data)

    def misc_bytes(self) -> bytes:
        return (self.parts / 'misc.img').read_bytes()

    def boot_image(self, name: str = 'boot.img', size: int = li.BOOT_BYTES,
                   magic: bytes = b'ANDROID!') -> Path:
        path = self.tmp / name
        data = bytearray(size)
        data[:len(magic)] = magic
        for offset in range(8, size, 4096):
            data[offset] = (offset // 4096) & 0xFF
        path.write_bytes(data)
        return path

    def batch(self) -> list[str]:
        log = self.state / 'writes.log'
        return log.read_text().splitlines() if log.exists() else []


class CheckTests(InstallerCase):
    def test_check_accepts_lidar_kaeru(self) -> None:
        result = self.run_cli('check')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('product=LIDAR', result.stdout)
        self.assertIn('check: Lidar Kaeru, geometry ok', result.stdout)

    def test_check_refuses_wrong_product(self) -> None:
        result = self.run_cli('check', env={'FAKE_PRODUCT': 'ECHO_PLUS'})
        self.assertEqual(result.returncode, 1)
        self.assertIn('wrong fastboot product', result.stderr)

    def test_check_refuses_missing_kaeru(self) -> None:
        result = self.run_cli('check', env={'FAKE_KAERU': ''})
        self.assertEqual(result.returncode, 1)
        self.assertIn('not Kaeru fastboot', result.stderr)

    def test_check_refuses_wrong_size(self) -> None:
        result = self.run_cli('check', env={'FAKE_SIZE_OVERRIDE': 'boot_a=16777217'})
        self.assertEqual(result.returncode, 1)
        self.assertIn('storage table says 16777216', result.stderr)

    def test_check_refuses_wrong_userdata_size(self) -> None:
        result = self.run_cli('check', env={'FAKE_SIZE_OVERRIDE': 'userdata=4939300864'})
        self.assertEqual(result.returncode, 1)
        self.assertIn('partition userdata', result.stderr)


class AllowListTests(unittest.TestCase):
    def test_system_a_refused(self) -> None:
        with self.assertRaises(li.Refusal):
            li.require_writable_partition('system_a')
        with self.assertRaises(li.Refusal):
            li.require_writable_partition('expdb')

    def test_misc_only_through_bcb(self) -> None:
        with self.assertRaises(li.Refusal):
            li.require_writable_partition('misc')
        li.require_writable_partition('misc', bcb=True)
        li.require_writable_partition('boot_a')
        li.require_writable_partition('userdata')


class ExpdbGuardTests(unittest.TestCase):
    def test_v2_kaeru_header_is_accepted(self) -> None:
        self.assertEqual(expdb_guard.check_expdb_prefix(EXPDB_V2_PREFIX), 'kaeru-v2')

    def test_fastboot_please_marker_is_refused(self) -> None:
        with self.assertRaisesRegex(expdb_guard.ExpdbGenerationError,
                                    'FASTBOOT_PLEASE'):
            expdb_guard.check_expdb_prefix(EXPDB_BROKEN_PREFIX)

    def test_blank_or_foreign_payload_is_refused(self) -> None:
        for prefix in (b'\0' * 16, b'ANDROID!' + b'\0' * 8):
            with self.subTest(prefix=prefix), \
                    self.assertRaisesRegex(expdb_guard.ExpdbGenerationError,
                                           'expected MTK magic'):
                expdb_guard.check_expdb_prefix(prefix)

    def test_short_or_missing_read_is_refused(self) -> None:
        for prefix in (None, b'', EXPDB_V2_PREFIX[:15]):
            with self.subTest(prefix=prefix), \
                    self.assertRaisesRegex(expdb_guard.ExpdbGenerationError,
                                           'unreadable'):
                expdb_guard.check_expdb_prefix(prefix)


class InstallTests(InstallerCase):
    def test_refuses_non_16mib_before_any_write(self) -> None:
        image = self.boot_image(size=8 * 1024 * 1024)
        result = self.run_cli('install', '--boot', str(image), '--yes')
        self.assertEqual(result.returncode, 2)
        self.assertIn('16', result.stderr)
        self.assertEqual(self.batch(), [])

    def test_refuses_bad_magic_before_any_write(self) -> None:
        image = self.boot_image(magic=b'NOTBOOT!')
        result = self.run_cli('install', '--boot', str(image), '--yes')
        self.assertEqual(result.returncode, 2)
        self.assertIn('ANDROID!', result.stderr)
        self.assertEqual(self.batch(), [])

    def test_refuses_without_yes(self) -> None:
        image = self.boot_image()
        result = self.run_cli('install', '--boot', str(image))
        self.assertEqual(result.returncode, 2)
        self.assertIn('--yes', result.stderr)
        self.assertEqual(self.batch(), [])

    def test_refuses_broken_expdb_before_any_write(self) -> None:
        self.expdb_prefix = EXPDB_BROKEN_PREFIX
        image = self.boot_image()
        code, out, err = self.run_main('install', '--boot', str(image), '--yes',
                                       fetch_range=self.fetch_range_from_parts)
        self.assertEqual(code, 2, err)
        self.assertIn('FASTBOOT_PLEASE', err)
        self.assertEqual(self.batch(), [])
        self.assertNotIn('flashed and verified', out)

    def test_refuses_unreadable_expdb_before_any_write(self) -> None:
        image = self.boot_image()

        def unreadable(_self, _partition: str, _offset: int, _length: int) -> bytes:
            raise li.InstallError('usb fetch expdb failed')

        code, _out, err = self.run_main('install', '--boot', str(image), '--yes',
                                        fetch_range=unreadable)
        self.assertEqual(code, 2, err)
        self.assertIn('cannot read expdb', err)
        self.assertEqual(self.batch(), [])

    def test_refuses_short_expdb_before_any_write(self) -> None:
        self.expdb_prefix = EXPDB_V2_PREFIX[:8]
        image = self.boot_image()
        code, _out, err = self.run_main('install', '--boot', str(image), '--yes',
                                        fetch_range=self.fetch_range_from_parts)
        self.assertEqual(code, 2, err)
        self.assertIn('unreadable', err)
        self.assertEqual(self.batch(), [])

    def test_flashes_both_slots_and_verifies(self) -> None:
        image = self.boot_image()
        code, out, err = self.run_main('install', '--boot', str(image), '--yes',
                                       fetch_range=self.fetch_range_from_parts)
        self.assertEqual(code, 0, err)
        self.assertIn('install: flashed and verified', out)
        expected = image.read_bytes()
        for name in ('boot_a', 'boot_b'):
            self.assertEqual((self.parts / f'{name}.img').read_bytes(), expected)
            self.assertTrue((self.logdir / 'install.log').read_text().count(name) >= 2)
        writes = self.batch()
        self.assertTrue(any(line.startswith('flash boot_a') for line in writes))
        self.assertTrue(any(line.startswith('flash boot_b') for line in writes))
        self.assertTrue(any(line.startswith('fetch boot_a') for line in writes))
        self.assertTrue(any(line.startswith('fetch boot_b') for line in writes))

    def test_boot_b_can_differ(self) -> None:
        first = self.boot_image('a.img')
        second = self.boot_image('b.img')
        second.write_bytes(second.read_bytes() + b'')
        second_data = bytearray(second.read_bytes())
        second_data[100] ^= 0xFF
        second.write_bytes(second_data)
        code, _out, err = self.run_main('install', '--boot', str(first),
                                        '--boot-b', str(second), '--yes',
                                        fetch_range=self.fetch_range_from_parts)
        self.assertEqual(code, 0, err)
        self.assertEqual((self.parts / 'boot_a.img').read_bytes(), first.read_bytes())
        self.assertEqual((self.parts / 'boot_b.img').read_bytes(), second.read_bytes())

    def test_userdata_prefix_verified(self) -> None:
        image = self.boot_image()
        raw = self.tmp / 'userdata.raw'
        data = bytearray(2 * 1024 * 1024)
        data[1024 + 0x38:1024 + 0x3A] = b'\x53\xef'
        data[1024 + 0x78:1024 + 0x88] = b'LIBREECHO_DATA\0\0'
        data[4096 * 100] = 0x5A
        raw.write_bytes(data)
        simg = self.tmp / 'userdata.simg'
        free = bytearray(b'\1') * 512
        free[0] = 0          # superblock and group descriptors
        free[100] = 0        # the 0x5A marker
        li.write_sparse(raw, simg, free, 2 * 1024 * 1024)
        self.assertEqual(li.validate_sparse(simg, li.USERDATA_BYTES)['total_blocks'], 512)
        result = self.run_main('install', '--boot', str(image),
                               '--userdata', str(simg), '--yes',
                               fetch_range=self.fetch_range_from_parts)
        code, out, err = result
        self.assertEqual(code, 0, err)
        self.assertIn('label LIBREECHO_DATA', out)
        self.assertEqual((self.parts / 'userdata.img').read_bytes(), bytes(data))

    def test_userdata_wrong_label_aborts(self) -> None:
        image = self.boot_image()
        raw = self.tmp / 'userdata.raw'
        data = bytearray(2 * 1024 * 1024)
        data[1024 + 0x38:1024 + 0x3A] = b'\x53\xef'
        data[1024 + 0x78:1024 + 0x88] = b'LIBREECHO_DATA\0\0'
        raw.write_bytes(data)
        simg = self.tmp / 'userdata.simg'
        free = bytearray(b'\1') * 512
        free[0] = 0
        li.write_sparse(raw, simg, free, 2 * 1024 * 1024)

        def other_label(_fb: li.Fastboot, partition: str, offset: int,
                        length: int) -> bytes:
            prefix = bytearray(self.fetch_range_from_parts(partition, offset, length))
            prefix[1024 + 0x78:1024 + 0x88] = b'OTHER_DATA' + bytes(6)
            return bytes(prefix)

        code, out, err = self.run_main('install', '--boot', str(image),
                                       '--userdata', str(simg), '--yes',
                                       fetch_range=other_label)
        self.assertEqual(code, 1)
        self.assertIn("label is 'OTHER_DATA'", err)
        self.assertNotIn('install: flashed and verified', out)

    def test_readback_mismatch_aborts(self) -> None:
        image = self.boot_image()
        code, out, err = self.run_main(
            'install', '--boot', str(image), '--yes',
            fetch_range=self.fetch_range_from_parts,
            env={'FAKE_CORRUPT_FETCH_PART': 'boot_a'})
        self.assertEqual(code, 1)
        self.assertIn('readback sha256', err)
        self.assertNotIn('install: flashed and verified', out)

    def test_bad_boot_a_readback_stops_before_next_flash(self) -> None:
        image = self.boot_image()
        raw = self.tmp / 'userdata.raw'
        data = bytearray(2 * 1024 * 1024)
        data[1024 + 0x38:1024 + 0x3A] = b'\x53\xef'
        data[1024 + 0x78:1024 + 0x88] = b'LIBREECHO_DATA\0\0'
        raw.write_bytes(data)
        simg = self.tmp / 'userdata.simg'
        free = bytearray(b'\1') * 512
        free[0] = 0
        li.write_sparse(raw, simg, free, 2 * 1024 * 1024)
        code, out, err = self.run_main(
            'install', '--boot', str(image), '--userdata', str(simg), '--yes',
            fetch_range=self.fetch_range_from_parts,
            env={'FAKE_CORRUPT_FETCH_PART': 'boot_a'})
        self.assertEqual(code, 1, err)
        self.assertIn('boot_a readback sha256', err)
        self.assertNotIn('install: flashed and verified', out)
        writes = self.batch()
        self.assertTrue(any(line.startswith('flash boot_a') for line in writes))
        self.assertFalse(any(line.startswith('flash boot_b') for line in writes))
        self.assertFalse(any(line.startswith('flash userdata') for line in writes))


class BcbTests(InstallerCase):
    def test_show_decodes_both_slots(self) -> None:
        result = self.run_cli('bcb', 'show')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('bcb_valid=yes', result.stdout)
        self.assertIn('selected_slot=a', result.stdout)
        self.assertIn('slot_a_priority=15', result.stdout)
        self.assertIn('slot_a_success=1', result.stdout)
        self.assertIn('slot_b_priority=0', result.stdout)

    def test_set_active_changes_only_bcb_bytes(self) -> None:
        before = self.make_misc(li.FRESH_BCB)
        code, out, err = self.run_main('bcb', 'set-active', 'B',
                                       fetch_range=self.fetch_range_from_parts)
        self.assertEqual(code, 0, err)
        after = self.misc_bytes()
        changed = {index for index in range(len(after)) if after[index] != before[index]}
        self.assertTrue(all(li.BCB_OFFSET <= index < li.BCB_OFFSET + li.BCB_SIZE
                            for index in changed))
        record = after[li.BCB_OFFSET:li.BCB_OFFSET + li.BCB_SIZE]
        self.assertEqual(record[li.BCB_SLOT_A], 0x8E)
        self.assertEqual(record[li.BCB_SLOT_B], 0x3F)
        backups = list(self.logdir.glob('misc-*-before.bin'))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), before)
        self.assertIn('selected_slot=b', out)

    def test_reset_writes_fresh_record(self) -> None:
        self.make_misc(bytes((0x00, 0x41, 0x42, 0x42, 0x01, 0x8E, 0x3F)))
        before = self.misc_bytes()
        code, out, err = self.run_main('bcb', 'reset',
                                       fetch_range=self.fetch_range_from_parts)
        self.assertEqual(code, 0, err)
        after = self.misc_bytes()
        changed = {index for index in range(len(after)) if after[index] != before[index]}
        self.assertTrue(all(li.BCB_OFFSET <= index < li.BCB_OFFSET + li.BCB_SIZE
                            for index in changed))
        self.assertEqual(after[li.BCB_OFFSET:li.BCB_OFFSET + li.BCB_SIZE], li.FRESH_BCB)
        self.assertIn('selected_slot=a', out)

    def test_set_active_refuses_unconfirmed_current(self) -> None:
        self.make_misc(b'\x00ABB\x01\x00\x00')
        code, out, err = self.run_main('bcb', 'set-active', 'B',
                                       fetch_range=self.fetch_range_from_parts)
        self.assertEqual(code, 1)
        self.assertIn('no bootable slot', err)

    def test_write_refuses_mismatched_expdb_before_flashing_misc(self) -> None:
        before = self.make_misc(li.FRESH_BCB)
        self.expdb_prefix = EXPDB_BROKEN_PREFIX
        code, _out, err = self.run_main('bcb', 'reset',
                                        fetch_range=self.fetch_range_from_parts)
        self.assertEqual(code, 2, err)
        self.assertIn('FASTBOOT_PLEASE', err)
        self.assertEqual(self.misc_bytes(), before)
        self.assertFalse(any(line.startswith('flash misc') for line in self.batch()))


class MakeUserdataTests(InstallerCase):
    def generation_tree(self, tx: str = 'txn-selftest-1') -> Path:
        tree = self.tmp / 'generation'
        (tree / 'features').mkdir(parents=True)
        lines = ['format=libreecho-ota-v3',
                 'manifest_version=1',
                 'board=lidar',
                 f'transaction_id={tx}',
                 'feature_ids=airplay2,tts,wakeword,stt,assistant']
        for feature in li.FEATURES:
            directory = tree / 'features' / feature
            directory.mkdir()
            payload = (b'payload-' + feature.encode('ascii') + b'\n') * 64
            manifest = ('{"feature":"' + feature + '"}\n').encode('ascii')
            (directory / 'payload.squashfs').write_bytes(payload)
            (directory / 'manifest.json').write_bytes(manifest)
            lines.append(f'feature_{feature}_size={len(payload)}')
            lines.append(f'feature_{feature}_sha256={hashlib.sha256(payload).hexdigest()}')
            lines.append(f'feature_{feature}_manifest_size={len(manifest)}')
            lines.append(
                f'feature_{feature}_manifest_sha256={hashlib.sha256(manifest).hexdigest()}')
        manifest_bytes = ('\n'.join(lines) + '\n').encode('ascii')
        (tree / 'target.manifest').write_bytes(manifest_bytes)
        (tree / 'target.manifest.sig').write_bytes(b'a' * 128 + b'\n')
        (tree / 'COMPLETE').write_bytes(
            (hashlib.sha256(manifest_bytes).hexdigest() + '\n').encode('ascii'))
        return tree

    def test_full_image_with_generation_tree(self) -> None:
        tree = self.generation_tree()
        package = self.tmp / 'local-install.ota.tar'
        package.write_bytes(b'ota-tar' * 64)
        os.chmod(package, 0o640)
        output = self.tmp / 'userdata.simg'
        raw = self.tmp / 'userdata.ext4'
        result = self.run_cli('make-userdata', '--output', str(output),
                              '--generation-tree', str(tree),
                              '--keep-raw', str(raw),
                              '--local-package', str(package))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(output.exists())

        header = output.read_bytes()[:28]
        magic, major, minor, file_header, chunk_header, block_size, \
            total_blocks, total_chunks, _checksum = struct.unpack('<IHHHHIIII', header)
        self.assertEqual((magic, major, minor, file_header, chunk_header),
                         (li.SPARSE_MAGIC, 1, 0, 28, 12))
        self.assertEqual(block_size, 4096)
        self.assertEqual(total_blocks, 1205883)
        self.assertEqual(total_blocks * block_size, li.SPARSE_BYTES)
        self.assertLess(total_blocks * block_size, li.USERDATA_BYTES)
        self.assertGreaterEqual(total_chunks, 1)
        li.validate_sparse(output, li.USERDATA_BYTES)

        prefix = li.sparse_prefix(output, 2048)
        self.assertEqual(li.superblock_label(prefix), 'LIBREECHO_DATA')

        stats = {
            path: li.debugfs_stat(raw, path)
            for path in (
                '/libreecho/generations/txn-selftest-1',
                '/libreecho/generations/txn-selftest-1/target.manifest',
                '/libreecho/generations/txn-selftest-1/features',
                '/libreecho/generations/txn-selftest-1/features/airplay2',
                '/libreecho/generations/txn-selftest-1/features/airplay2/payload.squashfs',
                '/libreecho/update/current',
                '/libreecho/update/incoming/local-install.ota.tar',
            )
        }
        for path, info in stats.items():
            self.assertEqual((info['uid'], info['gid']), (0, 0), path)
        self.assertEqual(stats['/libreecho/generations/txn-selftest-1']['mode'], 0o500)
        self.assertEqual(
            stats['/libreecho/generations/txn-selftest-1/target.manifest']['mode'], 0o400)
        self.assertEqual(
            stats['/libreecho/generations/txn-selftest-1/features/airplay2']['mode'], 0o500)
        self.assertEqual(
            stats['/libreecho/generations/txn-selftest-1/features/airplay2/'
                  'payload.squashfs']['mode'], 0o400)
        self.assertEqual(stats['/libreecho/update/current']['mode'], 0o600)
        self.assertEqual(
            stats['/libreecho/update/incoming/local-install.ota.tar']['mode'], 0o640)

        data = subprocess.run(['debugfs', '-R', 'cat /libreecho/update/current', str(raw)],
                              capture_output=True, text=True, check=True).stdout
        self.assertEqual(data.strip(), 'txn-selftest-1')

    def test_sparse_programs_allocated_blocks_over_junk(self) -> None:
        if not all(shutil.which(tool) for tool in ('mke2fs', 'dumpe2fs', 'e2fsck')):
            self.skipTest('e2fsprogs required')
        size = 32 * 1024 * 1024
        raw = self.tmp / 'small.ext4'
        with open(raw, 'wb') as handle:
            handle.truncate(size)
        subprocess.run(['mke2fs', *li.USERDATA_MKE2FS_OPTIONS, str(raw)],
                       capture_output=True, timeout=120, check=True)
        dump = subprocess.run(['env', 'LC_ALL=C', 'dumpe2fs', str(raw)],
                              capture_output=True, text=True, timeout=120, check=True)
        free = li._userdata_free_block_map(dump.stdout, size)
        allocated = sum(1 for value in free if not value)
        self.assertGreater(allocated, 0)
        simg = self.tmp / 'small.simg'
        geometry = li.write_sparse(raw, simg, free, size)
        self.assertEqual(geometry['programmed_bytes'], allocated * 4096)
        # Zeroed allocated runs (inode tables, journal) are FILL, so the file
        # stays far below the raw span while still programming every block.
        self.assertLess(simg.stat().st_size, size // 2)

        expanded = self.tmp / 'small.expanded'
        expand_sparse_over(simg, expanded, junk=0xA5)
        stale = next(index for index, value in enumerate(free) if value)
        with open(expanded, 'rb') as handle:
            handle.seek(stale * li.SPARSE_BLOCK_SIZE)
            self.assertEqual(handle.read(li.SPARSE_BLOCK_SIZE),
                             b'\xa5' * li.SPARSE_BLOCK_SIZE)
        result = subprocess.run(['e2fsck', '-fn', str(expanded)],
                                capture_output=True, text=True, timeout=300)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_manifest_hash_mismatch_refuses(self) -> None:
        tree = self.generation_tree()
        payload = tree / 'features' / 'tts' / 'payload.squashfs'
        data = bytearray(payload.read_bytes())
        data[0] ^= 0xFF
        payload.write_bytes(data)
        output = self.tmp / 'userdata.simg'
        result = self.run_cli('make-userdata', '--output', str(output),
                              '--generation-tree', str(tree))
        self.assertEqual(result.returncode, 1)
        self.assertIn('does not match manifest', result.stderr)
        self.assertFalse(output.exists())

    def test_extra_generation_entry_refuses(self) -> None:
        tree = self.generation_tree()
        (tree / 'extra').write_text('x')
        result = self.run_cli('make-userdata', '--output',
                              str(self.tmp / 'userdata.simg'),
                              '--generation-tree', str(tree))
        self.assertEqual(result.returncode, 1)
        self.assertIn('unexpected entries', result.stderr)


if __name__ == '__main__':
    unittest.main()
