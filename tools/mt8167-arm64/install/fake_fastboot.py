#!/usr/bin/env python3
"""A fake Lidar Kaeru fastboot, used only by the installer tests.

It emulates the surface the installer drives: the getvar answers measured on
the unit (lab-notes/phase-04/hw-20261117-k1-fetch-diag/getvar.log:1 and
lab-notes/phase-04/hw-20261117-k1-acm-flash/getvar-before.log:20-52 in the
libreecho-lidar-port archive), `oem fetch-enable`, raw and Android sparse
flash, 1 MiB fetch chunks, and failures for unknown partitions.

State lives under $FAKE_FASTBOOT_STATE:
  sizes.json      name -> byte size (the tests write it from the tool's table)
  parts/<name>    partition contents, created by the tests
  writes.log      one line per flash/fetch, so tests can prove what ran
Env overrides:
  FAKE_PRODUCT                 answer for getvar product
  FAKE_SIZE_OVERRIDE           "name=bytes,name=bytes"
  FAKE_CORRUPT_FETCH_PART      flip one byte in that partition's fetch output
"""
from __future__ import annotations

import json
import os
import struct
import sys
from pathlib import Path

SPARSE_MAGIC = 0xED26FF3A
MAX_FETCH = 0x100000

DEFAULT_SIZES = {
    'kb': 2048 * 512, 'dkb': 2048 * 512, 'lk_a': 2048 * 512,
    'tee1': 10240 * 512, 'lk_b': 2048 * 512, 'tee2': 10240 * 512,
    'expdb': 20480 * 512, 'misc': 1024 * 512, 'persist': 32768 * 512,
    'boot_a': 32768 * 512, 'boot_b': 32768 * 512, 'swdl': 65536 * 512,
    'system_a': 2506752 * 512, 'system_b': 2506752 * 512,
    'cache': 65536 * 512, 'userdata': 9647071 * 512,
}


class Fake:
    def __init__(self) -> None:
        self.state = Path(os.environ.get('FAKE_FASTBOOT_STATE', '.'))
        self.parts = self.state / 'parts'
        self.parts.mkdir(parents=True, exist_ok=True)
        sizes = DEFAULT_SIZES
        sizes_file = self.state / 'sizes.json'
        if sizes_file.exists():
            sizes = json.loads(sizes_file.read_text())
        override = os.environ.get('FAKE_SIZE_OVERRIDE', '')
        if override:
            sizes = dict(sizes)
            for item in override.split(','):
                if item:
                    name, value = item.split('=')
                    sizes[name] = int(value, 0)
        self.sizes = sizes
        self.writes = self.state / 'writes.log'

    def record(self, text: str) -> None:
        with open(self.writes, 'a', encoding='utf-8') as handle:
            handle.write(text + '\n')

    def fail(self, message: str) -> int:
        print(f'FAILED (remote: \'{message}\')')
        return 1

    def finish(self) -> None:
        print('Finished. Total time: 0.001s', file=sys.stderr)

    def getvar(self, name: str) -> int:
        if name == 'product':
            print(f'product: {os.environ.get("FAKE_PRODUCT", "LIDAR")}')
        elif name == 'kaeru-version':
            version = os.environ.get('FAKE_KAERU', '2.0.0-g66704e6-dirty')
            if not version:
                return self.fail('unknown variable')
            print(f'kaeru-version: {version}')
        elif name == 'max-fetch-size':
            print(f'max-fetch-size:0x{MAX_FETCH:x}')
        elif name.startswith('partition-size:'):
            partition = name.split(':', 1)[1]
            if partition not in self.sizes:
                return self.fail('Partition not found')
            print(f'{name}: {self.sizes[partition]:x}')
        else:
            return self.fail('unknown variable')
        self.finish()
        return 0

    def expand_sparse(self, data: bytes, name: str) -> bytes:
        magic, _major, _minor, file_header, chunk_header, block_size, \
            total_blocks, total_chunks, _checksum = struct.unpack_from('<IHHHHIIII', data)
        if magic != SPARSE_MAGIC:
            return data
        output = bytearray(total_blocks * block_size)
        offset = file_header
        written = 0
        for _ in range(total_chunks):
            chunk_type, _r, blocks, total_size = struct.unpack_from('<HHII', data, offset)
            payload = data[offset + chunk_header:offset + total_size]
            chunk_bytes = blocks * block_size
            if chunk_type == 0xCAC1:
                output[written:written + chunk_bytes] = payload
            elif chunk_type == 0xCAC2:
                output[written:written + chunk_bytes] = payload * (chunk_bytes // 4)
            elif chunk_type == 0xCAC3:
                pass
            elif chunk_type == 0xCAC4:
                pass
            else:
                raise ValueError('unknown sparse chunk')
            written += chunk_bytes
            offset += total_size
        return bytes(output)

    def flash(self, partition: str, path: str) -> int:
        if partition not in self.sizes:
            return self.fail('Partition not found')
        data = Path(path).read_bytes()
        sparse = struct.unpack_from('<I', data)[0] == SPARSE_MAGIC
        if sparse:
            data = self.expand_sparse(data, partition)
        if len(data) > self.sizes[partition]:
            return self.fail('image is larger than the partition')
        print(f'Sending {partition} ({len(data)} KB)')
        target = self.parts / f'{partition}.img'
        with open(target, 'r+b' if target.exists() else 'w+b') as handle:
            handle.write(data)
        self.record(f'flash {partition} bytes={len(data)} sparse={int(sparse)}')
        print(f'Writing {partition}')
        print('OKAY')
        self.finish()
        return 0

    def fetch(self, partition: str, output: str) -> int:
        if partition not in self.sizes:
            return self.fail('Partition not found')
        source = self.parts / f'{partition}.img'
        if not source.exists():
            source.write_bytes(bytes(self.sizes[partition]))
        data = source.read_bytes()
        if os.environ.get('FAKE_CORRUPT_FETCH_PART') == partition and data:
            data = bytearray(data)
            data[0] ^= 0xFF
            data = bytes(data)
        offset = 0
        while offset < len(data):
            size = min(MAX_FETCH, len(data) - offset)
            print(f'Fetching {partition} (offset={offset:x}, size={size:x})')
            offset += size
        Path(output).write_bytes(data)
        self.record(f'fetch {partition} bytes={len(data)}')
        self.finish()
        return 0


def main(argv: list[str]) -> int:
    fake = Fake()
    if not argv:
        return fake.fail('no command')
    command, args = argv[0], argv[1:]
    if command == 'getvar' and len(args) == 1:
        return fake.getvar(args[0])
    if command == 'oem':
        if args[:1] == ['fetch-enable']:
            print('OKAY')
            fake.finish()
            return 0
        if args[:1] == ['kaeru-version']:
            print('(bootloader) kaeru v2.0.0-g66704e6-dirty')
            print('OKAY')
            fake.finish()
            return 0
        return fake.fail('unknown oem command')
    if command == 'flash' and len(args) == 2:
        return fake.flash(args[0], args[1])
    if command == 'fetch' and len(args) == 2:
        return fake.fetch(args[0], args[1])
    if command == 'reboot':
        fake.record('reboot')
        print('OKAY')
        fake.finish()
        return 0
    return fake.fail(f'unknown command {command}')


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
