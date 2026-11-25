#!/usr/bin/env python3
"""Host installer for the Echo Plus 2nd Gen ("Lidar") over Kaeru fastboot.

Kaeru is stock LK with patches: ``getvar`` answers the identity and geometry
checks, ``fetch`` reads a partition back in at most 1 MiB pieces, and the stock
``flash`` path writes both raw and Android sparse images.  Facts this file
relies on.  Kaeru is https://github.com/R0rt1z2/kaeru.

* ``getvar product`` answers ``product: LIDAR``.  ``getvar kaeru-version``
  answers ``kaeru-version: 2.0.0-...``, and only Kaeru publishes that variable
  (kaeru ``lib/common.c:62``).
* ``getvar partition-size:<name>`` answers hex bytes
  (kaeru ``lib/fastboot/cmd_fetch.c:143-151``).
* ``oem fetch-enable`` publishes ``max-fetch-size`` and is what the stock
  fetch procedure runs first (kaeru ``lib/fastboot/cmd_fetch.c:164-191``).
* The fetch command is ``fetch:<name>[:<off>[:<len>]]`` and refuses more than
  0x100000 bytes per call (kaeru ``cmd_fetch.c:13,65-104``).  The stock
  fastboot client ``fetch PARTITION OUT_FILE`` therefore splits a partition
  into 1 MiB calls.
* That client has no range argument and asks for the next 1 MiB chunk as soon
  as the previous one lands, so stopping it after the first chunk leaves Kaeru
  inside a DATA phase; the next command then reads the abandoned stream instead
  of its own reply.  ``install`` therefore speaks
  ``fetch:<name>:<off>:<len>`` over USB directly for the userdata readback.
* ``oem kaeru-version`` is registered at kaeru ``lib/fastboot/cmd_version.c:25``
  and prints ``kaeru v<version>``.

Nothing here writes a partition that is not in ``WRITABLE_PARTITIONS``; ``misc``
is reachable only through ``bcb``.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import libreecho_platform_targets as targets  # noqa: E402
from expdb_guard import EXPDB_PREFIX_BYTES, ExpdbGenerationError, check_expdb_prefix  # noqa: E402

# The Lidar GPT is defined once, in the Platform target table; this module
# keeps only the sector counts it needs as names.
SECTOR_SIZE = targets.STORAGE_SECTOR_SIZE
PARTITIONS = {name: sectors for _number, name, sectors in targets.PARTITIONS}
PARTITION_BYTES = {name: sectors * SECTOR_SIZE for name, sectors in PARTITIONS.items()}
BOOT_SECTORS = PARTITIONS['boot_a']
BOOT_BYTES = BOOT_SECTORS * SECTOR_SIZE
MISC_SECTORS = PARTITIONS['misc']
MISC_BYTES = MISC_SECTORS * SECTOR_SIZE
USERDATA_SECTORS = PARTITIONS['userdata']
USERDATA_BYTES = USERDATA_SECTORS * SECTOR_SIZE
USERDATA_LABEL = 'LIBREECHO_DATA'
ANDROID_MAGIC = b'ANDROID!'

# One choke point.  misc is written only by the BCB commands, never by a
# generic flash, because a partial misc image would corrupt the only boot
# selector stock LK reads.
WRITABLE_PARTITIONS = frozenset({'boot_a', 'boot_b', 'userdata', 'misc'})
REQUIRED_SIZES = ('boot_a', 'boot_b', 'misc', 'userdata')

EXPECTED_PRODUCT = 'LIDAR'
MAX_FETCH_SIZE = 0x100000

# Kaeru fastboot enumerates as this USB identity.
LIDAR_FASTBOOT_VID = 0x0BB4
LIDAR_FASTBOOT_PID = 0x0C01
USB_READ_TIMEOUT_MS = 10000

# Amazon BCB: 7 bytes at misc+0x360, one metadata byte per slot
# (tools/mt8163-arm32/ota/libreecho_bootctl.c:22-25, 250-281).  The offset and
# record size are part of the Platform target table.
BCB_OFFSET = targets.BCB_OFFSET
BCB_SIZE = targets.BCB_RECORD_SIZE
BCB_SLOT_A = 5
BCB_SLOT_B = 6
# A fresh install leaves slot A confirmed (priority 15, tries 0, successful 1,
# i.e. slot_metadata(15,0,1) = 0x8f) and slot B untouched at zero.  That is the
# record bootctl's confirm path writes (libreecho_bootctl.c:405) and the one the
# VM harness seeds (ota-test-vm/build-initramfs.sh:89).
FRESH_BCB = bytes((0x00, 0x41, 0x42, 0x42, 0x01, 0x8F, 0x00))

FEATURES = ('airplay2', 'tts', 'wakeword', 'stt', 'assistant')
FEATURE_FILES = (('payload.squashfs', 'sha256', 'size'),
                 ('manifest.json', 'manifest_sha256', 'manifest_size'))
GENERATION_FILES = frozenset({'target.manifest', 'target.manifest.sig', 'COMPLETE'})
LOCAL_PACKAGE_MAX_BYTES = 32 * 1024 * 1024
GENERATION_ID = re.compile(r'[A-Za-z0-9._+~:-]{1,96}\Z')
HEX64 = re.compile(r'[0-9a-f]{64}\Z')
HEX128 = re.compile(r'[0-9a-f]{128}\Z')
UINT = re.compile(r'(?:0|[1-9][0-9]*)\Z')

SPARSE_MAGIC = 0xED26FF3A
SPARSE_RAW = 0xCAC1
SPARSE_FILL = 0xCAC2
SPARSE_DONT_CARE = 0xCAC3
SPARSE_CRC32 = 0xCAC4
# Stock Android userdata images on this LK use 4096-byte sparse blocks, so this
# follows the geometry the device is known to accept.  The ext4 filesystem ends
# at floor(4939300352 / 4096) blocks, 3584 bytes before the partition end; that
# shortfall is invisible because the runtime checks only the block device size
# and the label (libreecho-init:20-58), never the filesystem size.
SPARSE_BLOCK_SIZE = 4096
SPARSE_BYTES = USERDATA_BYTES // SPARSE_BLOCK_SIZE * SPARSE_BLOCK_SIZE
# LK writes this many bytes of the image to eMMC in one flash.  The product
# installer bounds the same quantity at 64 MiB (``tools/libreecho-install.py``,
# ``_validate_android_sparse_image``), which fits its ~1 GiB userdata.
# Lidar's partition is 4.9 GB: a correct allocation map programs the zeroed
# 64 MiB journal and ~74 MiB of inode tables that the host once skipped, about
# 147 MiB in total.  Those blocks must reach the device; skipping them left
# stale eMMC bytes as live ext4 metadata and the kernel logged "block bitmap
# and bg descriptor inconsistent".  192 MiB accepts the empty filesystem and
# stays below the size of a v1 generation image, which is delivered over adb
# instead of a single flash.
SPARSE_PROGRAMMED_MAX = 192 * 1024 * 1024

# mke2fs options shared by make_userdata and the sparse-allocation test.
# ``-m 0`` leaves no root-reserved pool, so ext4-free runs stay skippable.
# ``lazy_itable_init=0,lazy_journal_init=0`` makes mke2fs write every inode
# table and journal block itself; with lazy init the kernel would create that
# metadata after the sparse image was programmed, which is the mount-time
# repair path this tool must not depend on.
USERDATA_MKE2FS_OPTIONS = (
    '-q', '-F', '-t', 'ext4', '-b', str(SPARSE_BLOCK_SIZE),
    '-m', '0',
    '-O', '^64bit,^metadata_csum,^orphan_file',
    '-E', 'lazy_itable_init=0,lazy_journal_init=0',
    '-L', USERDATA_LABEL,
)


class InstallError(RuntimeError):
    """A failed check or command.  The run log has the details."""


class Refusal(InstallError):
    """The request is unsafe; nothing was written."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')


class RunLog:
    """Every fastboot command, its output and every hash land here."""

    def __init__(self, directory: Path, command: str):
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path = self.directory / f'{command}.log'
        self._handle = open(self.path, 'a', encoding='utf-8')

    def close(self) -> None:
        self._handle.close()

    def line(self, text: str) -> None:
        self._handle.write(text + '\n')
        self._handle.flush()

    def note(self, text: str) -> None:
        print(text)
        self.line(text)

    def command(self, argv: list[str], timeout: float, cwd: Path | None = None):
        started = time.monotonic()
        self.line(f'$ {" ".join(str(item) for item in argv)}')
        try:
            result = subprocess.run([str(item) for item in argv],
                                    cwd=str(cwd) if cwd else None,
                                    capture_output=True, text=True,
                                    timeout=timeout)
        except subprocess.TimeoutExpired as error:
            self.line(f'[timeout after {timeout}s]')
            raise InstallError(f'command timed out after {timeout}s: {argv[0]}') from error
        except OSError as error:
            self.line(f'[exec failed: {error}]')
            raise InstallError(f'cannot run {argv[0]}: {error}') from error
        elapsed = time.monotonic() - started
        self.line(f'[exit {result.returncode} in {elapsed:.2f}s]')
        if result.stdout:
            self.line('[stdout]\n' + result.stdout.rstrip('\n'))
        if result.stderr:
            self.line('[stderr]\n' + result.stderr.rstrip('\n'))
        return result

    def hash(self, label: str, path: Path) -> str:
        digest = sha256_file(path)
        self.line(f'[sha256] {digest}  {label} ({path.stat().st_size} bytes)')
        return digest


class Fastboot:
    def __init__(self, binary: str, log: RunLog):
        self.binary = binary
        self.log = log
        self.fetch_enabled = False

    def _run(self, args: list[str], timeout: float):
        return self.log.command([self.binary, *args], timeout=timeout)

    def getvar(self, name: str, timeout: float = 30.0) -> str | None:
        result = self._run(['getvar', name], timeout=timeout)
        text = result.stdout + '\n' + result.stderr
        pattern = re.compile(r'(?m)^\s*(?:\(bootloader\)\s*)?' + re.escape(name) +
                             r':\s*(\S+)\s*$')
        match = pattern.search(text)
        if result.returncode != 0 or match is None:
            return None
        return match.group(1)

    def enable_fetch(self) -> None:
        if self.fetch_enabled:
            return
        result = self._run(['oem', 'fetch-enable'], timeout=30.0)
        if result.returncode != 0:
            # Kaeru leaves max-fetch-size empty until this succeeds, so the
            # size check in check_device reports the failure.
            self.log.line('[warn] oem fetch-enable failed')
        self.fetch_enabled = True

    def flash(self, partition: str, image: Path, timeout: float = 900.0) -> None:
        result = self._run(['flash', partition, str(image)], timeout=timeout)
        text = (result.stdout + result.stderr).upper()
        if result.returncode != 0 or 'FAILED' in text:
            raise InstallError(f'fastboot flash {partition} failed')

    def fetch(self, partition: str, output: Path, timeout: float = 900.0) -> None:
        self.enable_fetch()
        if output.exists():
            output.unlink()
        result = self._run(['fetch', partition, str(output)], timeout=timeout)
        text = (result.stdout + result.stderr).upper()
        if result.returncode != 0 or 'FAILED' in text or not output.exists():
            raise InstallError(f'fastboot fetch {partition} failed')

    def fetch_range(self, partition: str, offset: int, length: int) -> bytes:
        """Read ``length`` bytes at ``offset`` with one bounded Kaeru fetch.

        The stock client has no offset argument: it streams the whole partition
        and queues the next 1 MiB chunk the moment the previous one lands, so
        killing it after the first chunk leaves Kaeru mid-DATA and the next
        command reads the abandoned stream.  Asking for one range on the
        USB link instead ends in Kaeru's OKAY and leaves the command state
        intact.
        """
        self.enable_fetch()
        command = f'fetch:{partition}:0x{offset:08x}:0x{length:08x}'
        self.log.line(f'$ usb {command}')
        try:
            import usb.core
            import usb.util
        except ImportError as error:
            raise InstallError(
                'pyusb is required for a bounded fetch; install python-pyusb '
                '(Arch) or python3-usb (Debian)') from error

        try:
            found = list(usb.core.find(find_all=True, idVendor=LIDAR_FASTBOOT_VID,
                                       idProduct=LIDAR_FASTBOOT_PID) or ())
        except usb.core.USBError as error:
            raise InstallError(f'cannot enumerate USB devices: {error}') from error
        if len(found) != 1:
            raise InstallError(
                f'expected exactly one USB device {LIDAR_FASTBOOT_VID:04x}:'
                f'{LIDAR_FASTBOOT_PID:04x} in fastboot, found {len(found)}')
        device = found[0]

        def read_reply() -> bytes:
            while True:
                reply = bytes(endpoint_in.read(64, timeout=USB_READ_TIMEOUT_MS))
                text = reply[4:].decode('ascii', 'replace').rstrip('\x00')
                if reply[:4] == b'INFO':
                    self.log.line(f'[usb info] {text}')
                    continue
                if reply[:4] == b'FAIL':
                    raise InstallError(f'usb fetch {partition} failed: {text}')
                return reply

        interface = None
        claimed = False
        data = bytearray()
        try:
            try:
                configuration = device.get_active_configuration()
            except usb.core.USBError:
                device.set_configuration()
                configuration = device.get_active_configuration()
            try:
                interface = configuration[(0, 0)]
            except ValueError as error:
                raise InstallError(
                    'fastboot USB interface (0,0) is missing') from error

            def bulk_endpoint(direction: int):
                return usb.util.find_descriptor(
                    interface, custom_match=lambda endpoint: (
                        usb.util.endpoint_direction(endpoint.bEndpointAddress) == direction
                        and usb.util.endpoint_type(endpoint.bmAttributes) ==
                        usb.util.ENDPOINT_TYPE_BULK))

            endpoint_out = bulk_endpoint(usb.util.ENDPOINT_OUT)
            endpoint_in = bulk_endpoint(usb.util.ENDPOINT_IN)
            if endpoint_out is None or endpoint_in is None:
                raise InstallError('fastboot USB interface has no bulk endpoints')
            usb.util.claim_interface(device, interface.bInterfaceNumber)
            claimed = True

            endpoint_out.write(command.encode('ascii'))
            header = read_reply()
            if header[:4] != b'DATA' or len(header) != 12:
                raise InstallError(
                    f'usb fetch {partition}: expected DATA header, got {header!r}')
            try:
                announced = int(header[4:12], 16)
            except ValueError as error:
                raise InstallError(
                    f'usb fetch {partition}: bad DATA header {header!r}') from error
            if announced != length:
                raise InstallError(
                    f'usb fetch {partition}: device announced {announced} bytes, '
                    f'asked for {length}')
            while len(data) < length:
                chunk = endpoint_in.read(min(64 * 1024, length - len(data)),
                                         timeout=USB_READ_TIMEOUT_MS)
                if not chunk:
                    raise InstallError(
                        f'usb fetch {partition}: stream ended at {len(data)} '
                        f'of {length} bytes')
                data += bytes(chunk)
            trailer = read_reply()
            if trailer[:4] != b'OKAY':
                raise InstallError(
                    f'usb fetch {partition}: expected OKAY, got {trailer!r}')
        except usb.core.USBError as error:
            raise InstallError(f'usb fetch {partition} failed: {error}') from error
        finally:
            if claimed and interface is not None:
                usb.util.release_interface(device, interface.bInterfaceNumber)
            usb.util.dispose_resources(device)
        self.log.line(f'[usb fetch {partition}: {len(data)} bytes at 0x{offset:x}]')
        return bytes(data)

    def reboot(self, timeout: float = 60.0) -> None:
        result = self._run(['reboot'], timeout=timeout)
        if result.returncode != 0:
            raise InstallError('fastboot reboot failed')


def parse_size(value: str | None) -> int | None:
    if value is None:
        return None
    text = value.strip()
    if text.lower().startswith('0x'):
        text = text[2:]
    try:
        return int(text, 16)
    except ValueError:
        return None


def require_writable_partition(partition: str, *, bcb: bool = False) -> None:
    """The single write allow-list.  Every flash passes through here."""
    if partition not in WRITABLE_PARTITIONS:
        raise Refusal(f'partition {partition} is not in the write allow-list '
                      f'({", ".join(sorted(WRITABLE_PARTITIONS))})')
    if partition == 'misc' and not bcb:
        raise Refusal('misc is only writable through the bcb commands')


def require_kaeru_expdb_chain(fb: Fastboot, log: RunLog) -> str:
    """Establish the expdb chain generation before a flash write.

    Platform AGENTS.md "Boot-chain safety" rule 2: read
    ``expdb[0:16]``; the MTK image magic means the v2.0.0 Kaeru payload is in
    place, an ASCII ``FASTBOOT_PLEASE`` means the chain is already broken.
    A short or failed read refuses exactly like a mismatch: the write path has
    no safe fallback.  ``fetch_range`` asks Kaeru for one bounded range, so a
    10 MiB expdb is never streamed.
    """
    try:
        prefix = fb.fetch_range('expdb', 0, EXPDB_PREFIX_BYTES)
        generation = check_expdb_prefix(prefix)
    except ExpdbGenerationError as error:
        raise Refusal(str(error)) from error
    except InstallError as error:
        raise Refusal(
            f'cannot read expdb[0:{EXPDB_PREFIX_BYTES}] for the chain-generation '
            f'check: {error}') from error
    log.note(f'expdb[0:{EXPDB_PREFIX_BYTES}]: {generation} '
             f'({prefix[:4].hex()}); chain generation ok')
    return generation


def check_device(fb: Fastboot, log: RunLog, *, full: bool) -> dict[str, int]:
    product = fb.getvar('product')
    log.note(f'product={product}')
    if product != EXPECTED_PRODUCT:
        raise InstallError(f'wrong fastboot product: {product!r}, expected '
                           f'{EXPECTED_PRODUCT!r}; this is not a Lidar Kaeru')
    version = fb.getvar('kaeru-version')
    log.note(f'kaeru_version={version}')
    if not version:
        raise InstallError('getvar kaeru-version is empty; this is not Kaeru fastboot')
    fb.enable_fetch()
    max_fetch = parse_size(fb.getvar('max-fetch-size'))
    log.note(f'max_fetch_size={max_fetch}')
    if max_fetch is None or max_fetch <= 0 or max_fetch > MAX_FETCH_SIZE:
        raise InstallError(f'unexpected max-fetch-size {max_fetch!r}; '
                           f'Kaeru caps it at 0x{MAX_FETCH_SIZE:x}')

    names = PARTITIONS if full else ('misc',)
    sizes: dict[str, int] = {}
    for name in names:
        reported = parse_size(fb.getvar(f'partition-size:{name}'))
        expected = PARTITION_BYTES[name]
        if reported is None:
            if name in REQUIRED_SIZES:
                raise InstallError(f'cannot query partition-size:{name}')
            log.note(f'partition {name}: size not reported, skipped')
            continue
        if reported != expected:
            raise InstallError(
                f'partition {name} is {reported} bytes, storage table says '
                f'{expected}; refusing')
        sizes[name] = reported
        log.note(f'partition {name}: {reported} ok')
    return sizes


def validate_boot_image(path: Path) -> None:
    """Exactly 16 MiB with the Android boot magic.

    verify_recovery_image.py exposes verify_image(stock, collection, ...),
    which needs the stock boot image, kernel, DTB and a build manifest; it is
    not a generic image check, so this tool does size and magic only.
    """
    size = path.stat().st_size
    if size != BOOT_BYTES:
        raise Refusal(f'{path} is {size} bytes, a Lidar boot slot is {BOOT_BYTES}')
    with open(path, 'rb') as handle:
        magic = handle.read(len(ANDROID_MAGIC))
    if magic != ANDROID_MAGIC:
        raise Refusal(f'{path} does not start with ANDROID! magic: {magic!r}')


def superblock_label(raw: bytes) -> str | None:
    """The runtime's own check: s_magic at 1024+0x38, label at 1024+0x78
    (libreecho-init:9-58)."""
    if len(raw) < 1024 + 0x88:
        return None
    superblock = raw[1024:2048]
    if struct.unpack_from('<H', superblock, 0x38)[0] != 0xEF53:
        return None
    name = superblock[0x78:0x88]
    return name.split(b'\0', 1)[0].decode('ascii', 'replace')


def _userdata_free_block_map(metadata: str, expected_bytes: int) -> bytearray:
    """Parse C-locale dumpe2fs output into one byte per 4096-byte block.

    1 means ext4 considers the block free.  Only complete per-group
    ``Free blocks:`` lists are accepted: the unindented filesystem-wide
    ``Free blocks:`` field is a COUNT, not a block number, and host
    SEEK_HOLE/SEEK_DATA information is never a filesystem allocation map.
    Ported from the product installer's strict parser
    (``tools/libreecho-install.py``).
    """
    blocks, remainder = divmod(expected_bytes, SPARSE_BLOCK_SIZE)
    if remainder or blocks < 1:
        raise InstallError('invalid userdata block geometry')

    def header(name: str) -> int:
        matches = re.findall('^' + re.escape(name) + r':[ \t]+([0-9]+)[ \t]*$',
                             metadata, re.M)
        if len(matches) != 1:
            raise InstallError(f'dumpe2fs missing or duplicate {name!r} header')
        return int(matches[0])

    if (header('Block size') != SPARSE_BLOCK_SIZE or
            header('Block count') != blocks or header('First block') != 0):
        raise InstallError('dumpe2fs geometry does not match userdata')
    expected_free = header('Free blocks')
    if not 0 < expected_free < blocks:
        raise InstallError('dumpe2fs reported an invalid free-block count')
    free = bytearray(blocks)
    group: tuple[int, int] | None = None
    next_group = 0
    next_block = 0
    group_free: int | None = None
    list_seen = False

    def finish_group() -> None:
        if group is not None:
            if group_free is None or not list_seen:
                raise InstallError('dumpe2fs omitted a userdata block-group free list')
            start, end = group
            if sum(free[start:end + 1]) != group_free:
                raise InstallError('dumpe2fs block-group free count mismatch')

    for line in metadata.splitlines():
        match = re.match(r'^Group ([0-9]+): \(Blocks ([0-9]+)-([0-9]+)\)', line)
        if line.startswith('Group '):
            if match is None:
                raise InstallError('dumpe2fs reported an invalid block-group header')
            finish_group()
            number, start, end = map(int, match.groups())
            if number != next_group or start != next_block or not start <= end < blocks:
                raise InstallError('dumpe2fs block-group coverage is inconsistent')
            group = (start, end)
            next_group += 1
            next_block = end + 1
            group_free = None
            list_seen = False
            continue
        if group is None:
            continue
        count = re.match(r'^\s+([0-9]+) free blocks,', line)
        if count:
            if group_free is not None:
                raise InstallError('dumpe2fs repeated a block-group free count')
            group_free = int(count[1])
        # Only the INDENTED per-group field is an allocation range list.
        ranges = re.fullmatch(r'[ \t]+Free blocks:[ \t]*(.*)', line)
        if ranges is None:
            continue
        if list_seen:
            raise InstallError('dumpe2fs repeated a block-group free list')
        list_seen = True
        previous = group[0] - 1
        text = ranges[1].strip()
        if not text:
            continue
        for item in text.split(','):
            bounds = re.fullmatch(r'([0-9]+)(?:-([0-9]+))?', item.strip())
            if bounds is None:
                raise InstallError('dumpe2fs reported an invalid free-block range')
            start = int(bounds[1])
            end = int(bounds[2] or bounds[1])
            if not group[0] <= start <= end <= group[1] or start <= previous:
                raise InstallError(
                    'dumpe2fs free-block range is overlapping or outside its group')
            free[start:end + 1] = b'\1' * (end - start + 1)
            previous = end
    finish_group()
    if next_block != blocks or sum(free) != expected_free or free[0]:
        raise InstallError('dumpe2fs free-block map is incomplete or inconsistent')
    return free


def write_sparse(raw_path: Path, output: Path, free: bytearray,
                 total_bytes: int | None = None) -> dict[str, int]:
    """Encode ``raw_path`` as an Android sparse image with 4096-byte blocks.

    ``free`` is one byte per block from :func:`_userdata_free_block_map`: 1 for
    ext4-free, 0 for allocated.  Free runs become DONT_CARE, and every
    allocated run is programmed.  Zeroed allocated blocks are FILL chunks, not
    skips: a fresh filesystem's inode tables, bitmaps and journal are all zero,
    and skipping them leaves stale bytes on eMMC that the mount then treats as
    metadata.

    Only the first ``total_bytes`` (default ``SPARSE_BYTES``) are encoded; the
    raw tail is the ext4 slack past the last filesystem block and must be zero.
    The span argument exists so tests can encode small images.
    """
    span = SPARSE_BYTES if total_bytes is None else total_bytes
    if span % SPARSE_BLOCK_SIZE:
        raise InstallError(f'sparse span {span} is not a multiple of {SPARSE_BLOCK_SIZE}')
    blocks = span // SPARSE_BLOCK_SIZE
    if len(free) != blocks:
        raise InstallError(
            f'free-block map has {len(free)} entries, expected {blocks}')
    read_blocks = 256  # 1 MiB RAW/FILL decision buffer
    total_blocks = 0
    total_chunks = 0
    programmed = 0

    with open(raw_path, 'rb') as source, open(output, 'w+b') as target:
        target.write(bytes(28))

        def emit(chunk_type: int, chunk_blocks: int, payload: bytes) -> None:
            nonlocal total_blocks, total_chunks, programmed
            target.write(struct.pack('<HHII', chunk_type, 0, chunk_blocks,
                                     12 + len(payload)))
            target.write(payload)
            total_blocks += chunk_blocks
            total_chunks += 1
            if chunk_type in (SPARSE_RAW, SPARSE_FILL):
                programmed += chunk_blocks * SPARSE_BLOCK_SIZE

        def emit_allocated(first: int, count: int) -> None:
            source.seek(first * SPARSE_BLOCK_SIZE)
            pending_zero = 0
            remaining = count
            while remaining:
                take = min(remaining, read_blocks)
                data = source.read(take * SPARSE_BLOCK_SIZE)
                if len(data) != take * SPARSE_BLOCK_SIZE:
                    raise InstallError(
                        f'{raw_path} is truncated inside allocated blocks')
                if data.count(0) == len(data):
                    pending_zero += take
                else:
                    if pending_zero:
                        emit(SPARSE_FILL, pending_zero, bytes(4))
                        pending_zero = 0
                    emit(SPARSE_RAW, take, data)
                remaining -= take
            if pending_zero:
                emit(SPARSE_FILL, pending_zero, bytes(4))

        start = 0
        while start < blocks:
            end = start + 1
            while end < blocks and free[end] == free[start]:
                end += 1
            if free[start]:
                emit(SPARSE_DONT_CARE, end - start, b'')
            else:
                emit_allocated(start, end - start)
            start = end
        source.seek(span)
        while True:
            extra = source.read(4 * 1024 * 1024)
            if not extra:
                break
            if extra.strip(b'\0'):
                raise InstallError(
                    f'{raw_path} has non-zero bytes beyond {span}')
        target.seek(0)
        target.write(struct.pack('<IHHHHIIII', SPARSE_MAGIC, 1, 0, 28, 12,
                                 SPARSE_BLOCK_SIZE, total_blocks, total_chunks, 0))
    return {'total_blocks': total_blocks, 'total_chunks': total_chunks,
            'programmed_bytes': programmed}


def validate_sparse(path: Path, partition_bytes: int) -> dict[str, int]:
    """Validate the sparse geometry against the Lidar userdata partition.

    The sparse span must fit inside the partition and may end short: the ext4
    filesystem stops at the last whole 4096-byte block, 3584 bytes before the
    partition end.  The product installer's exact-multiple preflight
    (``_validate_android_sparse_image`` in ``tools/libreecho-install.py``) is an
    integration item for that repo, not a constraint this runtime imposes.
    """
    size = path.stat().st_size
    if size < 28:
        raise InstallError(f'{path} is too short for a sparse header')
    with open(path, 'rb') as handle:
        header = handle.read(28)
        (magic, major, minor, file_header, chunk_header, block_size,
         total_blocks, total_chunks, _checksum) = struct.unpack('<IHHHHIIII', header)
        if (magic != SPARSE_MAGIC or major != 1 or minor != 0 or
                file_header != 28 or chunk_header != 12 or
                block_size != SPARSE_BLOCK_SIZE or total_chunks < 1):
            raise InstallError(f'{path} has an invalid Android sparse header')
        if total_blocks < 1 or total_blocks * block_size > partition_bytes:
            raise InstallError(
                f'{path} expands to {total_blocks * block_size} bytes, '
                f'outside 1..{partition_bytes} for userdata')
        offset = file_header
        expanded = 0
        programmed = 0
        dont_care = False
        for _ in range(total_chunks):
            handle.seek(offset)
            chunk = handle.read(chunk_header)
            if len(chunk) != chunk_header:
                raise InstallError(f'{path} has a truncated sparse chunk')
            chunk_type, _reserved, chunk_blocks, total_size = struct.unpack('<HHII', chunk)
            payload = total_size - chunk_header
            if total_size < chunk_header or offset + total_size > size:
                raise InstallError(f'{path} has an invalid sparse chunk size')
            if chunk_type == SPARSE_RAW:
                if payload != chunk_blocks * block_size:
                    raise InstallError(f'{path} has an invalid RAW chunk')
                programmed += chunk_blocks * block_size
            elif chunk_type == SPARSE_FILL:
                if payload != 4:
                    raise InstallError(f'{path} has an invalid FILL chunk')
                programmed += chunk_blocks * block_size
            elif chunk_type == SPARSE_DONT_CARE:
                if payload != 0:
                    raise InstallError(f'{path} has an invalid DONT_CARE chunk')
                dont_care = True
            elif chunk_type == SPARSE_CRC32:
                if payload != 4 or chunk_blocks != 0:
                    raise InstallError(f'{path} has an invalid CRC32 chunk')
            else:
                raise InstallError(f'{path} has an unknown sparse chunk type')
            expanded += chunk_blocks
            offset += total_size
        if offset != size or expanded != total_blocks:
            raise InstallError(f'{path} has inconsistent sparse geometry')
        if not dont_care:
            raise InstallError(
                f'{path} has no ext4-free DONT_CARE chunk; sparse skip mode failed')
        if programmed > SPARSE_PROGRAMMED_MAX:
            raise InstallError(
                f'{path} would make LK program {programmed} bytes in one flash; '
                f'limit is {SPARSE_PROGRAMMED_MAX}')
    return {'total_blocks': total_blocks, 'programmed_bytes': programmed}


def sparse_prefix(path: Path, length: int) -> bytes:
    """Expand only the first ``length`` bytes of a sparse image."""
    output = bytearray()
    with open(path, 'rb') as handle:
        header = handle.read(28)
        (magic, major, minor, file_header, chunk_header, block_size,
         total_blocks, total_chunks, _checksum) = struct.unpack('<IHHHHIIII', header)
        if magic != SPARSE_MAGIC or file_header != 28 or chunk_header != 12:
            raise InstallError(f'{path} has an invalid sparse header')
        handle.seek(file_header)
        for _ in range(total_chunks):
            if len(output) >= length:
                break
            chunk = handle.read(chunk_header)
            chunk_type, _reserved, chunk_blocks, total_size = struct.unpack('<HHII', chunk)
            payload_size = total_size - chunk_header
            chunk_bytes = chunk_blocks * block_size
            if chunk_type == SPARSE_RAW:
                data = handle.read(payload_size)
                output += data[:max(0, length - len(output))]
            elif chunk_type == SPARSE_FILL:
                value = handle.read(4)
                need = min(chunk_bytes, length - len(output))
                output += (value * ((need + 3) // 4))[:need]
            elif chunk_type in (SPARSE_DONT_CARE, SPARSE_CRC32):
                if chunk_type == SPARSE_CRC32:
                    handle.read(payload_size)
                    continue
                need = min(chunk_bytes, length - len(output))
                output += bytes(need)
            else:
                raise InstallError(f'{path} has an unknown sparse chunk type')
    return bytes(output[:length])


def check_userdata_image(path: Path) -> dict[str, int]:
    geometry = validate_sparse(path, USERDATA_BYTES)
    prefix = sparse_prefix(path, 1160)
    label = superblock_label(prefix.ljust(2048, b'\0'))
    if label != USERDATA_LABEL:
        raise InstallError(
            f'{path} does not carry the {USERDATA_LABEL} ext4 label (found {label!r})')
    return geometry


# ---------------------------------------------------------------- make-userdata


def _manifest(path: Path) -> dict[str, str]:
    try:
        text = path.read_bytes().decode('ascii')
    except (OSError, UnicodeDecodeError) as error:
        raise InstallError(f'cannot read {path} as ASCII: {error}') from error
    values: dict[str, str] = {}
    for line in text.splitlines():
        if not line or '=' not in line:
            raise InstallError(f'{path}: malformed manifest line {line!r}')
        key, value = line.split('=', 1)
        if key in values:
            raise InstallError(f'{path}: duplicate manifest key {key}')
        values[key] = value
    return values


def _uint(manifest: dict[str, str], key: str) -> int:
    value = manifest.get(key)
    if value is None or not UINT.match(value):
        raise InstallError(f'manifest key {key} is missing or not an unsigned integer')
    return int(value)


def _hash(manifest: dict[str, str], key: str) -> str:
    value = manifest.get(key, '')
    if not HEX64.match(value):
        raise InstallError(f'manifest key {key} is not 64 lowercase hex characters')
    return value


def _copy_hashed(source: Path, target: Path, mode: int) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with open(source, 'rb') as reader, open(target, 'wb') as writer:
        for block in iter(lambda: reader.read(1024 * 1024), b''):
            digest.update(block)
            writer.write(block)
            size += len(block)
    os.chmod(target, mode)
    return size, digest.hexdigest()


def stage_generation(tree: Path, transaction_id: str | None, local_package: Path | None,
                     staging: Path, log: RunLog) -> str:
    if not tree.is_dir():
        raise InstallError(f'{tree} is not a directory')
    entries: dict[str, Path] = {}
    for root, directories, files in os.walk(tree, followlinks=False):
        root_path = Path(root)
        for name in directories + files:
            full = root_path / name
            relative = full.relative_to(tree).as_posix()
            if full.is_symlink():
                raise InstallError(f'{full} is a symlink; a generation tree is regular files only')
            entries[relative] = full
    expected = set(GENERATION_FILES) | {'features'}
    for feature in FEATURES:
        expected.add(f'features/{feature}')
        for name, _hash_key, _size_key in FEATURE_FILES:
            expected.add(f'features/{feature}/{name}')
    missing = sorted(expected - set(entries))
    extra = sorted(set(entries) - expected)
    if missing:
        raise InstallError(f'generation tree is missing: {", ".join(missing)}')
    if extra:
        raise InstallError(f'generation tree has unexpected entries: {", ".join(extra)}')
    expected_dirs = {'features'} | {f'features/{feature}' for feature in FEATURES}
    for relative, path in entries.items():
        if path.is_dir():
            if relative not in expected_dirs:
                raise InstallError(f'{path} is an unexpected directory')
        elif not path.is_file():
            raise InstallError(f'{path} is not a regular file')

    manifest_path = tree / 'target.manifest'
    manifest = _manifest(manifest_path)
    if manifest.get('board') != 'lidar':
        raise InstallError(f'manifest board is {manifest.get("board")!r}, expected lidar')
    if manifest.get('format') != 'libreecho-ota-v3':
        raise InstallError('manifest format is not libreecho-ota-v3')
    listed = manifest.get('feature_ids', '').split(',')
    if sorted(listed) != sorted(FEATURES) or len(listed) != len(FEATURES):
        raise InstallError(f'manifest feature_ids must be exactly {",".join(FEATURES)}')
    tx = manifest.get('transaction_id', '')
    if not GENERATION_ID.match(tx):
        raise InstallError(f'manifest transaction_id {tx!r} is invalid')
    if transaction_id is not None and transaction_id != tx:
        raise InstallError(f'--transaction-id {transaction_id!r} does not match '
                           f'manifest transaction_id {tx!r}')

    signature = (tree / 'target.manifest.sig').read_bytes().strip()
    try:
        signature_text = signature.decode('ascii')
    except UnicodeDecodeError as error:
        raise InstallError('target.manifest.sig is not ASCII') from error
    if not HEX128.match(signature_text):
        raise InstallError('target.manifest.sig is not 128 lowercase hex characters')

    manifest_digest = sha256_file(manifest_path)
    complete = (tree / 'COMPLETE').read_text(encoding='ascii').strip()
    if complete != manifest_digest:
        raise InstallError('COMPLETE does not match the target.manifest hash')

    for feature in FEATURES:
        for name, hash_key, size_key in FEATURE_FILES:
            expected_hash = _hash(manifest, f'feature_{feature}_{hash_key}')
            expected_size = _uint(manifest, f'feature_{feature}_{size_key}')
            source = tree / 'features' / feature / name
            size = source.stat().st_size
            if size != expected_size:
                raise InstallError(
                    f'features/{feature}/{name} is {size} bytes, manifest says {expected_size}')
            digest = sha256_file(source)
            if digest != expected_hash:
                raise InstallError(
                    f'features/{feature}/{name} hash {digest} does not match manifest')

    generation = staging / 'libreecho' / 'generations' / tx
    generation.mkdir(parents=True)
    for relative in sorted(GENERATION_FILES):
        _copy_hashed(tree / relative, generation / relative, 0o400)
    for feature in FEATURES:
        feature_dir = generation / 'features' / feature
        feature_dir.mkdir(parents=True)
        for name, _hash_key, _size_key in FEATURE_FILES:
            _copy_hashed(tree / 'features' / feature / name, feature_dir / name, 0o400)
    os.chmod(generation / 'features', 0o500)
    for feature in FEATURES:
        os.chmod(generation / 'features' / feature, 0o500)
    os.chmod(generation, 0o500)
    log.note(f'generation {tx}: staged and re-hashed against target.manifest')

    update = staging / 'libreecho' / 'update'
    update.mkdir(parents=True)
    current = update / 'current'
    current.write_text(tx + '\n', encoding='ascii')
    os.chmod(current, 0o600)

    if local_package is not None:
        if not local_package.is_file():
            raise InstallError(f'{local_package} is not a regular file')
        size = local_package.stat().st_size
        if size > LOCAL_PACKAGE_MAX_BYTES:
            raise InstallError(f'{local_package} is {size} bytes; the device refuses '
                               f'more than {LOCAL_PACKAGE_MAX_BYTES}')
        incoming = update / 'incoming'
        incoming.mkdir(parents=True)
        source_mode = stat.S_IMODE(local_package.stat().st_mode)
        target = incoming / 'local-install.ota.tar'
        _copy_hashed(local_package, target, source_mode)
        # npf: the TWRP v3 installer copies with the source mode
        # (update-binary:833), so preserve it rather than invent one.
        if sha256_file(target) != sha256_file(local_package):
            raise InstallError('local-install package readback mismatch')
        log.note(f'local install package: {size} bytes, mode {source_mode:04o}')
    return tx


def debugfs_stat(image: Path, path: str) -> dict[str, int]:
    result = subprocess.run(['debugfs', '-R', f'stat {path}', str(image)],
                            capture_output=True, text=True, timeout=60)
    match_mode = re.search(r'Mode:\s+([0-7]+)', result.stdout)
    match_user = re.search(r'User:\s+(\d+)\s+Group:\s+(\d+)', result.stdout)
    match_size = re.search(r'Size:\s+(\d+)', result.stdout)
    if result.returncode != 0 or not match_mode or not match_user or not match_size:
        raise InstallError(f'debugfs cannot stat {path} in {image}: '
                           f'{result.stdout.strip()} {result.stderr.strip()}')
    return {'mode': int(match_mode.group(1), 8) & 0o7777,
            'uid': int(match_user.group(1)), 'gid': int(match_user.group(2)),
            'size': int(match_size.group(1))}


def verify_staged_tree(image: Path, staging: Path, transaction_id: str,
                       local_package: Path | None, log: RunLog) -> None:
    checked = {
        f'/libreecho/generations/{transaction_id}': (0o500, None),
        f'/libreecho/generations/{transaction_id}/target.manifest': (0o400, None),
        f'/libreecho/generations/{transaction_id}/target.manifest.sig': (0o400, None),
        f'/libreecho/generations/{transaction_id}/COMPLETE': (0o400, None),
        f'/libreecho/generations/{transaction_id}/features': (0o500, None),
        '/libreecho/update/current': (0o600, None),
    }
    for feature in FEATURES:
        base = f'/libreecho/generations/{transaction_id}/features/{feature}'
        checked[base] = (0o500, None)
        checked[base + '/payload.squashfs'] = (0o400, None)
        checked[base + '/manifest.json'] = (0o400, None)
    if local_package is not None:
        checked['/libreecho/update/incoming/local-install.ota.tar'] = (
            stat.S_IMODE(local_package.stat().st_mode), local_package.stat().st_size)
    for path, (mode, size) in checked.items():
        info = debugfs_stat(image, path)
        if info['mode'] != mode or info['uid'] != 0 or info['gid'] != 0:
            raise InstallError(
                f'{path} in the image is mode {info["mode"]:04o} '
                f'uid {info["uid"]} gid {info["gid"]}, expected '
                f'{mode:04o} root:root')
        if size is not None and info['size'] != size:
            raise InstallError(f'{path} is {info["size"]} bytes, expected {size}')
        log.line(f'[debugfs] {path}: mode {info["mode"]:04o} '
                 f'uid {info["uid"]} gid {info["gid"]} size {info["size"]}')
        print(f'  {path}: {info["mode"]:04o} root:root {info["size"]} bytes')


def make_userdata(output: Path, generation_tree: Path | None, transaction_id: str | None,
                  local_package: Path | None, keep_raw: Path | None,
                  log: RunLog) -> None:
    if output.exists():
        raise Refusal(f'{output} already exists')
    if transaction_id is not None and generation_tree is None:
        raise Refusal('--transaction-id requires --generation-tree')
    if keep_raw is not None and keep_raw.exists():
        raise Refusal(f'{keep_raw} already exists')
    for tool in ('mke2fs', 'dumpe2fs'):
        if shutil.which(tool) is None:
            raise InstallError(f'{tool} is required to build userdata')
    if generation_tree is not None and shutil.which('fakeroot') is None:
        raise InstallError('fakeroot is required to give staged files root ownership')
    if generation_tree is not None and shutil.which('debugfs') is None:
        raise InstallError('debugfs is required to verify the staged tree')

    output.parent.mkdir(parents=True, exist_ok=True)
    workspace = Path(tempfile.mkdtemp(prefix='lidar-userdata-'))
    try:
        staging = workspace / 'root'
        staging.mkdir()
        tx = None
        if generation_tree is not None:
            tx = stage_generation(generation_tree, transaction_id, local_package,
                                  staging, log)
        elif local_package is not None:
            update = staging / 'libreecho' / 'update' / 'incoming'
            update.mkdir(parents=True)
            _copy_hashed(local_package, update / 'local-install.ota.tar',
                         stat.S_IMODE(local_package.stat().st_mode))

        raw = workspace / 'userdata.ext4'
        with open(raw, 'wb') as handle:
            handle.truncate(USERDATA_BYTES)
        options = list(USERDATA_MKE2FS_OPTIONS)
        if generation_tree is not None or local_package is not None:
            # mke2fs -d records owners and modes from the tree it walks; under
            # fakeroot the tree is root-owned without needing real root.
            script = ('chown -R 0:0 "$1" && exec mke2fs ' + ' '.join(options) +
                      ' -d "$1" "$2"')
            result = log.command(['fakeroot', '/bin/sh', '-c', script, 'sh',
                                  str(staging), str(raw)], timeout=900)
        else:
            result = log.command(['mke2fs', *options, str(raw)], timeout=900)
        if result.returncode != 0:
            raise InstallError('mke2fs failed')

        with open(raw, 'rb') as handle:
            superblock = handle.read(2048)
        label = superblock_label(superblock)
        raw_size = raw.stat().st_size
        log.note(f'raw image: {raw_size} bytes, label {label!r}')
        if raw_size != USERDATA_BYTES:
            raise InstallError(f'raw image is {raw_size} bytes, expected {USERDATA_BYTES}')
        if label != USERDATA_LABEL:
            raise InstallError(f'raw image label is {label!r}, expected {USERDATA_LABEL}')
        # The runtime accepts a non-legacy size only above this floor
        # (libreecho-init:15,28-31); the measured Lidar partition clears it.
        if not 2137088 <= USERDATA_SECTORS <= 33554432:
            raise InstallError('userdata size is outside the runtime window')
        if tx is not None:
            verify_staged_tree(raw, staging, tx, local_package, log)

        temp_output = output.with_name(output.name + '.tmp')
        if temp_output.exists():
            temp_output.unlink()
        # env affects only this child process, not the caller's global locale.
        dump = log.command(['env', 'LC_ALL=C', shutil.which('dumpe2fs'), str(raw)],
                           timeout=900)
        if dump.returncode != 0:
            raise InstallError('dumpe2fs failed')
        free = _userdata_free_block_map(dump.stdout, SPARSE_BYTES)
        log.note(f'ext4 allocation: {len(free) - sum(free)} of {len(free)} blocks '
                 f'allocated, {sum(free)} free')
        geometry = write_sparse(raw, temp_output, free)
        log.note(f'sparse: {temp_output.stat().st_size} bytes, '
                 f'{geometry["total_blocks"]} blocks, '
                 f'{geometry["total_chunks"]} chunks, '
                 f'{geometry["programmed_bytes"]} programmed bytes')
        check_userdata_image(temp_output)
        log.hash('userdata sparse image', temp_output)
        os.replace(temp_output, output)
        print(f'wrote {output} ({output.stat().st_size} bytes, '
              f'expands to {geometry["total_blocks"] * SPARSE_BLOCK_SIZE}, '
              f'label {USERDATA_LABEL})')
        if keep_raw is not None:
            shutil.move(str(raw), keep_raw)
            log.hash('userdata raw image', keep_raw)
            print(f'kept {keep_raw}')
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


# --------------------------------------------------------------------- install


def verify_boot_readback(fb: Fastboot, log: RunLog, partition: str, image: Path,
                         workspace: Path) -> None:
    dump = workspace / f'{partition}.bin'
    fb.fetch(partition, dump)
    got = sha256_file(dump)
    want = sha256_file(image)
    log.note(f'readback {partition}: {dump.stat().st_size} bytes, sha256 {got}')
    if dump.stat().st_size != BOOT_BYTES:
        raise InstallError(f'{partition} readback is '
                           f'{dump.stat().st_size} bytes, expected {BOOT_BYTES}')
    if got != want:
        raise InstallError(f'{partition} readback sha256 {got} != {want}')


def verify_userdata_readback(fb: Fastboot, log: RunLog, image: Path) -> None:
    readback = fb.fetch_range('userdata', 0, MAX_FETCH_SIZE)
    label = superblock_label(readback.ljust(2048, b'\0'))
    if label != USERDATA_LABEL:
        raise InstallError(f'userdata readback label is {label!r}, '
                           f'expected {USERDATA_LABEL}')
    expected = sparse_prefix(image, len(readback))
    if readback != expected:
        raise InstallError('userdata prefix readback does not match the '
                           'sparse image')
    log.note(f'userdata readback: {len(readback)} bytes, label {label}')


def install(boot: Path, boot_b: Path | None, userdata: Path | None, assume_yes: bool,
            fb: Fastboot, log: RunLog) -> None:
    check_device(fb, log, full=True)
    validate_boot_image(boot)
    second = boot_b if boot_b is not None else boot
    validate_boot_image(second)
    userdata_geometry = None
    if userdata is not None:
        userdata_geometry = check_userdata_image(userdata)

    log.note(f'plan: flash boot_a <- {boot} ({boot.stat().st_size} bytes, '
             f'sha256 {sha256_file(boot)})')
    log.note(f'plan: flash boot_b <- {second} ({second.stat().st_size} bytes, '
             f'sha256 {sha256_file(second)})')
    if userdata is not None:
        log.note(f'plan: flash userdata <- {userdata} '
                 f'({userdata.stat().st_size} bytes, '
                 f'{userdata_geometry["programmed_bytes"]} programmed)')
        log.note(f'plan: fetch the first MiB of userdata and prove the '
                 f'{USERDATA_LABEL} label')
    log.note('plan: fetch each flashed partition and compare it to its source '
             'before the next write')
    if not assume_yes:
        raise Refusal('refusing to write without --yes')

    # Every write below follows this check (AGENTS.md "Boot-chain safety" rule
    # 2); there is no earlier flash in ``install`` that could run without it.
    require_kaeru_expdb_chain(fb, log)

    writes = [('boot_a', boot), ('boot_b', second)]
    if userdata is not None:
        writes.append(('userdata', userdata))
    workspace = Path(tempfile.mkdtemp(prefix='lidar-readback-'))
    try:
        for partition, image in writes:
            require_writable_partition(partition)
            log.note(f'flash {partition}: {image}')
            fb.flash(partition, image)
            # Verify before the next flash, so a bad write stops the run with
            # the remaining partitions still holding their previous contents.
            if partition == 'userdata':
                verify_userdata_readback(fb, log, image)
            else:
                verify_boot_readback(fb, log, partition, image, workspace)
        print('install: flashed and verified')
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


# ------------------------------------------------------------------------- bcb


def _slot_metadata(priority: int, tries: int, success: int) -> int:
    return priority | (tries << 4) | (success << 7)


def _slot_fields(record: bytes, index: int) -> tuple[int, int, int]:
    value = record[index]
    return value & 0x0F, (value >> 4) & 0x07, value >> 7


def _bcb_valid(record: bytes) -> bool:
    return len(record) == BCB_SIZE and record[0] == 0 and \
        record[1:4] == b'ABB' and record[4] == 1


def _selected_slot(record: bytes) -> int:
    first = 1 if _slot_fields(record, BCB_SLOT_B + 0)[0] > \
        _slot_fields(record, BCB_SLOT_A + 0)[0] else 0
    second = 1 - first
    if _slot_fields(record, 5 + first)[2] or _slot_fields(record, 5 + first)[1]:
        return first
    if _slot_fields(record, 5 + second)[2] or _slot_fields(record, 5 + second)[1]:
        return second
    return -1


def print_bcb(record: bytes) -> None:
    valid = _bcb_valid(record)
    print(f'schema=1')
    print(f'bcb_valid={"yes" if valid else "no"}')
    selected = _selected_slot(record) if valid else -1
    print(f'selected_slot={"-" if selected < 0 else "ab"[selected]}')
    for name, index in (('a', BCB_SLOT_A), ('b', BCB_SLOT_B)):
        priority, tries, success = _slot_fields(record, index)
        print(f'slot_{name}_priority={priority}')
        print(f'slot_{name}_tries={tries}')
        print(f'slot_{name}_success={success}')


def fetch_misc(fb: Fastboot, log: RunLog, workspace: Path) -> tuple[bytes, Path]:
    path = workspace / 'misc.bin'
    fb.fetch('misc', path)
    data = path.read_bytes()
    if len(data) != MISC_BYTES:
        raise InstallError(f'misc fetch returned {len(data)} bytes, expected {MISC_BYTES}')
    log.hash('misc readback', path)
    return data, path


def bcb_show(fb: Fastboot, log: RunLog) -> None:
    check_device(fb, log, full=False)
    workspace = Path(tempfile.mkdtemp(prefix='lidar-bcb-'))
    try:
        data, _path = fetch_misc(fb, log, workspace)
    finally:
        shutil.rmtree(workspace, ignore_errors=True)
    print_bcb(data[BCB_OFFSET:BCB_OFFSET + BCB_SIZE])


def bcb_write(fb: Fastboot, log: RunLog, target: int | None) -> None:
    check_device(fb, log, full=False)
    # The BCB update flashes misc; establish the chain generation first.
    require_kaeru_expdb_chain(fb, log)
    workspace = Path(tempfile.mkdtemp(prefix='lidar-bcb-'))
    try:
        original, _path = fetch_misc(fb, log, workspace)
        backup = log.directory / f'misc-{utc_stamp()}-before.bin'
        counter = 1
        while backup.exists():
            backup = log.directory / f'misc-{utc_stamp()}-before-{counter}.bin'
            counter += 1
        backup.write_bytes(original)
        log.hash('misc backup', backup)

        patched = bytearray(original)
        if target is None:
            patched[BCB_OFFSET:BCB_OFFSET + BCB_SIZE] = FRESH_BCB
            operation = 'reset'
        else:
            record = bytes(original[BCB_OFFSET:BCB_OFFSET + BCB_SIZE])
            if not _bcb_valid(record):
                raise InstallError('invalid Amazon BCB record; refusing to activate')
            current = _selected_slot(record)
            if current < 0:
                raise InstallError('BCB has no bootable slot')
            if not _slot_fields(record, 5 + current)[2]:
                raise InstallError('current slot is not confirmed successful')
            if target == current:
                raise InstallError('target slot is already selected')
            record = bytearray(record)
            record[5 + current] = _slot_metadata(14, 0, 1)
            record[5 + target] = _slot_metadata(15, 3, 0)
            patched[BCB_OFFSET:BCB_OFFSET + BCB_SIZE] = record
            operation = f'set-active {"A" if target == 0 else "B"}'
        assert patched[:BCB_OFFSET] == original[:BCB_OFFSET]
        assert patched[BCB_OFFSET + BCB_SIZE:] == original[BCB_OFFSET + BCB_SIZE:]

        image = workspace / 'misc.patched'
        image.write_bytes(patched)
        log.hash('misc patched image', image)
        require_writable_partition('misc', bcb=True)
        log.note(f'bcb {operation}: flashing misc')
        fb.flash('misc', image)
        readback_path = workspace / 'misc.readback'
        fb.fetch('misc', readback_path)
        readback = readback_path.read_bytes()
        if readback != bytes(patched):
            raise InstallError('misc readback does not equal the patched image')
        changed = [index for index in range(MISC_BYTES) if patched[index] != original[index]]
        if any(not BCB_OFFSET <= index < BCB_OFFSET + BCB_SIZE for index in changed):
            raise InstallError('misc bytes outside the BCB changed')
        log.note(f'bcb {operation}: readback identical, {len(changed)} bytes changed '
                 f'at 0x{BCB_OFFSET:x}..0x{BCB_OFFSET + BCB_SIZE - 1:x}')
        print_bcb(bytes(patched[BCB_OFFSET:BCB_OFFSET + BCB_SIZE]))
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


# ------------------------------------------------------------------------- cli


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description='Install LibreEcho on the Echo Plus 2nd Gen (Lidar) over Kaeru fastboot.')
    parser.add_argument('--fastboot', default='fastboot',
                        help='fastboot executable (default: fastboot on PATH)')
    parser.add_argument('--log-dir', default=None,
                        help='run log directory (default: ./lidar-install-logs/<UTC>)')
    sub = parser.add_subparsers(dest='command', required=True)

    sub.add_parser('check', help='read-only identity and partition-size check')

    make = sub.add_parser('make-userdata', help='build the sparse LIBREECHO_DATA image')
    make.add_argument('--output', required=True, type=Path, help='output .simg')
    make.add_argument('--generation-tree', type=Path,
                      help='v3 generation directory to stage on userdata')
    make.add_argument('--transaction-id', help='generation id (must match the manifest)')
    make.add_argument('--local-package', type=Path,
                      help='release OTA tar for update/incoming/local-install.ota.tar')
    make.add_argument('--keep-raw', type=Path, help='also keep the raw ext4 image here')

    ins = sub.add_parser('install', help='flash boot slots and userdata, then verify')
    ins.add_argument('--boot', required=True, type=Path)
    ins.add_argument('--boot-b', type=Path)
    ins.add_argument('--userdata', type=Path)
    ins.add_argument('--yes', action='store_true', help='confirm the planned writes')

    bcb = sub.add_parser('bcb', help='read or patch the Amazon BCB in misc')
    bsub = bcb.add_subparsers(dest='bcb_command', required=True)
    bsub.add_parser('show')
    set_active = bsub.add_parser('set-active')
    set_active.add_argument('slot', choices=('A', 'B'))
    bsub.add_parser('reset')

    sub.add_parser('reboot', help='fastboot reboot')
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    log_dir = Path(args.log_dir) if args.log_dir else \
        Path('lidar-install-logs') / utc_stamp()
    if args.command == 'bcb':
        command_name = f'bcb-{args.bcb_command}'
    else:
        command_name = args.command
    log = RunLog(log_dir, command_name)
    log.line(f'argv={" ".join(sys.argv[1:] if argv is None else argv)}')
    try:
        if args.command == 'make-userdata':
            make_userdata(args.output, args.generation_tree, args.transaction_id,
                          args.local_package, args.keep_raw, log)
        else:
            fb = Fastboot(args.fastboot, log)
            if args.command == 'check':
                check_device(fb, log, full=True)
                print('check: Lidar Kaeru, geometry ok')
            elif args.command == 'install':
                install(args.boot, args.boot_b, args.userdata, args.yes, fb, log)
            elif args.command == 'bcb':
                if args.bcb_command == 'show':
                    bcb_show(fb, log)
                elif args.bcb_command == 'set-active':
                    bcb_write(fb, log, 0 if args.slot == 'A' else 1)
                else:
                    bcb_write(fb, log, None)
            elif args.command == 'reboot':
                fb.reboot()
                log.note('reboot requested')
        log.line(f'result=ok log={log.path}')
        return 0
    except Refusal as error:
        log.line(f'result=refused error={error}')
        print(f'ERROR: {error}', file=sys.stderr)
        return 2
    except InstallError as error:
        log.line(f'result=failed error={error}')
        print(f'ERROR: {error}', file=sys.stderr)
        return 1
    finally:
        log.note(f'log: {log.path}')
        log.close()


if __name__ == '__main__':
    sys.exit(main())
