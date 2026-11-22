#!/usr/bin/env python3
"""Platform target table for the MT8167 ARM64 kernel with ARM32 userspace.

Adding a board is a table entry, not a new builder.  The runtime userspace in
``tools/mt8163-arm32`` serves both boards; it probes the partition layout or
reads ``/etc/libreecho/target`` and never asks ``uname`` which board it is on.
"""
from __future__ import annotations

import argparse
import os
import re

DEFAULT_TARGET = 'lidar'

# Partition geometry from the live GPT dump
# (lab-notes/phase-01/brom-printgpt.log:123-142 in the
# https://github.com/TomGrozev/libreecho-lidar-port archive), as (number,
# name, size in 512-byte sectors).  The Lidar layout has no recovery
# partition, and its 512 KiB misc partition distinguishes it from the MT8163
# layout (misc 1025 sectors, recovery at p12).
STORAGE_SECTOR_SIZE = 512
PARTITIONS = (
    (1, 'kb', 2048),
    (2, 'dkb', 2048),
    (3, 'lk_a', 2048),
    (4, 'tee1', 10240),
    (5, 'lk_b', 2048),
    (6, 'tee2', 10240),
    (7, 'expdb', 20480),
    (8, 'misc', 1024),
    (9, 'persist', 32768),
    (10, 'boot_a', 32768),
    (11, 'boot_b', 32768),
    (12, 'swdl', 65536),
    (13, 'system_a', 2506752),
    (14, 'system_b', 2506752),
    (15, 'cache', 65536),
    (16, 'userdata', 9647071),
)

# Stock LK reads the Amazon 7-byte BCB at misc+0x360.  The host installer may
# reset it only when the caller asks for that explicitly.
BCB_OFFSET = 0x360
BCB_RECORD_SIZE = 7

TARGETS = {
    'lidar': {
        'release_slug': 'lidar',
        'hw_profile': 'lidar@1',
        'fastboot_products': ('LIDAR',),
        'dtb_verifier': 'lidar',
        'soc': 'mt8167',
        'userspace_architecture': 'armv7',
        # Amazon shipped no Lidar audio profile.  A
        # target with audio=None renders no /etc/libreecho/audio-profile, so
        # the audio engine keeps its disabled state instead of reading a
        # guessed speaker policy.
        'audio': None,
        'partitions': PARTITIONS,
        'storage_sector_size': STORAGE_SECTOR_SIZE,
        'bcb': {'partition': 'misc', 'device': '/dev/mmcblk0p8',
                'offset': BCB_OFFSET, 'record_size': BCB_RECORD_SIZE},
    },
}


def validate_audio(audio: dict) -> dict:
    raise ValueError('the Lidar target table does not define audio profiles')


def audio_profile_bytes(target: str) -> bytes | None:
    """Return the rendered speaker policy, or None when the target has none."""
    record = get_target(target)
    if record['audio'] is None:
        return None
    raise ValueError(f'target {target!r} has no renderer in this profile')


def get_target(target: str) -> dict:
    if target not in TARGETS:
        raise ValueError(f'unknown target: {target!r}')
    return TARGETS[target]


def descriptor_digest(value: str | None) -> str | None:
    if value is not None and re.fullmatch(r'[0-9a-f]{64}', value) is None:
        raise ValueError('target descriptor digest must be 64 lowercase hex characters')
    return value


def identity_bytes(target: str, digest: str | None = None) -> bytes:
    record = get_target(target)
    digest = descriptor_digest(digest)
    text = (f'target_id={target}\nrelease_slug={record["release_slug"]}\n'
            f'hw_profile={record["hw_profile"]}\n')
    if digest is not None:
        text += f'descriptor_sha256={digest}\n'
    return text.encode('ascii')


def partition_device(target: str, name: str) -> str:
    for index, partition_name, _size_kb in get_target(target)['partitions']:
        if partition_name == name:
            return f'/dev/mmcblk0p{index}'
    raise ValueError(f'target {target!r} has no partition named {name!r}')


def add_target_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument('--target', default=os.environ.get('LIBREECHO_TARGET', DEFAULT_TARGET),
                        help='target ID (default: LIBREECHO_TARGET or lidar)')
    parser.add_argument('--target-descriptor-sha256', type=descriptor_digest,
                        help='canonical Product target descriptor SHA256')


def validate_target_arguments(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    try:
        record = get_target(args.target)
        descriptor_digest(args.target_descriptor_sha256)
        if record['soc'] != 'mt8167' or record['userspace_architecture'] != 'armv7':
            parser.error('this profile only builds mt8167 kernels with armv7 userspace')
    except ValueError as error:
        parser.error(str(error))
