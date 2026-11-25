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

# Partition geometry from the live GPT dump, as (number, name, size in
# 512-byte sectors).  The Lidar layout has no recovery
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

# The Lidar speaker and microphone policy.  Schema 1 stays key=value; the
# audio engine and the UI read the same file.  Key order is presentation only,
# but it is kept in the order the engine documents so diffs stay readable.
AUDIO_CHAINS = ('lidar',)
CODEC_PROFILES = ('Flat',)
PCM_FORMATS = ('s16_le', 's24_3le', 's32_le')
CAPTURE_ROLES = ('mic0', 'mic1', 'mic2', 'mic3', 'mic4', 'mic5', 'mic6',
                 'line-in')
AUDIO_KEYS = (
    'speaker_chain', 'codec_profile', 'hp_driver_gain', 'lo_driver_gain',
    'pre_gain_db', 'bass_makeup_db',
    'playback_card', 'playback_device', 'playback_rate', 'playback_channels',
    'playback_format',
    'capture_card', 'capture_device', 'capture_rate', 'capture_channels',
    'capture_format', 'capture_roles', 'capture_chain',
    'aec_source', 'aec_card', 'aec_device', 'aec_rate', 'aec_channels',
    'aec_format',
)
TARGETS = {
    'lidar': {
        'release_slug': 'lidar',
        'hw_profile': 'lidar@1',
        'fastboot_products': ('LIDAR',),
        'dtb_verifier': 'lidar',
        'soc': 'mt8167',
        'userspace_architecture': 'armv7',
        # The crossover, mono mix and amplifier enable live in the AIC32x4
        # DAC and machine driver, so there is no software speaker DSP.  The
        # codec's driver-gain index starts at -6 dB, so 6 is 0 dB, the stock
        # speaker level.  Playback is the stereo speaker PCM; capture is the
        # 8-channel DMIC array; AEC is a separate stereo PCM.
        'audio': {
            'speaker_chain': 'lidar', 'codec_profile': 'Flat',
            'hp_driver_gain': 6, 'lo_driver_gain': 6,
            'pre_gain_db': 0, 'bass_makeup_db': 0,
            'playback_card': 0, 'playback_device': 0,
            'playback_rate': 48000, 'playback_channels': 2,
            'playback_format': 's16_le',
            'capture_card': 0, 'capture_device': 1,
            'capture_rate': 16000, 'capture_channels': 8,
            'capture_format': 's32_le',
            'capture_roles': 'mic0,mic1,mic2,mic3,mic4,mic5,mic6,line-in',
            'capture_chain': 'lidar',
            'aec_source': 'separate-pcm', 'aec_card': 0, 'aec_device': 2,
            'aec_rate': 48000, 'aec_channels': 2, 'aec_format': 's16_le',
        },
        'partitions': PARTITIONS,
        'storage_sector_size': STORAGE_SECTOR_SIZE,
        'bcb': {'partition': 'misc', 'device': '/dev/mmcblk0p8',
                'offset': BCB_OFFSET, 'record_size': BCB_RECORD_SIZE},
    },
}


def _integer(audio: dict, key: str, low: int, high: int | None = None) -> int:
    value = audio[key]
    if not isinstance(value, int) or isinstance(value, bool) or value < low:
        raise ValueError(f'{key} must be an integer >= {low}')
    if high is not None and value > high:
        raise ValueError(f'{key} must be an integer <= {high}')
    return value


def validate_audio(audio: dict) -> dict:
    if set(audio) != set(AUDIO_KEYS):
        raise ValueError(f'audio profile keys must be exactly {AUDIO_KEYS}')
    if audio['speaker_chain'] not in AUDIO_CHAINS:
        raise ValueError(f'unknown speaker_chain: {audio["speaker_chain"]!r}')
    if audio['codec_profile'] not in CODEC_PROFILES:
        raise ValueError(f'unknown codec_profile: {audio["codec_profile"]!r}')
    _integer(audio, 'hp_driver_gain', 0, 35)
    _integer(audio, 'lo_driver_gain', 0, 35)
    for key, high in (('pre_gain_db', 12.0), ('bass_makeup_db', 6.0)):
        value = audio[key]
        if (not isinstance(value, (int, float)) or isinstance(value, bool)
                or not 0 <= value <= high):
            raise ValueError(f'{key} must be within 0..{high} dB')
    for prefix in ('playback', 'capture', 'aec'):
        _integer(audio, prefix + '_card', 0)
        _integer(audio, prefix + '_device', 0)
        _integer(audio, prefix + '_rate', 1)
        _integer(audio, prefix + '_channels', 1, 8)
        if audio[prefix + '_format'] not in PCM_FORMATS:
            raise ValueError(
                f'unknown {prefix}_format: {audio[prefix + "_format"]!r}')
    if audio['capture_chain'] not in AUDIO_CHAINS:
        raise ValueError(
            f'unknown capture_chain: {audio["capture_chain"]!r}')
    if audio['aec_source'] != 'separate-pcm':
        raise ValueError(f'unknown aec_source: {audio["aec_source"]!r}')
    roles = audio['capture_roles']
    role_list = roles.split(',') if isinstance(roles, str) else []
    if (not role_list or len(set(role_list)) != len(role_list)
            or any(role not in CAPTURE_ROLES for role in role_list)):
        raise ValueError('capture_roles must be unique known roles')
    return audio


def audio_profile_bytes(target: str) -> bytes:
    """Deterministic key=value rendering consumed by the audio engine."""
    audio = validate_audio(get_target(target)['audio'])
    text = 'schema=1\n' + f'target_id={target}\n'
    for key in AUDIO_KEYS:
        value = audio[key]
        text += f'{key}={value:.2f}\n' if isinstance(value, float) else f'{key}={value}\n'
    return text.encode('ascii')


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
