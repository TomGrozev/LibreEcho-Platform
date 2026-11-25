#!/usr/bin/env python3
"""Boot-chain generation guard for the Lidar installers.

Platform ``AGENTS.md`` "Boot-chain safety" rule 2 requires the chain
generation to be established before any flash write: on the amonet v2.0.0
chain ``expdb[0:16]`` starts with the MTK image header of the Kaeru LK-stage
patch payload.  A legacy ``FASTBOOT_PLEASE`` marker there means the chain is
already broken, and writing flash from that state is forbidden.

Both callers read the partition their own way -- the fastboot installer issues a
bounded ``fetch:expdb:0:16`` and the BROM preparation command reads the same
extent through the Amonet tool -- and pass the bytes here.  This module owns the
one decision, so a new caller cannot invent a weaker test.
"""

EXPDB_PREFIX_BYTES = 16
# MediaTek image header magic 0x58881688, little endian, as every MTK stage
# image begins.
MTK_IMAGE_MAGIC = b'\x88\x16\x88\x58'
FASTBOOT_PLEASE = b'FASTBOOT_PLEASE'
CHAIN_GENERATION = 'kaeru-v2'


class ExpdbGenerationError(RuntimeError):
    """The chain generation is not the reviewed v2.0.0 Kaeru chain."""


def check_expdb_prefix(prefix: bytes | None) -> str:
    """Return the chain generation for ``expdb[0:16]`` or raise.

    Only the v2.0.0 Kaeru chain may be written.  A short read, a legacy
    ``FASTBOOT_PLEASE`` marker, and any other payload all fail closed.
    """
    if prefix is None or len(prefix) < EXPDB_PREFIX_BYTES:
        got = 0 if prefix is None else len(prefix)
        raise ExpdbGenerationError(
            f'expdb[0:{EXPDB_PREFIX_BYTES}] is unreadable (got {got} bytes); '
            'refusing to write flash')
    if prefix.startswith(FASTBOOT_PLEASE):
        raise ExpdbGenerationError(
            'expdb begins with FASTBOOT_PLEASE: the boot chain is already '
            'broken; refusing to write flash')
    if prefix[:len(MTK_IMAGE_MAGIC)] != MTK_IMAGE_MAGIC:
        raise ExpdbGenerationError(
            f'expdb[0:{len(MTK_IMAGE_MAGIC)}] is {prefix[:len(MTK_IMAGE_MAGIC)].hex()}, '
            f'expected MTK magic {MTK_IMAGE_MAGIC.hex()} (amonet v2.0.0 Kaeru '
            'payload); refusing to write flash')
    return CHAIN_GENERATION
