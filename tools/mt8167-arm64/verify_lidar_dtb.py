#!/usr/bin/env python3
"""Fail-closed verifier for the LibreEcho Lidar device tree.

The tree is read in Python so the check does not depend on fdtget.  It pins
the properties stock LK and the kernel need: the root compatible string that
selects the appended DTB, the ramdisk range in /chosen, the 0x80000 byte cap
that LK copies to tags_addr, and the syscon reboot-mode node that turns
``reboot("bootloader")`` into a watchdog reset with NONRST2 bit 2 set.
"""
from __future__ import annotations

import argparse
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

FDT_MAGIC = 0xD00DFEED
FDT_BEGIN_NODE = 1
FDT_END_NODE = 2
FDT_PROP = 3
FDT_NOP = 4
FDT_END = 9

MAX_DTB_SIZE = 0x80000
LIDAR_COMPATIBLE_PREFIX = 'amzn,lidar-'
LIDAR_PVT_COMPATIBLE = 'amzn,lidar-pvt'
WATCHDOG_BASE = 0x10007000
WATCHDOG_OFFSET = 0x24
WATCHDOG_MASK = 0x4
BOOTLOADER_MODE = 0x4


class ContractError(RuntimeError):
    """The DTB does not preserve a property the boot chain depends on."""


@dataclass
class FdtProperty:
    name: bytes
    value: bytes


@dataclass
class FdtNode:
    name: bytes
    properties: list[FdtProperty] = field(default_factory=list)
    children: list['FdtNode'] = field(default_factory=list)


@dataclass
class FlatFdt:
    root: FdtNode
    reservations: list[tuple[int, int]] = field(default_factory=list)


def _fail(label: str, message: str) -> None:
    raise ContractError(f'{label}: {message}')


def parse_fdt(blob: bytes, label: str = 'DTB') -> FlatFdt:
    if len(blob) < 40:
        _fail(label, 'shorter than a flattened device tree header')
    (magic, totalsize, off_struct, off_strings, off_rsvmap,
     version, _last_comp_version, _boot_cpuid, size_strings, size_struct) = (
        struct.unpack_from('>10I', blob, 0)
    )
    if magic != FDT_MAGIC:
        _fail(label, 'missing FDT magic')
    if totalsize < 40 or totalsize > len(blob):
        _fail(label, f'invalid totalsize {totalsize:#x} for {len(blob):#x} bytes')
    if off_struct + size_struct > totalsize or off_strings + size_strings > totalsize:
        _fail(label, 'structure or strings block lies outside the tree')
    if off_rsvmap < 40 or off_rsvmap > totalsize:
        _fail(label, 'invalid memory reservation map offset')
    if version < 16:
        _fail(label, f'unsupported FDT version {version}')

    reservations: list[tuple[int, int]] = []
    position = off_rsvmap
    while True:
        if position + 16 > totalsize:
            _fail(label, 'unterminated memory reservation map')
        address, size = struct.unpack_from('>QQ', blob, position)
        position += 16
        if address == 0 and size == 0:
            break
        reservations.append((address, size))

    strings = blob[off_strings:off_strings + size_strings]
    struct_block = blob[off_struct:off_struct + size_struct]
    position = 0
    stack: list[FdtNode] = []
    root: FdtNode | None = None

    def read_u32() -> int:
        nonlocal position
        if position + 4 > len(struct_block):
            _fail(label, 'truncated structure block')
        value = struct.unpack_from('>I', struct_block, position)[0]
        position += 4
        return value

    while True:
        token = read_u32()
        if token == FDT_NOP:
            continue
        if token == FDT_BEGIN_NODE:
            end = struct_block.find(b'\0', position)
            if end < 0:
                _fail(label, 'unterminated node name')
            name = struct_block[position:end]
            position = (end + 1 + 3) & ~3
            node = FdtNode(name)
            if stack:
                stack[-1].children.append(node)
            elif root is None:
                root = node
            else:
                _fail(label, 'second root node')
            stack.append(node)
            continue
        if token == FDT_END_NODE:
            if not stack:
                _fail(label, 'end of node without a begin')
            stack.pop()
            continue
        if token == FDT_PROP:
            length = read_u32()
            name_offset = read_u32()
            if name_offset >= len(strings):
                _fail(label, 'property name offset outside the strings block')
            end = strings.find(b'\0', name_offset)
            if end < 0:
                _fail(label, 'unterminated property name')
            name = strings[name_offset:end]
            if position + length > len(struct_block):
                _fail(label, f'truncated property {name!r}')
            value = struct_block[position:position + length]
            position = (position + length + 3) & ~3
            if not stack:
                _fail(label, 'property outside a node')
            stack[-1].properties.append(FdtProperty(name, value))
            continue
        if token == FDT_END:
            break
        _fail(label, f'unknown structure token {token}')
    if stack:
        _fail(label, 'unterminated node at the end of the structure block')
    if root is None:
        _fail(label, 'tree has no root node')
    return FlatFdt(root, reservations)


def serialize_fdt(tree: FlatFdt) -> bytes:
    strings = bytearray()
    name_offsets: dict[bytes, int] = {}

    def string_offset(name: bytes) -> int:
        if name not in name_offsets:
            name_offsets[name] = len(strings)
            strings.extend(name)
            strings.append(0)
        return name_offsets[name]

    struct_block = bytearray()

    def emit(node: FdtNode) -> None:
        struct_block.extend(struct.pack('>I', FDT_BEGIN_NODE))
        struct_block.extend(node.name)
        struct_block.append(0)
        struct_block.extend(b'\0' * (-len(struct_block) % 4))
        for prop in node.properties:
            struct_block.extend(struct.pack('>III', FDT_PROP, len(prop.value),
                                            string_offset(prop.name)))
            struct_block.extend(prop.value)
            struct_block.extend(b'\0' * (-len(prop.value) % 4))
        for child in node.children:
            emit(child)
        struct_block.extend(struct.pack('>I', FDT_END_NODE))

    emit(tree.root)
    struct_block.extend(struct.pack('>I', FDT_END))

    off_rsvmap = 40
    off_struct = off_rsvmap + 16 * (len(tree.reservations) + 1)
    off_strings = off_struct + len(struct_block)
    totalsize = off_strings + len(strings)
    header = struct.pack(
        '>10I', FDT_MAGIC, totalsize, off_struct, off_strings, off_rsvmap,
        17, 16, 0, len(strings), len(struct_block),
    )
    body = bytearray()
    for address, size in tree.reservations:
        body.extend(struct.pack('>QQ', address, size))
    body.extend(b'\0' * 16)
    return header + bytes(body) + bytes(struct_block) + bytes(strings)


def root_properties(tree: FlatFdt) -> dict[bytes, bytes]:
    return {prop.name: prop.value for prop in tree.root.properties}


def fdt_compatible(tree: FlatFdt, label: str = 'DTB') -> list[str]:
    value = root_properties(tree).get(b'compatible')
    if value is None:
        _fail(label, 'root has no compatible property')
    try:
        return [item.decode('ascii') for item in value.split(b'\0') if item]
    except UnicodeDecodeError as exc:
        raise ContractError(f'{label}: non-ASCII root compatible string') from exc


def validate_board_compatible(tree: FlatFdt, label: str = 'DTB') -> list[str]:
    compatible = fdt_compatible(tree, label)
    first = compatible[0] if compatible else ''
    if not first.startswith(LIDAR_COMPATIBLE_PREFIX):
        _fail(label, f'first root compatible {first!r} does not start with '
                     f'{LIDAR_COMPATIBLE_PREFIX!r}')
    if LIDAR_PVT_COMPATIBLE not in compatible:
        _fail(label, f'root compatible list lacks {LIDAR_PVT_COMPATIBLE!r}')
    return compatible


def _child(node: FdtNode, name: bytes) -> FdtNode | None:
    for child in node.children:
        if child.name == name:
            return child
    return None


def _set_property(node: FdtNode, name: bytes, value: bytes) -> None:
    for prop in node.properties:
        if prop.name == name:
            prop.value = value
            return
    node.properties.append(FdtProperty(name, value))


def chosen_initrd_properties(ramdisk_addr: int,
                             ramdisk_size: int) -> tuple[tuple[bytes, bytes], ...]:
    return (
        (b'linux,initrd-start', struct.pack('>Q', ramdisk_addr)),
        (b'linux,initrd-end', struct.pack('>Q', ramdisk_addr + ramdisk_size)),
    )


def set_chosen_initrd(dtb: bytes, ramdisk_addr: int, ramdisk_size: int,
                      label: str = 'DTB') -> bytes:
    """Return dtb with /chosen carrying the range from the boot header.

    LK copies the ramdisk to ramdisk_addr but writes the linux,initrd-* pair
    only for some boot modes, so the image publishes the range itself.  A tree
    that already carries the exact values is returned unchanged.
    """
    properties = chosen_initrd_properties(ramdisk_addr, ramdisk_size)
    tree = parse_fdt(dtb, label)
    chosen = _child(tree.root, b'chosen')
    if chosen is not None:
        current = {prop.name: prop.value for prop in chosen.properties}
        if all(current.get(name) == value for name, value in properties):
            return dtb
    else:
        chosen = FdtNode(b'chosen')
        tree.root.children.append(chosen)
    for name, value in properties:
        _set_property(chosen, name, value)
    return serialize_fdt(tree)


def validate_chosen_initrd(tree: FlatFdt, ramdisk_addr: int, ramdisk_size: int,
                           label: str = 'DTB') -> None:
    chosen = _child(tree.root, b'chosen')
    if chosen is None:
        _fail(label, 'no /chosen node for the initrd properties')
    current = {prop.name: prop.value for prop in chosen.properties}
    for name, expected in chosen_initrd_properties(ramdisk_addr, ramdisk_size):
        text = name.decode('ascii')
        value = current.get(name)
        if value is None:
            _fail(label, f'/chosen lacks {text}')
        if len(value) != 8:
            _fail(label, f'/chosen {text} is {len(value)} bytes, expected the '
                         'two-cell 64-bit form')
        actual = struct.unpack('>Q', value)[0]
        wanted = struct.unpack('>Q', expected)[0]
        if actual != wanted:
            _fail(label, f'/chosen {text} is {actual:#x}, expected {wanted:#x}')


def _cells(node: FdtNode, name: bytes, default: int) -> int:
    for prop in node.properties:
        if prop.name == name:
            if len(prop.value) != 4:
                raise ContractError(f'{name.decode()} is not one cell')
            return struct.unpack('>I', prop.value)[0]
    return default


def _regions(node: FdtNode, address_cells: int, size_cells: int,
             path: str) -> list[tuple[int, int, str]]:
    result: list[tuple[int, int, str]] = []
    for child in node.children:
        child_path = f'{path}/{child.name.decode("ascii", "replace")}'
        child_address = _cells(child, b'#address-cells', address_cells)
        child_size = _cells(child, b'#size-cells', size_cells)
        for prop in child.properties:
            if prop.name != b'reg':
                continue
            stride = (child_address + child_size) * 4
            if stride == 0 or len(prop.value) % stride:
                _fail(child_path, 'reserved-memory reg does not match its cell counts')
            for offset in range(0, len(prop.value), stride):
                values = struct.unpack_from(f'>{child_address + child_size}I',
                                             prop.value, offset)
                base = 0
                for value in values[:child_address]:
                    base = (base << 32) | value
                size = 0
                for value in values[child_address:]:
                    size = (size << 32) | value
                if size:
                    result.append((base, size, child_path))
        result.extend(_regions(child, child_address, child_size, child_path))
    return result


def reserved_memory_regions(tree: FlatFdt) -> list[tuple[int, int, str]]:
    address_cells = _cells(tree.root, b'#address-cells', 2)
    size_cells = _cells(tree.root, b'#size-cells', 2)

    def find(node: FdtNode, path: str) -> list[tuple[int, int, str]]:
        for child in node.children:
            child_path = f'{path}/{child.name.decode("ascii", "replace")}'
            if child.name == b'reserved-memory':
                return _regions(child,
                                _cells(child, b'#address-cells', address_cells),
                                _cells(child, b'#size-cells', size_cells),
                                child_path)
            found = find(child, child_path)
            if found:
                return found
        return []

    return find(tree.root, '')


def walk_nodes(node: FdtNode, path: str = '') -> Iterable[tuple[str, FdtNode]]:
    base = path.rstrip('/')
    current = f'{base}/{node.name.decode("ascii", "replace")}'
    yield current, node
    for child in node.children:
        yield from walk_nodes(child, current)


def _property_cell(node: FdtNode, name: bytes, path: str) -> int:
    for prop in node.properties:
        if prop.name == name:
            if len(prop.value) < 4:
                _fail(path, f'{name.decode()} is shorter than one cell')
            return struct.unpack('>I', prop.value[:4])[0]
    _fail(path, f'lacks {name.decode()}')
    raise AssertionError('unreachable')


def validate_reboot_mode(tree: FlatFdt, label: str = 'DTB') -> str:
    nodes = dict(walk_nodes(tree.root))
    for path, node in nodes.items():
        compatible = [item.decode('ascii', 'replace')
                      for prop in node.properties if prop.name == b'compatible'
                      for item in prop.value.split(b'\0') if item]
        if 'syscon-reboot-mode' not in compatible:
            continue
        offset = _property_cell(node, b'offset', path)
        mask = _property_cell(node, b'mask', path)
        mode = _property_cell(node, b'mode-bootloader', path)
        if (offset, mask, mode) != (WATCHDOG_OFFSET, WATCHDOG_MASK, BOOTLOADER_MODE):
            _fail(path, 'syscon-reboot-mode must use offset 0x24, mask 0x4, '
                        'mode-bootloader 0x4')
        parent_path = path.rsplit('/', 1)[0]
        parent = nodes.get(parent_path)
        if parent is not None:
            address_cells = _cells(tree.root, b'#address-cells', 2)
            for prop in parent.properties:
                if prop.name == b'reg':
                    if len(prop.value) < address_cells * 4:
                        _fail(path, 'parent reg is shorter than its address cells')
                    base = 0
                    for value in struct.unpack_from(f'>{address_cells}I', prop.value, 0):
                        base = (base << 32) | value
                    if base != WATCHDOG_BASE:
                        _fail(path, f'parent reg base is {base:#x}, expected '
                                    f'{WATCHDOG_BASE:#x}')
        return path
    _fail(label, 'no syscon-reboot-mode node for the reboot contract')
    raise AssertionError('unreachable')


def validate_lidar_dtb(source: bytes | Path,
                       ramdisk_addr: int | None = None,
                       ramdisk_size: int | None = None,
                       max_size: int = MAX_DTB_SIZE,
                       label: str = 'Lidar DTB') -> dict[str, object]:
    data = (Path(source).read_bytes()
            if isinstance(source, (str, Path)) else source)
    if len(data) > max_size:
        _fail(label, f'{len(data)} bytes exceed the {max_size:#x} byte cap LK '
                     'copies to tags_addr')
    tree = parse_fdt(data, label)
    compatible = validate_board_compatible(tree, label)
    reboot_path = validate_reboot_mode(tree, label)
    if (ramdisk_addr is None) != (ramdisk_size is None):
        raise ValueError('ramdisk_addr and ramdisk_size must be given together')
    if ramdisk_addr is not None and ramdisk_size is not None:
        validate_chosen_initrd(tree, ramdisk_addr, ramdisk_size, label)
    regions = reserved_memory_regions(tree)
    return {
        'size': len(data),
        'compatible': compatible,
        'reboot_mode_node': reboot_path,
        'reserved_memory': regions,
        'lowest_reserved_memory': min((base for base, _size, _path in regions),
                                      default=None),
        'reservations': list(tree.reservations),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description='Verify a Lidar device tree.')
    parser.add_argument('dtb', type=Path)
    parser.add_argument('--ramdisk-addr', type=lambda value: int(value, 0))
    parser.add_argument('--ramdisk-size', type=lambda value: int(value, 0))
    args = parser.parse_args()
    record = validate_lidar_dtb(args.dtb, args.ramdisk_addr, args.ramdisk_size)
    print(f'lidar_dtb_contract=PASS compatible={record["compatible"][0]} '
          f'reboot_mode={record["reboot_mode_node"]} '
          f'lowest_reserved_memory={record["lowest_reserved_memory"]} '
          f'size={record["size"]}')


if __name__ == '__main__':
    try:
        main()
    except ContractError as error:
        raise SystemExit(f'ERROR: {error}') from error
