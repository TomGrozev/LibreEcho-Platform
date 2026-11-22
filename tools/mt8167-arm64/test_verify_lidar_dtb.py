#!/usr/bin/env python3
"""Host tests for the Lidar device-tree contract. No device access."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import verify_lidar_dtb as contract

DTC_PATHS = (
    Path(os.environ['LIDAR_DTC']) if os.environ.get('LIDAR_DTC') else None,
    Path(shutil.which('dtc')) if shutil.which('dtc') else None,
)


def dtc() -> Path | None:
    for path in DTC_PATHS:
        if path is not None and path.is_file():
            return path
    return None


def compile_dts(directory: Path, text: str) -> bytes:
    tool = dtc()
    if tool is None:
        raise unittest.SkipTest('dtc is not available')
    source = directory / 'tree.dts'
    output = directory / 'tree.dtb'
    source.write_text(text)
    result = subprocess.run([str(tool), '-I', 'dts', '-O', 'dtb', '-o',
                             str(output), str(source)], text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode:
        raise AssertionError(result.stderr)
    return output.read_bytes()


def tree(first: str = 'amzn,lidar-pvt', pvt: bool = True,
         offset: str = '0x24', base: str = '0x10007000',
         include_reboot: bool = True) -> str:
    compatible = f'"{first}"'
    if pvt:
        compatible += ', "amzn,lidar-pvt"'
    compatible += ', "amzn,lidar"'
    reboot = f'''
        reboot-mode {{
            compatible = "syscon-reboot-mode";
            offset = <{offset}>;
            mask = <0x4>;
            mode-bootloader = <0x4>;
        }};''' if include_reboot else ''
    return f'''/dts-v1/;
/ {{
    model = "Amazon Lidar test";
    compatible = {compatible};
    #address-cells = <2>;
    #size-cells = <2>;

    reserved-memory {{
        #address-cells = <2>;
        #size-cells = <2>;
        ranges;
        region@48000000 {{
            reg = <0x0 0x48000000 0x0 0x100000>;
        }};
    }};

    watchdog@10007000 {{
        compatible = "mediatek,mt8167-wdt", "syscon";
        reg = <0x0 {base} 0x0 0x1000>;{reboot}
    }};
}};
'''


class LidarDtbTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if dtc() is None:
            raise unittest.SkipTest('dtc is not available')

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.directory = Path(self.tempdir.name)

    def tearDown(self):
        self.tempdir.cleanup()

    def test_valid_tree(self):
        blob = compile_dts(self.directory, tree())
        record = contract.validate_lidar_dtb(blob)
        self.assertEqual(record['compatible'][0], 'amzn,lidar-pvt')
        self.assertEqual(record['lowest_reserved_memory'], 0x48000000)
        self.assertEqual(record['reboot_mode_node'], '/watchdog@10007000/reboot-mode')

    def test_chosen_initrd_round_trip(self):
        blob = compile_dts(self.directory, tree())
        packed = contract.set_chosen_initrd(blob, 0x44000000, 0x1000)
        self.assertEqual(
            contract.set_chosen_initrd(packed, 0x44000000, 0x1000), packed)
        control = contract.validate_lidar_dtb(packed, 0x44000000, 0x1000)
        self.assertEqual(control['size'], len(packed))
        packed_tree = contract.parse_fdt(packed)
        chosen = next(child for child in packed_tree.root.children
                      if child.name == b'chosen')
        values = {prop.name: prop.value for prop in chosen.properties}
        self.assertEqual(len(values[b'linux,initrd-start']), 8)
        with self.assertRaises(contract.ContractError):
            contract.validate_lidar_dtb(packed, 0x44000000, 0x2000)

    def test_first_compatible_must_name_lidar(self):
        blob = compile_dts(self.directory, tree(first='amzn,lidar'))
        with self.assertRaises(contract.ContractError):
            contract.validate_lidar_dtb(blob)
        blob = compile_dts(self.directory, tree(first='other,board'))
        with self.assertRaises(contract.ContractError):
            contract.validate_lidar_dtb(blob)

    def test_pvt_compatible_is_required(self):
        blob = compile_dts(self.directory, tree(first='amzn,lidar-test', pvt=False))
        with self.assertRaises(contract.ContractError):
            contract.validate_lidar_dtb(blob)

    def test_reboot_node_is_required(self):
        blob = compile_dts(self.directory, tree(include_reboot=False))
        with self.assertRaises(contract.ContractError):
            contract.validate_lidar_dtb(blob)

    def test_reboot_offset_is_pinned(self):
        blob = compile_dts(self.directory, tree(offset='0x28'))
        with self.assertRaises(contract.ContractError):
            contract.validate_lidar_dtb(blob)

    def test_syscon_parent_base_is_pinned(self):
        blob = compile_dts(self.directory, tree(base='0x10008000'))
        with self.assertRaises(contract.ContractError):
            contract.validate_lidar_dtb(blob)

    def test_size_cap(self):
        with self.assertRaises(contract.ContractError):
            contract.validate_lidar_dtb(b'\0' * (contract.MAX_DTB_SIZE + 1))

    def test_cli(self):
        blob = compile_dts(self.directory, tree())
        path = self.directory / 'lidar.dtb'
        path.write_bytes(blob)
        result = subprocess.run(
            ['python3', str(Path(contract.__file__)), str(path)],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('lidar_dtb_contract=PASS', result.stdout)


if __name__ == '__main__':
    unittest.main()
