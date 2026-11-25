# Lidar preparation command

`lidar_prepare.py` is the reviewed replacement for the hand-run BROM session.
It takes the boot-chain backup, runs the same-byte restore drill
and stock-boot gate, installs the owner-access chain, and confirms Kaeru
fastboot.  It writes only boot-chain areas and never writes BOOT1 or expires
the `expdb` rule.

## Stages

| Command | Device access | Writes |
| --- | --- | --- |
| `identify` | tool `identity`, GPT and backup GPT reads | none |
| `backup` | reads every `lidar_backup_set.py` area twice | host files only |
| `drill` | reads, then writes identical bytes to the drill areas | gpt, gpt_backup, expdb, tee1, boot0 body, boot0 sector 0 last |
| `stock-boot` | none | none; records the operator's confirmation |
| `install` | reads, writes expdb, tee1, boot0 area 1 | expdb, tee1, boot0 area 1 (sector 0 last) |
| `confirm` | `fastboot getvar product` | none |
| `run` | all of the above in order | as above |

Every stage refuses to continue on a failed check.  Exit code 2 is a refusal
(the run stops at that check), 1 is a failed check or command, 0 is success.
A re-run after a partial install skips the expdb write only when expdb already
holds the byte-identical expected Kaeru stage and then continues with tee1 and
BOOT0; any other installed expdb content is refused.

## Usage

```sh
python3 lidar_prepare.py --amonet /opt/amonet identify

python3 lidar_prepare.py \
    backup --backup-dir lidar-backup

python3 lidar_prepare.py \
    drill --backup-dir lidar-backup --yes

# Power-cycle to a normal stock boot, then:
python3 lidar_prepare.py stock-boot --report lidar-stock-boot.json

# Back in BROM:
python3 lidar_prepare.py \
    install --backup-dir lidar-backup \
    --drill-report lidar-backup/drill-report.json \
    --stock-boot-report lidar-stock-boot.json \
    --kaeru lidar-kaeru.bin --kaeru-sha256 <hex> \
    --koboreru tee-payload-lidar.img --koboreru-sha256 <hex> --yes

python3 lidar_prepare.py confirm --fastboot fastboot
```

`--amonet` names the Amonet checkout; `AMONET` in the environment serves the
same purpose, and there is no built-in default.  The adapter runs
`modules/lidar_brom.py` from that checkout with this interpreter unless
`--amonet-python` names another.  With neither the flag nor the environment
variable set, or with a checkout that has no `modules/lidar_brom.py`, the
command exits 1 and the message names `--amonet` and `AMONET`.

The Amonet checkout is the only device tool.  No MediaTek download agent is
used: the Amonet payload runs from BROM SRAM and the command talks to the
Amonet CLI for every read and write.

`run` chains them with one session directory and `--yes`:

```sh
python3 lidar_prepare.py --amonet /opt/amonet run \
    --session-dir lidar-session \
    --kaeru ... --kaeru-sha256 ... \
    --koboreru ... --koboreru-sha256 ... --yes --stock-boot-ok
```

Add `--dry-run` to print every Amonet and fastboot command instead of
running it; it writes no host files.  Dry-run still validates the local input
files and their pinned digests; it prints, rather than checks, the
device-dependent gates.

Each stage requires its own approval: `drill` and `install` refuse without
`--yes`, and `run` also needs `--stock-boot-ok` or an interactive
`stock-boot-ok` token.

## Donor-derived artifacts

The stock preloader and the stock `tee1` tail come from the owner's backup, so
they are generated only under a private checkout directory (or outside a
checkout) and never shipped:

```sh
python3 lidar_donor_artifacts.py \
    --backup-dir lidar-backup \
    --out lidar-chain \
    --koboreru tee-payload-lidar.img --koboreru-sha256 <hex>
```

It first runs `lidar_backup_set.require_complete_backup`, then writes
`boot0-preloader.bin`, `tee1-stock.bin`, and, with Koboreru, the stock tail and
composed `tee1-stage.bin`, plus `donor-artifacts.json` with every digest.  The
`install` stage calls the same generator and consumes `tee1-stage.bin` and
`boot0-preloader.bin`; it no longer slices the backup itself.  Any output path
inside a git checkout must sit under a `private`, `local` or `local-firmware`
directory.

The stock Zigbee GBLs are captured from a host dump, never a device:

```sh
python3 capture_stock_gbls.py --source dump/system_a_rootfs \
    --out ../../../local-firmware
```

It verifies each known size and sha256 and writes a `local-firmware/.gitignore`
that keeps the files out of git.

The product release gate (`LibreEcho` `tools/prepare-release.py`,
`reject_donor_derived_artifacts`) refuses an asset with an MTK preloader/LK/TEE
or eMMC boot header, a Gecko GBL header, an EFR32 radio name, or a digest from
`donor-artifacts.json`.

## Chain layout

The chain install order:

1. `expdb` gets the source-built Kaeru LK stage padded with zeros to 0x40000.
2. A fresh `expdb[0:16]` read must pass `install/expdb_guard.py:check_expdb_prefix`.
3. `tee1` gets the source-built Koboreru image followed by the stock `tee1`
   tail from the verified backup.
4. BOOT0 area 1 gets the signed preloader from the verified backup's `boot0`
   file; bytes 512..end first, sector 0 last.
5. BOOT1 (area 2) is read before and after and must be unchanged.

The backup's preloader must hash to the reviewed 2019 signed image
(`fb987ad9...`), the only layout the Koboreru patch sites were derived from.
Any other preloader is refused: taking a
different one is an owner decision, not a command-line flag.

## Tests

```sh
python3 -m unittest -v test_lidar_prepare
```

The suite uses an in-memory fake adapter and a fake subprocess runner, so it
never opens USB or the network.  The same stages also run through the real
adapter against the Amonet simulated BROM when the sibling Amonet checkout
exists (or `AMONET` names it) and `LIDAR_BACKUP_DIR` names the reviewed Lidar
backup.  The backup path has no default because the reviewed dump is private
evidence; without `LIDAR_BACKUP_DIR` those cases print a skip reason.

## Files

| Path | Purpose |
| --- | --- |
| `lidar_prepare.py` | stages, GPT/geometry checks, chain install, CLI |
| `lidar_donor_artifacts.py` | donor-derived chain artifacts and digest manifest |
| `capture_stock_gbls.py` | verified copy of the stock Zigbee GBLs into `local-firmware/` |
| `amonet_adapter.py` | the Amonet seam and the adapter contract (`AdapterError`, `AdapterWriteRefused`, `Identity`): identity, area reads, pocket writes |
| `host_io.py` | shared hashing, timestamp and atomic-write helpers |
| `test_lidar_prepare.py` | host tests with a fake adapter, the runner and the Amonet simulator |
| `test_lidar_donor_artifacts.py` | synthetic backup and composition tests |
| `test_capture_stock_gbls.py` | synthetic rootfs capture tests |

Shared modules are imported from `../install/lidar_backup_set.py`,
`../install/expdb_guard.py`, and `../libreecho_platform_targets.py`; no data or
verifier is duplicated here.
