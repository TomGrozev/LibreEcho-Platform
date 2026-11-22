# Lidar host installer

`lidar_install.py` drives Kaeru fastboot on the Echo Plus 2nd Gen (Lidar) from a
Linux host.  It writes `boot_a`, `boot_b`, `userdata`, and the Amazon BCB in
`misc`, and nothing else.  Gear: MediaTek MT8167, 16 MiB Android boot images per
slot, ARM32 userspace with the ARM64 kernel.

## Usage

```sh
python3 lidar_install.py --fastboot fastboot check
python3 lidar_install.py make-userdata --output userdata.simg
python3 lidar_install.py make-userdata --output userdata.simg \
  --generation-tree <generation-dir> --local-package release.ota.tar
python3 lidar_install.py install --boot boot-lidar.img --userdata userdata.simg --yes
python3 lidar_install.py bcb show
python3 lidar_install.py bcb set-active B
python3 lidar_install.py bcb reset
python3 lidar_install.py reboot
```

Global options come before the subcommand:

- `--fastboot PATH` defaults to `fastboot` on `PATH`.
- `--log-dir DIR` defaults to `./lidar-install-logs/<UTC>`.  Every run appends
  the command lines, stdout, stderr, and file hashes to `<command>.log` there.

## What each command does

### check

Read-only.  Requires `getvar product` to be `LIDAR` (the value measured in
`lab-notes/phase-04/hw-20261117-k1-fetch-diag/getvar.log:1` in the
[libreecho-lidar-port](https://github.com/TomGrozev/libreecho-lidar-port)
archive) and `getvar kaeru-version` to answer (only Kaeru publishes it,
`lib/common.c:62` in [kaeru](https://github.com/R0rt1z2/kaeru)).  It queries
`max-fetch-size` and requires it to
be at most 1 MiB, then queries `partition-size:<name>` for all 16 Lidar
partitions and refuses on any difference from the storage table.  Nothing is
written.

### make-userdata

Host-only.  Builds an ext4 filesystem labelled `LIBREECHO_DATA` on the
9647071 * 512 = 4939300352 byte userdata partition, then encodes the filesystem
span as an Android sparse image.  The filesystem ends at
floor(4939300352 / 4096) = 1205883 blocks = 4939296768 bytes, 3584 bytes short
of the partition end; that shortfall is not visible to the runtime, which checks
the block device size and the label but never the filesystem size
(`libreecho-init:20-58`).  `check` and `install` still require the partition to
be exactly 9647071 * 512 bytes, and the sparse span must fit inside it.

The runtime accepts this size only when the label is present
(`libreecho-init:12`) and mounts `rw,nosuid,nodev,noatime`
(`libreecho-init:995`); `libreecho-update:38-56` applies the same identity
check.  `mke2fs` runs with `-O ^64bit,^metadata_csum,^orphan_file` so the image
does not need recent kernel features, and the journal, extents, and flex_bg
features stay on.  It also runs `-m 0` and `-E lazy_itable_init=0,
lazy_journal_init=0`: no root-reserved pool, and every inode table and journal
block is written by the host instead of being initialized by the kernel after
the flash.

Sparse block size is 4096, the size stock Android userdata images use on this
LK.  The encoder is in this file so the tool stays stdlib-only and does not
depend on `img2simg`.

The encoder does not treat zero bytes as skippable.  It parses `LC_ALL=C
dumpe2fs` output strictly, requires complete per-group `Free blocks:` lists,
and builds one allocation bit per block.  Only ext4-free runs become
`DONT_CARE`; every allocated block is programmed, with all-zero allocated runs
sent as `FILL` chunks.  A fresh filesystem's block bitmaps, inode tables, and
journal are almost entirely zero, and skipping them left stale eMMC bytes that
the mounted kernel read as ext4 metadata
(`lab-notes/phase-05/hw-20261118/step3/dmesg-1.txt:311-314`).  For this
partition that is about 147 MiB programmed (64 MiB journal plus inode tables),
so `SPARSE_PROGRAMMED_MAX` is 192 MiB; a v1 generation image is larger and is
delivered over adb instead of a single flash.

With `--generation-tree DIR` the tool stages the v3 generation exactly as the
TWRP v3 installer leaves it:

| path | mode |
| --- | --- |
| `/libreecho/generations/<tx>/target.manifest`, `.sig`, `COMPLETE` | 0400 |
| `/libreecho/generations/<tx>/features/<f>/payload.squashfs`, `manifest.json` | 0400 |
| generation and feature directories | 0500 |
| `/libreecho/update/current` (transaction id plus newline) | 0600 |
| `/libreecho/update/incoming/local-install.ota.tar` | source mode |

Ownership is root:root.  Before formatting, the tool re-checks the tree against
`target.manifest`: exact file set, the five feature ids, sizes, sha256 values,
the manifest transaction id, `COMPLETE`, and the 128-hex signature text.  It
does not verify the Ed25519 signature; the device does that against
`/etc/libreecho/ota-public-key.hex`.  After `mke2fs -d`, `debugfs` proves every
staged owner and mode.

`--local-package` must be a regular file of at most 32 MiB, the limit
`libreecho-update` enforces (`update-binary:68`).  `--keep-raw PATH` also keeps
the pre-sparse ext4 image for inspection; delete it afterwards.

### install

Runs `check`, then validates each boot image: exactly 16 MiB and starting with
`ANDROID!`.  `verify_recovery_image.py` exposes `verify_image(stock, ...)`,
which needs the stock boot image, kernel, DTB and build manifest, so it is not a
generic boot-image verifier; this tool checks size and magic only.

It prints the planned writes and refuses unless `--yes` is given.  Then it
flashes `boot_a`, `boot_b` (`--boot-b` defaults to `--boot`), and optionally
`userdata`, verifying each one immediately after its flash so a mismatch stops
the run before the next partition is overwritten:

- full fetch of the boot slot just flashed, size 16 MiB, sha256 equal to the
  source;
- a fetch of the first 1 MiB of userdata with the ext4 superblock label read
  back, compared byte for byte with the sparse image prefix.

The userdata read asks Kaeru for one bounded chunk with
`fetch:userdata:0x00000000:0x00100000` and returns to the prompt after its
`OKAY`.  The stock client has no range option for `fetch`, and stopping it after
the first chunk leaves Kaeru inside a DATA phase that desynchronises the next
command, so this path speaks the command on the USB link: it finds the single
`0bb4:0c01` fastboot interface with pyusb, writes the command, reads the
`DATA` header, the payload and `OKAY`.  That needs pyusb installed for the
host python: `python-pyusb` on Arch, `python3-usb` on Debian.  `install` also
needs it for the expdb chain-generation read, and so do `bcb set-active` and
`bcb reset`; `check`, `bcb show`, and `reboot` run only the `--fastboot`
client.

Every flash passes one allow-list.  `system_a`, `system_b`, `expdb`, `lk_a`,
`lk_b`, `tee1`, `tee2`, `persist`, `kb`, `dkb`, `swdl`, and `cache` are refused.
`misc` is refused outside the `bcb` commands.

### bcb

`bcb show` fetches the whole 512 KiB misc partition and decodes the 7-byte
Amazon BCB at offset `0x360` (`libreecho_bootctl.c:22-25,250-281`).

`bcb set-active A|B` follows bootctl's `activate` byte for byte
(`libreecho_bootctl.c:355-372`): the current confirmed slot becomes priority
14, tries 0, successful; the target becomes priority 15, tries 3,
unconfirmed.  It refuses when the current slot is not confirmed.

`bcb reset` writes the fresh-install record: slot A priority 15, tries 0,
successful, slot B zero.  That is the byte record suggested by `confirm`
(`libreecho_bootctl.c:405`) and seeded by the VM harness
(`ota-test-vm/build-initramfs.sh:89`).

Both write commands save a timestamped `misc-*-before.bin` backup in the log
directory, patch only the 7 BCB bytes, flash misc, fetch the whole partition
again, require an exact match, and require that no byte outside the BCB
changed.

### reboot

`fastboot reboot`.  To enter fastboot instead, hold the Action button at
power-on.  That is the recovery floor: Kaeru fastboot supports flash, erase,
getvar, reboot, and fetch.  It does not support `fastboot boot`.

## Unproven on hardware

These are measurements, not code claims:

- `bcb set-active` against stock LK's slot selection.  The BCB bytes match
  bootctl, but Lidar's LK has not been observed booting `boot_b` from a
  priority-15 slot B record.
- The USB `fetch:` range read.  Kaeru serves it and the protocol is the one in
  `cmd_fetch.c`, but the installer has not driven it on a device yet; the
  earlier readback used the stock client.

## Measured on hardware

On 2026-11-18 a Lidar unit flashed the 4.93 GB sparse userdata image and read
its 1 MiB prefix back, with the ext4 label `LIBREECHO_DATA` on both sides
(`lab-notes/phase-05/hw-20261118/logs/install.log:190-197`).  That readback
used the old prefix fetch: it stopped the client after the first chunk while
Kaeru was already sending chunk 2, so the next command read a stale
`product: 00100000` header from the abandoned stream
(`lab-notes/phase-05/hw-20261118/logs/bcb-reset.log:5`) and the one after
that failed with `Status read failed`.  Draining the bulk-in endpoint recovered
the unit (`lab-notes/phase-05/hw-20261118/drain_bulk_in.py`).

## Known integration point

The product installer's preflight `_validate_android_sparse_image`
(`tools/libreecho-install.py` in the LibreEcho repo) requires an exact
multiple of the partition size.  Lidar userdata cannot meet that because the
partition is an odd number of 512-byte sectors, so this is an integration item
for Product, not a Lidar runtime constraint.  The runtime accepts the
4096-byte sparse span that ends 3584 bytes short.
