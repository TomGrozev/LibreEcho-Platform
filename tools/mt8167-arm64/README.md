# MT8167 ARM64 profile

This profile builds LibreEcho images for the Echo Plus 2nd Gen ("Lidar"), which
runs an ARM64 kernel with the shared ARM32 userspace.  It contains the target
table, the ARM64 boot-envelope builder and verifier, the Lidar DTB verifier,
and the tests that pin the envelope.

The userspace sources, overlay and staging code stay in
`tools/mt8163-arm32/`.  The builder imports `copy_adbd`, `add_overlay`,
`validate_stage`, `build_cpio` and `compress_ramdisk` from that directory by
path.  Do not copy those files here.  The runtime userspace probes the
partition layout or reads `/etc/libreecho/target`; it never selects behaviour
with `uname`.

## Target

`libreecho_platform_targets.py` defines one target:

| field | value |
| --- | --- |
| target id | `lidar` |
| release slug | `lidar` |
| hardware profile | `lidar@1` |
| fastboot product | `LIDAR` |
| SoC | `mt8167` |
| userspace architecture | `armv7` |
| audio | Flat codec, `lidar` chain |

The table records all 16 GPT partitions from the live dump, including
`misc` 512 KiB at p8 and the absent recovery partition.

The builder renders `/etc/libreecho/audio-profile` (schema 1) from the target
table: flat codec, zero analogue and digital gain, stereo 48 kHz `s16_le`
playback, the 8-channel 16 kHz `s32_le` capture array
(`mic0..mic6,line-in`), and a separate stereo 48 kHz `s16_le` AEC PCM.  The UI
and the audio engine read the same file, and `wake word`/`agentd` stay enabled
because an audio profile is present.

The shared `init.rc` imports `/init.recovery.${ro.hardware}.rc`, so the overlay
keeps `ro.hardware=mt8163`; this is a userspace file-selection name, not a
board test. The board identity is `/etc/libreecho/target`.

## WLAN client

The MT7668 driver is mac80211/nl80211, so the profile stages a plain static
ARM32 `wpa_supplicant` 2.10 at `/sbin/wpa_supplicant` through
`--wpa-supplicant`. `libreecho-wifi` starts it against the profile selected by
`libreecho-init` (`/data/libreecho/config/wpa_supplicant.conf`, or the packaged
`/etc/wifi/wpa_supplicant.conf`), and `udhcpc` is the BusyBox applet. The
verifier rejects the member unless it is static ARM32 hard-float and matches
`--expected-wpa-supplicant-sha256`. MT8163's WMT connectivity bundle,
`--wifi-dtb` and `--audio-probe` remain refused.

## Boot envelope

The builder emits the stock boot envelope:

- 16 MiB Android v0 image, page size 2048, header version 0.
- kernel address `0x40080000`, ramdisk `0x44000000`, second `0x40F00000`,
  tags `0x4E000000`, os_version `0x0E04119C`.
- MediaTek `KERNEL` header `0x58881688` around the payload.
- deterministic gzip of the raw ARM64 `Image`.
- 19 stock appended DTBs; index 4 is replaced by ours, the other 18 stay
  byte-identical.  The stock collection hash is
  `8f56e981...ee7fde` and the stock PVT DTB hash is `b5302d9e...5a730f`.
- `/chosen linux,initrd-start` and `linux,initrd-end` from `ramdisk_addr` and
  the real ramdisk size.
- command line starts with `bootopt=64S3,32N2,64N2`, never contains
  `lidar.autoreboot`, and keeps the stock text unless `--cmdline-append` adds
  more.
- zero trailer.  The stock certificate is not carried over.

The builder refuses a kernel config with any `CONFIG_LIBREECHO_DEV*` set to
`y` or `m`.  The recovery marker driver resets both BCB slots on every boot,
which breaks A/B confirmation.

The builder also checks the physical layout.  The kernel end is
`0x40080000 + image_size`, where `image_size` is the ARM64 Image header field
at offset `0x10`.  That end must stay below the lowest `reserved-memory`
region in our DTB and below `ramdisk_addr`.  The ramdisk end must stay below
`tags_addr`.  No System.map is needed: an ARM64 `Image` states its loaded
extent in its own header, while the MT8163 `zImage` self-decompresses and had
to be bounded from symbols.  `image_size` normally includes BSS, so it is the
right bound.  A future kernel that lies in that field needs a new contract.

## Build

Inputs that are not in the repository must be supplied.  Component hashes are
required, not inferred.  Run this from the repository root:

```sh
python3 tools/mt8167-arm64/build_recovery_image.py \
  --stock-boot <stock-boot.img> \
  --kernel-image <obj>/arch/arm64/boot/Image \
  --kernel-config <linux-checkout>/arch/arm64/configs/mt8167_arm64_defconfig \
  --dtb <lidar.dtb> \
  --expected-dtb-sha256 <sha256> \
  --adbd <static-arm32-adbd> \
  --adbd-source-metadata <adbd-source-metadata.json> \
  --busybox <static-arm32-busybox> \
  --expected-busybox-sha256 <sha256> \
  --musl-loader <ld-musl-armhf.so.1> \
  --expected-musl-loader-sha256 <sha256> \
  --image-profile development \
  --service-profile diagnostic \
  --feature-policy preserve \
  --update-channel dev \
  --bootctl <static-arm32-libreecho-bootctl> \
  --update-verifier <static-arm32-libreecho-update-verify> \
  --ota-public-key <ota-public-key.hex> \
  --wifi-patch <mt7668pr2h.bin> \
  --wifi-licence <LICENCE.mediatek> \
  --qemu-arm <qemu-arm-static> \
  --output <out>/boot-lidar-recovery.img
```

`--stock-boot` reads the stock kernel command line and MediaTek header.  Use
`--stock-dtb-collection <19-dtb-concatenation>` instead when only the appended
trees are available; the builder then uses its built-in proven stock command
line constant.  The two source flags
are mutually exclusive.  `--expected-stock-dtb-collection-sha256` and
`--expected-stock-pvt-sha256` default to the pinned values.

Optional flags:

- `--cmdline-append TEXT` may repeat.  Each value is appended with one space.
- `--ramdisk-output PATH` defaults to the output name with
  `.ramdisk.cpio.xz`.
- `--manifest PATH` defaults to the output name with `.manifest.json`.
- `--target` defaults to `lidar`; `--target-descriptor-sha256` is recorded when
  Product supplies it.

The builder refuses to overwrite an existing output, ramdisk or manifest.
`--audio-probe`, `--wifi-dtb` and `--connectivity-bundle` are refused with an
explicit error because they are MT8163 payloads.

`--wifi-patch` and `--wifi-licence` are required.  The patch must be the
170990-byte linux-firmware `mt7668pr2h.bin` from tag `20261019`.  The builder
stages the same bytes as
`lib/firmware/mediatek/mt7668pr2h.bin` for the WLAN driver and
`lib/firmware/mt7668_patch_e2_hdr.bin` for `btmtksdio`, plus
`lib/firmware/LICENCE.mediatek` and the shipped
`etc/libreecho/vendor-assets/lidar-mt7668-stock-v1.tsv`, and records them in
`manifest['wifi_firmware']`.  The RAM codes and per-unit calibration come from
the owner's `system_a` at boot; they are never baked into the image.

UI and discovery inputs follow the shared MT8163 contract:

- `--ui-bundle PATH` opts in to the separately built UI.  It also requires
  `--ui-source`, `--expected-ui-commit` and `--expected-ui-diff-sha256`.
  Supplying any of those without `--ui-bundle` is refused.
- `--mdns-runtime PATH` stages the boot-contained shared Avahi/D-Bus runtime.
  `--service-profile production` requires it.

The Thread border router is Lidar-only, because only Lidar has the EFR32 radio:

- `--lidar-efr32 PATH` and `--otbr-agent PATH` stage the radio tool, the
  border agent and `/etc/init.d/libreecho-threadd.init` together; one without
  the other is refused, and both are refused outside `--target lidar`.
- The service takes the radio only when the persisted `radio` setting is
  `thread`. `lidar-efr32 run` holds `RESET_N` high for the lifetime of the
  border agent, because the line has no pull-up.
- otbr-agent publishes through the one Avahi/D-Bus responder that
  `/etc/init.d/libreecho-mdnsd.init` supervises. No private `dbus-daemon`,
  `avahi-daemon` or daemon config is staged: a second responder would race
  the shared one. `libreecho-init` starts the service only after that
  responder is up, and only when the init entry is present.
- `manifest['thread']` records the payload. The verifier requires the three
  staged members when the record is enabled and rejects a thread init on an
  image whose manifest disables it.

An `--image-profile ota` image must also pass `--ui-bundle`: its OTA health
probe runs `/usr/local/sbin/libreecho-web` and
`/etc/init.d/libreecho-web.init`, and only the UI bundle stages them.  The
builder calls `add_ui_bundle` and `add_mdns_runtime` from
`tools/mt8163-arm32/build_recovery_image.py` and records the same `ui` and
`mdns` manifest records the shared builder records.  With neither flag the
manifest keeps the disabled `ui` and `mdns` records.

The builder prints and records in the manifest the gzip kernel bytes, DTB
collection bytes, ramdisk bytes, used bytes and the free margin to 16 MiB.

## Verify

The verifier re-derives the envelope from the inputs and the manifest.  It
reads the DTB collection, gzip kernel, ramdisk, command line, Android id,
trailer and manifest-driven initramfs.

```sh
python3 tools/mt8167-arm64/verify_recovery_image.py \
  --stock-boot <stock-boot.img> \
  --kernel-image <obj>/arch/arm64/boot/Image \
  --kernel-config <linux-checkout>/arch/arm64/configs/mt8167_arm64_defconfig \
  --dtb <lidar.dtb> \
  --expected-dtb-sha256 <sha256> \
  --ramdisk <out>/boot-lidar-recovery.ramdisk.cpio.xz \
  --manifest <out>/boot-lidar-recovery.manifest.json \
  --boot-image <out>/boot-lidar-recovery.img \
  --expected-boot-sha256 <sha256> \
  --expected-busybox-sha256 <sha256> \
  --expected-musl-loader-sha256 <sha256> \
  --expected-bootctl-sha256 <sha256> \
  --expected-update-verifier-sha256 <sha256> \
  --expected-ota-public-key-sha256 <sha256> \
  --image-profile development \
  --service-profile diagnostic \
  --feature-policy preserve \
  --update-channel dev
```

Pass the same `--cmdline-append` values as the build.  The initramfs checks
reuse `parse_newc`, `decompress_ramdisk`, `elf_info`, `require_member`,
`validate_archive_tree`, `validate_symlinks`, `validate_ui` and `validate_mdns`
from the MT8163 verifier.

Optional verifier pins:

- `--expected-ui-manifest-sha256`, `--expected-ui-commit` and
  `--expected-ui-diff-sha256` require the staged UI bundle and pin its
  identities.  Without them a bundle staged in the image is rejected.
- `--expected-mdns-runtime-manifest-sha256` pins the staged shared mDNS
  runtime manifest.  The verifier still requires that runtime for
  `--service-profile production`.

Because the UI and mDNS member hashes come from the manifest, a one-byte
change to a staged UI or mDNS file fails verification.

## DTB contract

`verify_lidar_dtb.py` reads the flattened tree in Python and checks:

- the first root compatible starts with `amzn,lidar-`;
- the root compatible list contains `amzn,lidar-pvt`;
- the tree is at most `0x80000` bytes, the window LK copies to `tags_addr`;
- `/chosen` carries the 64-bit initrd start and end when the image is packed;
- a `syscon-reboot-mode` node exists with `offset = <0x24>`,
  `mask = <0x4>` and `mode-bootloader = <0x4>`, and its parent `reg` names
  `0x10007000`.

That node is how `reboot(LINUX_REBOOT_CMD_RESTART2, "bootloader")` sets
watchdog NONRST2 bit 2 across a reset, which makes stock LK enter fastboot.
No misc write is involved.

## Tests

The top-level suites run from this directory:

```sh
cd tools/mt8167-arm64
python3 -m unittest -v test_recovery_image_tools test_verify_lidar_dtb
```

`install/` and `prepare/` carry no `__init__.py`, so each runs from its own
directory:

```sh
cd tools/mt8167-arm64/install
python3 -m unittest -v

cd tools/mt8167-arm64/prepare
python3 -m unittest -v
```

The tests compile synthetic DTBs with `dtc` and skip with a clear reason when
it is absent; set `LIDAR_DTC` to a preserved `dtc` binary to choose which one
they use.  CI installs `device-tree-compiler` and requires the image and DTB
cases to report `ok`.  They prove a builder round trip passes the independent
verifier, and that command-line, kernel, ramdisk, DTB and manifest tampering
fails it.  The firmware fixtures are synthetic and same-size, so the staging
and inventory contracts run without vendor bytes.

The MT8163 tests that provide the imported helpers must keep passing:

```sh
cd tools/mt8163-arm32
python3 -m unittest test_recovery_image_tools -q
```
