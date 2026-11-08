# HTB Challenge — "Espresso" (Hardware / Firmware)

**Category:** Hardware  
**Difficulty:** Very Easy

---

## Challenge Scenario

> Someone leaked the new Espresso firmware, can you try to figure out what it does?

We are given a single binary file:

```text
firmware.bin   (4,194,304 bytes / 4 MB)
```

No other context is provided — no board schematic, no datasheet, nothing. The file itself has to tell us what it is and what tooling it expects.

---

## Tooling

- `file`, `xxd` — initial identification
- `esptool` (`pip install esptool`) — ESP32 image parsing
- `strings` — locating human-readable hints embedded in the binary
- `espressif/qemu` (prebuilt release from GitHub) — hardware emulation
- `qemu-system-xtensa` (Espressif fork, `esp32` machine type)

---

## Identifying the File

`file` reports nothing useful (`data`), but the first 4 KB are entirely `0xFF` — a strong indicator of an **erased/unwritten SPI flash region**, which is typical of a raw flash dump rather than a standalone executable:

```bash
xxd firmware.bin | head
# 00000000: ffff ffff ffff ffff ... (repeats for 0x1000 bytes)
```

The first non-`0xFF` byte appears at offset `0x1000`:

```text
e9 03 02 20 44 06 08 40 ee 00 00 00 ...
```

`0xE9` is the **Espressif image magic byte**, used by both ESP8266 and ESP32 firmware images. Combined with the challenge's name — "Espresso" being an obvious pun on **Espressif** — this confirms we're dealing with a raw **ESP32 flash dump**, and the bootloader starts at the standard offset `0x1000`.

---

## Parsing the Image with esptool

```bash
python3 -m esptool --chip esp32 image-info firmware.bin
```

Attempting this on the raw 4 MB dump only identifies the bootloader at `0x1000`; the actual application image lives inside the partition table, which on ESP32 defaults to offset `0x8000`. Reading the partition table manually (magic bytes `0xAA50`) gives:

| Type | Subtype | Offset     | Size       | Label      |
|------|---------|------------|------------|------------|
| 0x01 | 0x02    | 0x00009000 | 0x00006000 | `nvs`      |
| 0x01 | 0x01    | 0x0000f000 | 0x00001000 | `phy_init` |
| 0x00 | 0x00    | 0x00010000 | 0x00100000 | `factory`  |

- `nvs` is the Non-Volatile Storage partition — frequently used to store Wi-Fi credentials or app secrets.
- `factory` is the actual application firmware (1 MB), carved out and analyzed next.

```bash
python3 -c "
data = open('firmware.bin','rb').read()
open('nvs.bin','wb').write(data[0x9000:0x9000+0x6000])
open('factory.bin','wb').write(data[0x10000:0x10000+0x100000])
"
```

Checking the NVS partition first: it is **entirely `0xFF`** — empty, no secrets stored there. The interesting content has to be in the `factory` application image itself.

```bash
python3 -m esptool --chip esp32 image-info factory.bin
```

```text
Application Information
=======================
Project name:     espresso
App version:      2c1ec8fd-dirty
Compile time:     Feb 28 2026 03:10:39
ESP-IDF:          v6.1-dev-2748-g490691bc61
```

This confirms the image is a genuine ESP-IDF application named `espresso`.

---

## Finding the Hint Inside the Binary

Rather than diving straight into Xtensa disassembly, a simple `strings` pass over the extracted application is far more productive:

```bash
strings -n 6 factory.bin | grep -iE "flag|cloned|hardware"
```

```text
flag did not generate correctly.
It seems you are running the firmware on cloned hadware.
Buy the real hardware, or perhaps try to emulate it. ;)
```

This is a direct, intentional hint from the challenge author: the firmware's `app_main()` performs some kind of hardware-presence/genuineness check before generating the flag, and explicitly suggests **emulation** as the valid alternative to owning real ESP32 hardware.

---

## Emulating the Firmware

Espressif maintains its own fork of QEMU with native support for the `esp32` machine type, distributed as prebuilt GitHub release binaries — no compilation required:

```bash
curl -L -o qemu-xtensa.tar.xz \
  "https://github.com/espressif/qemu/releases/download/esp-develop-9.2.2-20260417/qemu-xtensa-softmmu-esp_develop_9.2.2_20260417-x86_64-linux-gnu.tar.xz"
tar xf qemu-xtensa.tar.xz
```

```bash
./qemu/bin/qemu-system-xtensa -machine help
```

```text
Supported machines are:
esp32                Espressif ESP32 machine
esp32s3               Espressif ESP32S3 machine
...
```

The original 4 MB `firmware.bin` is a complete flash image (bootloader + partition table + app), so it can be mounted directly as the emulated SPI flash device:

```bash
qemu-system-xtensa -nographic -machine esp32 \
  -drive file=firmware.bin,if=mtd,format=raw -nic none
```

The emulated boot proceeds exactly like a real device: 2nd-stage bootloader, partition table dump, segment loading, and finally `app_main()`:

```text
I (1611) app_init: Project name:     espresso
...
I (1770) main_task: Calling app_main()
I (1770) main: HTB{REDACTED}
I (1770) main_task: Returned from app_main()
```

The firmware's hardware-genuineness check passes happily under QEMU (since there is no "cloned hardware" to detect), and the flag is printed straight to the emulated UART console — exactly as the embedded hint promised.

---

## The Flag

```text
HTB{REDACTED}
```

---

## Takeaways

- A raw flash dump that opens with long runs of `0xFF` and a lone `0xE9` magic byte at offset `0x1000` is almost certainly an **Espressif (ESP8266/ESP32) firmware image** — worth checking before reaching for a generic disassembler.
- `esptool image-info` (and manual parsing of the `0xAA50` partition-table magic) is enough to map out NVS, PHY calibration, and application partitions without needing the original build sources.
- Not every embedded/firmware challenge requires full disassembly: `strings` on the extracted application partition directly surfaced the intended solution path here.
- When a challenge explicitly nudges toward "try to emulate it," check whether the vendor publishes a ready-to-use emulator. Espressif ships its own QEMU fork with ESP32/ESP32-S3 machine support as prebuilt GitHub release binaries — no toolchain build required.
- Mounting the untouched 4 MB dump directly as `-drive file=...,if=mtd,format=raw` is enough; QEMU reproduces the full boot sequence (bootloader → partition table → app) and surfaces any UART output, including log lines never meant to reach real end users.
