# HTB Try-Outs — "Debug" (Hardware)

**Category:** Hardware  
**Difficulty:** Easy

---

## Challenge Description

> Your team has recovered a satellite dish that was used for transmitting the location of the relic, but it seems to be malfunctioning. There seems to be some interference affecting its connection to the satellite system, but there are no indications of what it could be. Perhaps the debugging interface could provide some insight, but they are unable to decode the serial signal captured during the device's booting sequence. Can you help to decode the signal and find the source of the interference?

We're given a single zip archive containing one logic analyzer capture:

```text
hw_debug.zip
└── hw_debug.sal        # Saleae Logic 2 capture
```

A `.sal` file is the native session format of Saleae's Logic 2 software. The capture is a recording of the voltage on a few probe wires, in this case the debug UART of the dish, sampled over time. Nothing here is encrypted: the goal is to turn the raw edges back into the serial text that the device printed while booting.

---

## Tooling

- [Saleae Logic 2](https://www.saleae.com/downloads/) — the easy path: open the file and use the built-in **Async Serial** analyzer.
- `unzip` + `python3` — the manual path, useful when Logic 2 isn't available or when you want to understand the file format.

A `.sal` file is itself a zip archive, so it can be unpacked directly:

```bash
unzip hw_debug.zip
unzip hw_debug.sal -d sal
ls -la sal
```

```text
digital-0.bin    # channel 0 (named "TX")
digital-1.bin    # channel 1 (named "RX")
meta.json        # capture settings, channel names, analyzers
```

`meta.json` gives us the two facts we need to decode anything:

| Setting | Value |
|---|---|
| Device | Logic 8 |
| Enabled channels | Digital 0 ("TX"), Digital 1 ("RX") |
| Digital sample rate | **25 MS/s** |

---

## The Easy Way: Logic 2

1. Open `hw_debug.sal` in Logic 2.
2. Add an **Async Serial** analyzer on the **RX** channel (Digital 1).
3. Set: **115200** baud, 8 data bits, no parity, 1 stop bit, LSB first.
4. Open the analyzer's terminal view (or export the table) and read the boot log.

The next sections explain where those parameters come from and how to get the same result without Logic 2.

---

## Finding the Right Channel

The two binary files start with the magic `<SALEAE>`, followed by a version (`1`) and a type (`100`, digital). Parsing them shows a very different amount of data per channel:

| File | Size | Chunks holding transitions |
|---|---|---|
| `digital-0.bin` (TX) | 88 KB | **0** |
| `digital-1.bin` (RX) | 178 KB | **219** (out of 1121) |

The TX line never moves, so everything interesting is on **RX** (`digital-1.bin`).

---

## Reverse Engineering the Capture Format

The digital channels are not stored as raw samples but as **run lengths between edges**, split into fixed-size chunks. Looking at the hex, the file is a 44-byte header followed by one 79-byte record per chunk, each ending with the sample rate (`0x017d7840` = 25,000,000) and a length-prefixed blob of data:

```text
... 40 78 7d 01 00 00 00 00 | 01 00 00 00 00 00 00 00 | <N as u64> | <N bytes of data>
    └── 25,000,000 ─────────┘
```

- An **empty** chunk has `N = 3` and its data is just `72 ff 7f` — one token meaning "no edge during this whole chunk".
- A **busy** chunk has a few hundred bytes of tokens such as `41 58 41 58 43 31 45 0b ...`.
- Every chunk spans `0xcc0 * 256 = 835,584` samples (about 33 ms).

### Decoding the tokens

The tokens are variable-length integers:

- The **first byte** carries 6 bits of value (`byte & 0x3f`).
- Every following byte adds **7 more bits** (`byte & 0x7f`).
- Bit 7 (`0x80`) of a following byte means "another byte follows".
- The stored number is **delta − 1**, so the real distance between two edges is `value + 1` samples.

Checking this against the empty chunk: `72 ff 7f` → `0x32 << 14 | 0x7f << 7 | 0x7f = 835,583`, and `+1` gives exactly the chunk length of 835,584. For busy chunks, the sum of all tokens also equals one full chunk, with the **last** token being the idle time after the last edge (not a new edge).

### Finding the baud rate

Histogramming the decoded edge-to-edge distances gives a handful of tight clusters:

| Distance (samples) | Bits at 217 samples/bit |
|---|---|
| 217 | 1 |
| 434 | 2 |
| 651 | 3 |
| 868 | 4 |
| 1085 | 5 |
| 1302 | 6 |

Every run is a multiple of **217 samples**. With a 25 MS/s sample rate:

```text
25,000,000 / 217 ≈ 115,207 baud  →  115200 baud
```

That's the standard UART speed, 8N1.

> **Pitfall:** reading the 2-byte tokens as plain 8-bit-aligned numbers (`(b0 << 8) | b1`) gives odd durations like 344, 817, 1290 and 1636 — values that are *almost* regular but never match a UART bit time. Treating the second byte as a 7-bit group (and adding the `+1`) is what makes the 217-sample grid appear.

---

## Decoding the UART

With edge timestamps reconstructed, the UART decode is standard: the line idles high, a falling edge starts a frame, and we sample each bit in its middle.

```python
import bisect

CHUNK = 0xcc0 * 256          # samples per chunk
BIT   = 25_000_000 / 115200  # ~217 samples per bit

def tokens(blob):
    out, i = [], 0
    while i < len(blob):
        v = blob[i] & 0x3f; i += 1
        while i < len(blob):
            b = blob[i]; i += 1
            v = (v << 7) | (b & 0x7f)
            if not b & 0x80:
                break
        out.append(v + 1)            # stored value is delta - 1
    return out

# chunks = list of data blobs from digital-1.bin (one per chunk)
edges = []
for k, blob in enumerate(chunks):
    pos = k * CHUNK
    for dt in tokens(blob)[:-1]:     # last token = trailing idle time
        pos += dt
        edges.append(pos)

def level(t):                        # line idles high (1)
    return 1 ^ (bisect.bisect_right(edges, t) & 1)

out, k = bytearray(), 0
while k < len(edges):
    if (1 ^ ((k + 1) & 1)) == 0:     # falling edge = start bit
        t0 = edges[k]
        bits = [level(t0 + BIT * (j + 0.5)) for j in range(1, 9)]
        out.append(sum(b << i for i, b in enumerate(bits)))   # LSB first
        end = t0 + BIT * 9.5
        while k < len(edges) and edges[k] < end:
            k += 1
    else:
        k += 1

print(out.decode('latin-1'))
```

The script reconstructs about 39,500 edges and 7,144 UART frames.

---

## The Boot Log

The output is a realistic embedded boot sequence: ARM Trusted Firmware stages (`BL1`, `BL2`, `BL31`), U-Boot, an eMMC probe, a FIT image load of the kernel and ramdisk, and finally the login prompt of the dish's management terminal:

```text
INFO:    AUTOSTARTUP MODE = 1
NOTICE:  Booting Trusted Firmware
NOTICE:  BL1: v1.3(release):f26889a
...
U-Boot 2016.05-00307-g16c388c (Jul 23 2021 ...
DRAM:  1004 MiB
...
Is production hardware? YES
= Type 'egypt' to stop boot process in the next 2 seconds =
...
= Galaxy Gateway Network Information =
...
Starting kernel ...

Development login enabled: no
Debugging mode enabled: yes
Safe mode enabled: no

SATDish - Managment User Terminal.
Dish is offline
admin login:
```

Between the "Galaxy Gateway Network Information" banner and the kernel hand-off, a block of warnings appears:

```text
WARNING: The deep space observatory is offline HTB{
INFO:    Communication systems are offline reference code: 547311173_
WARNING: Unauthorized subroutines detected! reference code: n37w02k_
WARNING: The satellite dish can not sync with the swarm. reference code: c0mp20m153d}
```

The flag is spread across four lines: the opening `HTB{` on the first, and one **"reference code"** fragment on each of the next three.

---

## Putting It Together

Concatenating the fragments in the order they are printed:

```text
HTB{547311173_n37w02k_c0mp20m153d}
```

Decoding the leetspeak confirms it reads as a coherent phrase, and answers the "source of the interference" question from the challenge description:

| Leet | Decoded |
|---|---|
| `547311173` | SATELLITE |
| `n37w02k` | NETWORK |
| `c0mp20m153d` | COMPROMISED |

→ "Satellite network compromised" — matching the surrounding messages about unauthorized subroutines and a dish that can no longer sync with the swarm.

---

## Flag

```text
HTB{REDACTED}
```

---

## Notes on Decode Quality

The manual decoder is not perfect, and it's worth being upfront about it:

- 4 of the 1121 chunks have a token sum that doesn't match the expected chunk length, and about 200 frames report a framing error (stop bit not high).
- Those errors show up as short runs of garbage or `\x00` bytes in a few places (for example inside the U-Boot version line and the `sdhci_transfer_data` messages), which suggests a small timing drift or edge-case chunk boundaries that the simple decoder doesn't handle.
- None of this touches the flag area: the four warning lines decode cleanly, and the result is a coherent leetspeak phrase, which is a strong sanity check.

If a perfect log is needed, Logic 2's own Async Serial analyzer on the RX channel is the reference implementation.

---

## Takeaways

- A logic analyzer capture is just another "source" artifact: if a tool can't open it, the format can often be reverse engineered. Here a `.sal` file turned out to be a plain zip with simple run-length encoded channels.
- Check **which channel actually carries data** before decoding. TX contained zero transitions; all the information was on RX.
- Let the data tell you the baud rate: histogramming edge-to-edge distances and looking for a common divisor (217 samples at 25 MS/s → 115200 baud) is more reliable than guessing from a list of standard rates.
- When a numeric field looks "almost regular" but never lands on a clean grid, suspect the encoding (7-bit groups, off-by-one deltas) rather than the signal.
- Boot logs are a rich source of information in hardware assessments. Debug UARTs often expose firmware versions, memory maps, device state and, as here, whatever the designers (or an attacker) chose to print.
