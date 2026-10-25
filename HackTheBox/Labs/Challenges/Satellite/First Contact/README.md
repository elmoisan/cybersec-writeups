# HTB Challenge — "First Contact" (Satellite)

**Category:** Satellite  
**Difficulty:** Easy

---

## Challenge Scenario

> Your team has recovered a satellite dish that was used for transmitting the location of the relic, but it seems to be malfunctioning. There seems to be some interference affecting its connection to the satellite system, but there are no indications of what it could be. Perhaps the debugging interface could provide some insight, but they are unable to decode the serial signal captured during the device's booting sequence. Can you help to decode the signal and find the source of the interference?

We are given a single ZIP archive containing one logic-analyzer capture:

```text
hw_debug.zip
└── hw_debug.sal
```

The `.sal` file is the native session format used by Saleae Logic 2. It records the voltage on a few probe wires over time. In this challenge, the interesting signal is the UART debug output emitted by the dish while booting. Nothing is encrypted; the goal is to reconstruct the serial text from the raw logic capture.

---

## Tooling

- Saleae Logic 2 — easiest path to open the capture and apply the Async Serial analyzer
- `unzip` and `python3` — useful if we want to decode the capture manually

A `.sal` file is itself a ZIP archive, so it can be extracted directly:

```bash
unzip hw_debug.zip
unzip hw_debug.sal -d sal
ls -la sal
```

This reveals:

```text
digital-0.bin
digital-1.bin
meta.json
```

The important metadata is stored in `meta.json`:

| Setting | Value |
|---|---|
| Device | Logic 8 |
| Enabled channels | Digital 0 (TX), Digital 1 (RX) |
| Digital sample rate | 25 MS/s |

---

## Finding the Relevant Signal

The digital channels are stored as run-length encoded edge transitions. The sample rate is 25 MS/s, and the interesting activity is on the RX line (`digital-1.bin`). Looking at the raw files, we can see that TX never changes, which means the signal of interest is overwhelmingly on the receive side.

The capture format is fairly regular: each chunk contains a sequence of edge-to-edge distances, and the final token in a chunk is the idle time after the last edge. The values are variable-length integers, and when decoded correctly they reveal a clear UART timing pattern.

---

## Finding the UART Parameters

The burst lengths cluster around multiples of a base distance. With a 25 MS/s sample rate, this resolves to roughly 217 samples per bit, which matches the common UART speed:

```text
25,000,000 / 217 ≈ 115,207 baud -> 115200 baud
```

This is the standard UART configuration: 115200 baud, 8 data bits, no parity, 1 stop bit, LSB first.

---

## Decoding the UART Boot Log

The logic capture can be decoded by reconstructing the edges and then reading each UART frame at the midpoint of each bit. The resulting output is a realistic boot log from an embedded system, including an eMMC probe, U-Boot startup, kernel handoff, and finally the management terminal prompt.

The relevant section contains warning lines that reveal the issue behind the dish malfunction:

```text
WARNING: The deep space observatory is offline HTB{
INFO:    Communication systems are offline reference code: 547311173_
WARNING: Unauthorized subroutines detected! reference code: n37w02k_
WARNING: The satellite dish can not sync with the swarm. reference code: c0mp20m153d}
```

The flag is split across those lines: the opening `HTB{` appears on the first line, and the remaining fragments are encoded as the three "reference code" values printed afterward.

---

## Reconstructing the Flag

Concatenating the fragments in the order they are emitted:

```text
HTB{547311173_n37w02k_c0mp20m153d}
```

Decoding the leetspeak gives a coherent phrase:

| Leet | Decoded |
|---|---|
| `547311173` | SATELLITE |
| `n37w02k` | NETWORK |
| `c0mp20m153d` | COMPROMISED |

This matches the challenge narrative perfectly: the cause is a compromised satellite network.

---

## The Flag

```text
HTB{REDACTED}
```

---

## Takeaways

- A logic-analyzer capture can usually be decoded without proprietary tools if the file format is understood.
- `.sal` files often turn out to be ZIP bundles containing simple binary channel data and metadata.
- UART decoding is straightforward once the sample rate and bit framing are known.
- Even when the flag is intentionally split across multiple lines, the data remains recoverable with a careful reconstruction pipeline.
- This challenge is a good example of how hardware debugging often boils down to timing analysis and serial protocol understanding rather than decryption.
