# HTB Try-Outs — "Critical Flight" (Hardware)

**Category:** Hardware  
**Difficulty:** Easy

---

## Challenge Description

> Your team has assigned you to a mission to investigate the production files of Printed Circuit Boards for irregularities. This is in response to the deployment of nonfunctional DIY drones that keep falling out of the sky. The team had used a slightly modified version of an open-source flight controller in order to save time, but it appears that someone had sabotaged the design before production. Can you help identify any suspicious alterations made to the boards?

We're given a zip archive containing the Gerber production files for a 4-layer PCB called `HadesMicro`:

```text
flight_control_board/
├── HadesMicro-F_Cu.gbr           # Top copper      (L1)
├── HadesMicro-In1_Cu.gbr         # Inner copper 1  (L2)
├── HadesMicro-In2_Cu.gbr         # Inner copper 2  (L3)
├── HadesMicro-B_Cu.gbr           # Bottom copper   (L4)
├── HadesMicro-F_Mask.gbr / B_Mask.gbr
├── HadesMicro-F_Paste.gbr / B_Paste.gbr
├── HadesMicro-F_Silkscreen.gbr / B_Silkscreen.gbr
├── HadesMicro-F_Fab.gbr / B_Fab.gbr
└── HadesMicro-Edge_Cuts.gbr
```

Gerber files are the plain-text, vector-based format PCB manufacturers use to physically produce a board — one file per copper/solder-mask/silkscreen layer. Since nothing in the archive is executable or encrypted, the obvious approach is to render every layer and inspect it visually, the way a fab house or a hardware reviewer would.

---

## Tooling

[`gerbv`](https://gerbv.github.io/) is a free, open-source Gerber viewer that can also export each layer straight to PNG from the command line:

```bash
sudo apt install gerbv

# Render every .gbr layer individually
for f in *.gbr; do
    name="${f%.gbr}"
    gerbv -x png -o "render/${name}.png" -a --border=10 --dpi=2400 "$f"
done
```

Rendering every layer separately (instead of only looking at the assembled board image) is the key step here — anything hidden on an inner copper layer or a layer that isn't normally rendered during assembly review is invisible unless you open that specific `.gbr` file.

---

## Finding the Hidden Text

Most layers (`F_Fab`, `B_Fab`, `F_Paste`, `B_Paste`, silkscreens, etc.) only contain the expected component outlines, pads and reference designators. However, two layers stand out:

### Bottom copper (`B_Cu`)

Rendering `HadesMicro-B_Cu.gbr` reveals text etched directly into the copper fill, tucked next to a connector footprint — something that serves no electrical purpose and would normally go unnoticed since it's completely covered by solder mask on the physical board:

```text
HTB{533_7h3_1nn32_w02k1n95
```

### Inner copper layer 1 (`In1_Cu`)

The text continues on the first inner copper layer — a layer that is never visible on an assembled or even bare board, since it's sandwiched between the outer layers. This is only recoverable from the raw fabrication files:

```text
_0f_313c720n1c5#$@}
```

No other layer (`F_Cu`, `In2_Cu`, silkscreens, mask, paste, fab) contains any additional hidden text — confirmed by scanning every rendered layer for wide, high-density black regions (the solid rectangular background KiCad draws behind copper-layer text).

---

## Putting It Together

Concatenating the two fragments in layer order (bottom copper → inner layer 1) gives the full string:

```text
HTB{533_7h3_1nn32_w02k1n95_0f_313c720n1c5#$@}
```

Decoding the leetspeak portion confirms it reads as a coherent phrase:

| Leet | Decoded |
|---|---|
| `533` | SEE |
| `7h3` | THE |
| `1nn32` | INNER |
| `w02k1n95` | WORKINGS |
| `0f` | OF |
| `313c720n1c5` | ELECTRONICS |

→ "See the inner workings of electronics" — a fitting message for a challenge solved by digging into the raw copper layers of a PCB instead of just looking at the finished board.

---

## Flag

```text
HTB{REDACTED}
```

---

## Takeaways

- Gerber/PCB production files should be treated like any other "source" artifact in a security review: every individual layer needs to be opened and inspected, not just the composite board render.
- Inner copper layers are an effective (if slightly unconventional) hiding spot — they carry no functional silkscreen and are invisible on both the bare and assembled board, making them an easy place to stash hidden data or, in a real-world scenario, a hardware backdoor/trojan trace.
- When extracting data embedded as vector text in a Gerber file, render at a high DPI before transcribing — some characters are easy to misread at low resolution, and symbol characters can be mistaken for additional leetspeak letters.
