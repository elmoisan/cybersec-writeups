# ETHERNET - Altered Transmission

`Network` • `Frame Analysis` • `25 pts`

## TL;DR

Dissect three intercepted 802.1Q/IPv6/ICMPv6 frames, work out that the damaged egress frame is an Echo Reply to one specific request, rebuild the 10 missing bytes by reversing the request's addresses, and concatenate them in frame order.

**Flag:** `REDACTED`

---

## Challenge Description

> These frames were altered when they were intercepted on the switch, find the lost information. The expected validation password is 20 characters long, i.e. 10 bytes in lowercase hexadecimal notation.

**File:** `ch14.txt`

**Context:** The file contains three intact frames captured on the way in (`INGRESS`) and one damaged frame on the way out (`EGRESS`) where unknown bytes are replaced by `?`. Exactly 10 bytes are missing, which matches the 10 bytes of the password.

---

## Recon

**Step 1: Read the capture format**

```text
>>> INGRESS >>>
        0x0000:  0050 569e 7bf9 0050 569e 7bfb 8100 0185
        0x0010:  86dd 6000 0000 0040 3a40 2002 c000 0203
        ...
<<< EGRESS <<<
        0x0000:  0050 569e 7b?? 0050 569e 7b?? ???? 0186
        0x0010:  86dd 6000 0000 0040 ??40 2002 c000 0203
        ...
```

**Observations:**
- Each frame is 122 bytes, dumped in hex with the offset in front of every line
- The `EGRESS` frame has the same layout as the `INGRESS` ones, with `?` for lost nibbles
- `8100` at offset `0x0c` and `86dd` at offset `0x10` tell us the frame is **802.1Q tagged** and carries **IPv6**

**Step 2: Know the layout**

| Offset | Size | Field |
|--------|------|-------|
| `0x00` | 6 | Destination MAC |
| `0x06` | 6 | Source MAC |
| `0x0c` | 2 | TPID (`8100` = 802.1Q tag follows) |
| `0x0e` | 2 | TCI (3 bits priority, 1 bit DEI, **12 bits VLAN ID**) |
| `0x10` | 2 | EtherType (`86dd` = IPv6) |
| `0x12` | 4 | IPv6 version / traffic class / flow label |
| `0x16` | 2 | IPv6 payload length (`0040` = 64) |
| `0x18` | 1 | Next header (`3a` = 58 = ICMPv6) |
| `0x19` | 1 | Hop limit |
| `0x1a` | 16 | IPv6 source address |
| `0x2a` | 16 | IPv6 destination address |
| `0x3a` | 1 | ICMPv6 type (`80` = Echo Request, `81` = Echo Reply) |
| `0x3b` | 1 | ICMPv6 code |
| `0x3c` | 2 | ICMPv6 checksum |
| `0x3e` | 2 | Identifier |
| `0x40` | 2 | Sequence number |
| `0x42` | ... | Echo data |

**Hypothesis:** The `EGRESS` frame is the answer to one of the three `INGRESS` frames. If we find which one and know how a reply is built, every missing byte can be deduced.

---

## Exploitation

### Step 1: Dissect the frames

A small script (`dissect.py`) parses the dump and prints each field:

```bash
$ python3 dissect.py ch14.txt
```

| | Frame 1 | Frame 2 | Frame 3 | EGRESS |
|---|---|---|---|---|
| MAC dst | `...:7b:f9` | `...:7b:f7` | `...:7b:fe` | `...:7b:??` |
| MAC src | `...:7b:fb` | `...:7b:f9` | `...:7b:f7` | `...:7b:??` |
| TPID | `8100` | `8100` | `8100` | `????` |
| VLAN | 389 | 390 | 390 | 390 |
| Next header | `3a` | `3a` | `3a` | `??` |
| IPv6 src | `2002:c000:203::7331` | `2002:c000:203::b00b` | `2002:c000:203::7331` | `2002:c000:203::????` |
| IPv6 dst | `2002:c000:203::dead` | `2002:c000:203::fada` | `2002:c000:203::b00b` | `2002:c000:203::????` |
| ICMPv6 type | `80` | `80` | `80` | `??` |
| Checksum | `0af0` | `0af0` | `c760` | `09f0` |
| Identifier | `0792` | `0792` | `0795` | `0792` |

---

### Step 2: List exactly what is missing

The script also reports the offsets of the `?` bytes in the egress frame:

```text
unknown byte offsets: 0x5, 0xb, 0xc, 0xd, 0x18, 0x28, 0x29, 0x38, 0x39, 0x3a   count = 10
```

| # | Offset | Size | Field |
|---|--------|------|-------|
| 1 | `0x05` | 1 | Destination MAC, last byte |
| 2 | `0x0b` | 1 | Source MAC, last byte |
| 3 | `0x0c` | 2 | TPID |
| 4 | `0x18` | 1 | IPv6 next header |
| 5 | `0x28` | 2 | IPv6 source, last 2 bytes |
| 6 | `0x38` | 2 | IPv6 destination, last 2 bytes |
| 7 | `0x3a` | 1 | ICMPv6 type |

✅ 1 + 1 + 2 + 1 + 2 + 2 + 1 = **10 bytes**, which is exactly the size of the password.

---

### Step 3: Request or reply?

The egress frame has code `00` and checksum `09f0`, while the requests carry `0af0`.

The ICMPv6 checksum is a one's complement sum over 16-bit words. The first word of the message is `type || code`:

```text
Request : 80 00  ->  0x8000
Reply   : 81 00  ->  0x8100   (sum + 0x0100)
```

Raising the sum by `0x0100` lowers the checksum by `0x0100`:

```text
0x0af0 - 0x0100 = 0x09f0   ✅ matches the egress checksum
```

The egress frame is therefore an **Echo Reply**, type `81`.

> 💡 Note: frames 1 and 2 have different IPv6 addresses but the same checksum `0af0`, so the checksums in this challenge are not recomputed with the real IPv6 pseudo-header. The type-field delta is the intended clue.

---

### Step 4: Which request does it answer?

An Echo Reply copies the identifier, the sequence number and the data of the request.

| Candidate | Same identifier/data? | Same VLAN (390)? |
|-----------|-----------------------|-------------------|
| Frame 1 | ✅ (`0792`) | ❌ (389) |
| Frame 2 | ✅ (`0792`) | ✅ |
| Frame 3 | ❌ (`0795`, other data) | ✅ |

Only **frame 2** satisfies both conditions.

---

### Step 5: Rebuild the reply by swapping the request's endpoints

A reply goes back where the request came from, so source and destination are swapped at both layer 2 and layer 3:

| Field | Request (frame 2) | Reply (egress) |
|-------|-------------------|----------------|
| MAC dst | `...:f7` | `...:f9` (request's source) |
| MAC src | `...:f9` | `...:f7` (request's destination) |
| IPv6 src | `...::b00b` | `...::fada` (request's destination) |
| IPv6 dst | `...::fada` | `...::b00b` (request's source) |
| ICMPv6 type | `80` | `81` |

The two remaining fields are constants:
- **TPID** is `8100`, because the frame is VLAN-tagged (the VLAN ID `0186` is already visible)
- **Next header** is `3a`, because the payload is ICMPv6

---

### Step 6: Build the password

Concatenate the 10 bytes **in the order they appear in the frame** (not in the order they were found):

```text
[dst MAC] [src MAC] [TPID] [next hdr] [IPv6 src] [IPv6 dst] [type]
   1 B       1 B      2 B      1 B        2 B        2 B      1 B
```

```
REDACTED
```

20 lowercase hex characters, as required.

---

## Impact & Mitigation

### Real-World Implications

| Weakness | Impact |
|----------|--------|
| **CWE-319** | Cleartext Transmission of Sensitive Information |
| **CWE-290** | Authentication Bypass by Spoofing |
| **CWE-923** | Improper Restriction of Communication Channel to Intended Endpoints |

**Attack Scenarios:**
1. **Passive sniffing on a switch (SPAN/mirror port)**: Anyone with access to a mirrored port sees MAC addresses, VLAN IDs, IPv6 addresses and payloads
2. **VLAN hopping**: Understanding the 802.1Q tag is the basis of double-tagging and switch-spoofing attacks
3. **MAC / IPv6 spoofing**: Every header field used here is trivially forgeable, so an attacker can craft a believable reply
4. **Network reconnaissance**: ICMPv6 Echo traffic reveals which hosts are alive and in which VLAN they sit

**Why this matters:**
- Ethernet and ICMP offer no authentication or integrity beyond a weak checksum
- Packet captures often leave the network (tickets, vendors, forums) and expose the topology
- Being able to read a raw hex dump is a core skill for incident response and protocol debugging

---

### Secure Practices

**❌ NEVER rely on this (L2/L3 identifiers are not proof of identity):**

```text
Trusting a frame because its source MAC / IPv6 address / VLAN tag looks right
```

**✅ DO this instead:**

**Option 1: Harden the switch**
```text
! Cisco-style example
interface GigabitEthernet0/1
  switchport mode access
  switchport access vlan 390
  switchport nonegotiate
  switchport port-security
  switchport port-security maximum 2
  spanning-tree bpduguard enable
```

**Option 2: Protect IPv6 neighbor discovery and router advertisements**
```text
ipv6 nd raguard policy HOST
ipv6 snooping
```

**Option 3: Encrypt and authenticate traffic end to end**
```text
MACsec (802.1AE) on the link, IPsec or TLS above it
```

**Best Practices:**
1. **Disable DTP and unused trunk negotiation**; never leave the native VLAN as VLAN 1
2. **Limit MACs per port** and enable DHCPv6/RA guard and IPv6 snooping
3. **Restrict SPAN/mirror ports** and log who configures them
4. **Sanitize captures** (addresses, VLANs, payloads) before sharing them
5. **Encrypt sensitive traffic** instead of trusting the network path

---

## Key Takeaways

**Technical Skills:**
- Read a raw hex dump and map every byte to its field (Ethernet, 802.1Q, IPv6, ICMPv6)
- Computed field offsets and counted unknown bytes to confirm the expected size
- Parsed the capture with a short Python script instead of counting nibbles by hand

**Network Concepts:**
- An 802.1Q tag adds 4 bytes: a TPID (`8100`) and a TCI whose low 12 bits are the VLAN ID
- IPv6 has a fixed 40-byte header; `next header = 58` means ICMPv6
- ICMPv6 Echo: type `128` (`0x80`) request, type `129` (`0x81`) reply; the reply echoes the identifier, sequence number and data
- The ICMP checksum is a one's complement sum, so changing one word shifts the checksum by the opposite amount
- A reply swaps source and destination at every layer

---

## References

- [Ethernet frame formats (FR)](https://repository.root-me.org/R%C3%A9seau/FR%20-%20Les%20r%C3%A9seaux%20Ethernet%20-%20le%20format%20des%20trames.pdf)
- [Ethernet frame format (FR)](https://repository.root-me.org/R%C3%A9seau/FR%20-%20Format%20des%20trames%20Ethernet.pdf)
- [IEEE 802.1Q: Virtual LANs](https://www.ieee802.org/1/pages/802.1Q.html)
- [RFC 8200: Internet Protocol, Version 6 (IPv6) Specification](https://www.rfc-editor.org/rfc/rfc8200)
- [RFC 4443: ICMPv6 for IPv6](https://www.rfc-editor.org/rfc/rfc4443)
- [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
