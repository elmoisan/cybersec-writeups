# GSM - Network Traffic

`Network` • `Packet Capture Analysis` • `25 pts`

## TL;DR

Open a pcap captured on a GSM A-bis link, ignore the LAPD keep-alives, find the single SMS-DELIVER hidden in frame 87, and decode its GSM 7-bit user data by hand. The capture was cut short by a 96-byte snaplen, but the part of the SMS that survived still contains the flag.

**Flag:** `REDACTED`

---

## Challenge Description

> You are hired to analyze a network capture. You must hand over something understandable to your contact, even if at first sight the trace looks incomplete.

**File:** `ch9.pcap`

**Context:** A short capture (104 frames) of Global System for Mobile communications traffic. Almost all frames are identical signalling noise. One frame carries an SMS, and that frame is truncated.

---

## Recon

**Step 1: Read the capture header**

```text
magic     0xa1b2c3d4   (classic pcap, little endian)
linktype  113          (Linux cooked capture, SLL)
snaplen   96
frames    104
```

**Observations:**
- Link type 113 is *Linux cooked capture*; the 16-byte SLL header carries protocol `0x00f5`, which Wireshark hands to the LAPD / GSM A-bis dissectors
- The **snaplen is 96**: no frame can be stored with more than 96 bytes
- Comparing `caplen` and `origlen` for every record shows that only one frame was clipped (see Step 2)

**Step 2: Triage the frames**

| Frames | Size | What they are |
|--------|------|---------------|
| 1-36, 44-80, 84-86, ... | 31 bytes | LAPD keep-alive style frames, only the last byte changes |
| 38, 40, 42, 95, 97, 99 | 41 / 32 bytes | Radio signalling (location updating with LAI `20801`, channel assignment) |
| **87** | **96 bytes** | **Larger payload, contains an SMS** |

```text
frame 87: caplen 96 / origlen 126
```

**Observations:**
- The location area identity contains `20801`: MCC **208** (France), MNC **01** (Orange)
- Frame 87 is the only one whose original length is larger than what was stored: **30 bytes are missing**
- The payload contains the byte pair `07 91`, the start of an SMSC address in international format

**Hypothesis:** Frame 87 is an SMS delivered to the handset. Even truncated, the first characters of the message are intact, so the flag may still be readable.

---

## Exploitation

### Step 1: Isolate the TPDU

After the 16-byte SLL header and the A-bis/LAPD framing, the data is a GSM 03.40 *SMS-DELIVER*:

```text
07 91 23 30 10 21 00 68                 SMSC (length 7, international)
04                                      first octet: MTI = 00 (SMS-DELIVER), UDHI = 0
0b 91 71 20 33 66 03 f8                 originating address (11 digits)
00                                      PID
00                                      DCS = GSM 7-bit default alphabet
21 40 20 61 65 02 08                    timestamp
47                                      UDL = 71 septets
c7 f7 9b 0c 52 bf c5 2c 10 1d 5d 06 ... user data (packed 7-bit)
```

---

### Step 2: Decode the header fields

Numbers and timestamps are **BCD with swapped nibbles**, and `f` is a filler.

| Field | Raw | Decoded |
|-------|-----|---------|
| SMSC | `23 30 10 21 00 68` | `+32 03 01 12 00 86` |
| Originating address | `71 20 33 66 03 f8` | `+17023366308` |
| Timestamp | `21 40 20 61 65 02 08` | `2012-04-02 16:56:20` |
| DCS | `00` | GSM 7-bit default alphabet |
| UDL | `47` | 71 characters announced |

---

### Step 3: Spot the truncation

```text
UDL announced : 71 septets  ->  ceil(71 * 7 / 8) = 63 bytes
Bytes present : 33 bytes    ->  floor(33 * 8 / 7) = 37 septets
```

Only 37 of the 71 characters made it into the capture, which is exactly the "incomplete trace" from the statement. The rest was dropped by the snaplen, not by the network.

---

### Step 4: Unpack the GSM 7-bit data

GSM 7-bit packs 8 characters into 7 bytes. Each byte holds the low bits of one septet and the high bits of the next, starting from the **least significant bit**. A short script (`decode_sms.py`) does it:

```python
GSM7 = ("@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞ\x1bÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?"
        "¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà")

bits = int.from_bytes(user_data, "little")
text = "".join(GSM7[(bits >> (7 * k)) & 0x7f] for k in range(len(user_data) * 8 // 7))
print(text[:71])
```

```bash
$ python3 -I decode_sms.py ch9.pcap
'Good job, the flag is REDACTED'
```

The 37 recovered characters are the whole useful message, the flag included.

---

### Step 5: Validate

The flag is the word that follows `the flag is`, 15 lowercase alphanumeric characters.

```text
REDACTED
```

---

## Impact & Mitigation

### Real-World Implications

| Weakness | Impact |
|----------|--------|
| **CWE-319** | Cleartext Transmission of Sensitive Information |
| **CWE-311** | Missing Encryption of Sensitive Data |

**Attack Scenarios:**
1. **Passive interception of a radio or backhaul link**: SMS content, sender number, SMSC and timestamp are all readable without any key
2. **2FA / one-time code theft**: Codes sent by SMS can be read by anyone able to sniff the link, which is why SMS is a weak second factor
3. **Metadata collection**: Location area (MCC/MNC/LAC), numbers and timing reveal who talks to whom and where

**Why this matters:**
- SMS has no end-to-end confidentiality; protection, when present, only covers the radio hop and depends on the cipher in use
- A truncated capture is still evidence: the first bytes of a payload are often enough
- Reading a raw TPDU by hand is a useful skill for telecom forensics and for checking what a tool reports

---

### Secure Practices

**❌ NEVER rely on this (SMS as a confidential channel):**

```text
Sending passwords, one-time codes or secrets in a plain SMS
```

**✅ DO this instead:**

**Option 1: Use an authenticated app or hardware token**
```text
TOTP application, FIDO2/WebAuthn security key
```

**Option 2: Use end-to-end encrypted messaging for sensitive content**
```text
Signal or any E2EE messenger instead of SMS
```

**Best Practices:**
1. **Treat SMS as cleartext**, even when the radio link is encrypted
2. **Capture with a large enough snaplen** (`tcpdump -s 0`) so analysis is never limited by truncation
3. **Restrict access to A-bis / backhaul links** and encrypt them (IPsec) when they cross untrusted networks
4. **Sanitize captures** (numbers, SMSC, location data) before sharing them

---

## Key Takeaways

**Technical Skills:**
- Read the pcap global header (link type, snaplen) and compare `caplen` with `origlen` to find truncated frames
- Filter repetitive signalling and focus on the one frame that carries content
- Decode an SMS-DELIVER TPDU by hand: BCD numbers, timestamp, PID, DCS, UDL, user data
- Unpack GSM 7-bit text with a short Python script instead of doing it bit by bit

**Network Concepts:**
- GSM A-bis connects the BTS to the BSC and uses LAPD for signalling
- MCC/MNC identify the country and the operator (`208` / `01` = France / Orange)
- SMS-DELIVER carries the originating address, the timestamp and the user data; UDL counts **septets**, not bytes
- GSM 7-bit packs 8 characters into 7 bytes, so a truncated payload loses characters at the end only
- A small snaplen silently truncates packets: always check `caplen` versus `origlen`

---

## References

- [3GPP TS 23.040: Technical realization of the Short Message Service (SMS)](https://www.3gpp.org/dynareport/23040.htm)
- [3GPP TS 23.038: Alphabets and language-specific information](https://www.3gpp.org/dynareport/23038.htm)
- [pcap savefile format (tcpdump)](https://www.tcpdump.org/manpages/pcap-savefile.5.html)
- [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
- [CWE-311: Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html)
