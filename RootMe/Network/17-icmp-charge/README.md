# Charge ICMP

`Network` • `Hard` • `40 pts`

## TL;DR

Analyze a capture made entirely of `ICMP` echo-request/echo-reply traffic. The interesting packets carry an oversized 256-byte payload, but the hidden data isn't in the raw bytes directly — it's in the bytes that appear in only one packet and nowhere else. Extracting those and applying a Caesar rotation of -42 reveals an MD5 hash in plaintext.

**Flag:** `[REDACTED]`

---

## Challenge Description

> INDICE : Une information est cachée dans cette capture de paquets ICMP. Le flag de validation est un hash MD5.
>
> Ce challenge est issu des épreuves de qualification pour le CTF de la 18ème édition de la DEFCON.

**Provided file:** `ch6.pcap`

---

## Recon

`tshark -q -z io,phs` shows the capture contains nothing but `ICMP` traffic (34 packets, `eth > ip > icmp` only — no TCP/UDP at all).

Listing type/code/length per packet shows a mix of `echo request` (type 8) and `echo reply` (type 0), most carrying a **256-byte payload** — far larger than a typical ping payload (32–48 bytes), which is the first sign of a covert channel. One outlier packet carries 129 bytes instead of 256 — a natural first suspect, but it turns out to be a decoy.

Since echo-replies just mirror the request's payload, only the **echo-request (type 8)** packets need to be analyzed.

---

## Exploitation

### 1) Dead ends first

Standard techniques applied to the raw 256-byte payloads produce nothing readable:

- Frequency analysis of the byte stream doesn't resemble natural-language text.
- Single-byte XOR brute force across the whole concatenated payload yields no printable result.
- A direct Caesar rotation on the full payload stream also fails.

The byte values are confined to a narrow, unusual range (roughly `0x34`–`0xa8`, ~39 distinct values), which rules out a simple substitution over the full stream and hints that most of the payload is just filler/noise shared across packets.

### 2) The real trick: keep only bytes unique to their packet

The key insight — "*sumthing is not like the other*" — is that the payload bytes that matter are the ones that appear **in one packet and no other**. Every other byte is shared padding designed to blend the real signal into noise.

Using Scapy, only the 256-byte `echo request` packets are kept, and for each one, only the byte values that don't occur in any other captured packet are extracted, in order:

```python
from scapy.all import rdpcap, ICMP, Raw

pkts = rdpcap('ch6.pcap')
raws = [bytes(p[Raw].load) for p in pkts
        if p.haslayer(ICMP) and p[ICMP].type == 8 and len(p[Raw].load) == 256]

def alone(c, strs, exceptstr):
    for s in strs:
        if s != exceptstr and c in s:
            return False
    return True

unique = b""
for raw in raws:
    for c in raw:
        if alone(c, raws, raw):
            unique += bytes([c])
```

This yields exactly **32 bytes** — the length of an MD5 hash written in hexadecimal, a strong hint that the extraction is correct.

### 3) Caesar rotation to recover the plaintext

The 32 extracted bytes aren't ASCII yet, so every rotation (`+i mod 256`) is tried on them:

```python
for i in range(256):
    shifted = bytes([(c + i) % 256 for c in unique])
    if all(32 <= b < 127 for b in shifted):
        print(i, shifted.decode('ascii'))
```

At **i = 214** (equivalent to a shift of **-42**), the output becomes fully printable ASCII:

```
a7290d426b6a1764af6fd7fba5db214e
```

A 32-character lowercase-hex string — a valid MD5 hash.

---

## Final Reconstruction

| Step | Result |
|------|--------|
| Filter | 256-byte `ICMP` echo-request packets only |
| Extraction | Bytes unique to a single packet, concatenated in order |
| Transform | Caesar rotation by -42 |
| Output | `a7290d426b6a1764af6fd7fba5db214e` (MD5 hash) |

---

## Key Takeaways

- **ICMP payload size is a giveaway:** a normal `ping` payload is small and fixed; anything noticeably larger (here 256 bytes) suggests data smuggling or a covert channel.
- **"Noise plus signal" hiding:** padding shared identically across every packet is easy to build and easy to filter out — isolating what's *not* repeated is often more productive than analyzing the raw stream as a whole.
- **Try the full 256-value rotation space, not just printable-ASCII shifts:** an unusual but consistent rotation constant (-42, a nod to *The Hitchhiker's Guide to the Galaxy*) is exactly the kind of "magic number" some encodings (like yEnc) use, and it's cheap to brute-force blindly.
- **Recognize output shape as a validation signal:** hitting exactly 32 bytes (hex-MD5 length) before even decoding confirms the extraction method is correct, well before the content is readable.

---

## References

- [RFC 792 - Internet Control Message Protocol](https://datatracker.ietf.org/doc/html/rfc792)
- [yEnc encoding specification](http://www.yenc.org/yenc-draft.1.3.txt)
- [DEF CON 18 CTF Quals - Packet 100 writeup (StalkR's Blog)](https://blog.stalkr.net/2010/05/defcon-18-ctf-quals-writeup-packet-100.html)
