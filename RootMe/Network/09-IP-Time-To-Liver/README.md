# IP - Time To Live

`Network` • `Easy` • `15 pts`

## TL;DR

ICMP traceroute capture analysis. Identify the minimum TTL value that successfully reached the target host by finding the first Echo Reply in the packet capture.

**Flag:** `[REDACTED]`

---

## Challenge Description

> Retrouvez le TTL employé pour atteindre l'hote ciblé par cet échange de paquets ICMP.
> *(Find the TTL used to reach the targeted host in this ICMP packet exchange.)*

**Given:** `ch7.pcap` (network capture file)

---

## Recon

### What is TTL?

**Time To Live** is a field in the IP header (1 byte, values 1–255). Its purpose:

- Each router that forwards a packet **decrements TTL by 1**
- When TTL reaches **0**, the router **drops the packet** and sends back an ICMP "Time Exceeded" (type 11) message to the sender
- This prevents packets from looping forever on the internet

```
Sender → [TTL=13] → Router1 [TTL=12] → Router2 [TTL=11] → ... → Destination [TTL=1] → Echo Reply ✅
Sender → [TTL=1]  → Router1 [TTL=0]  → ✗ TTL Exceeded sent back to sender
```

### What is a Traceroute?

Traceroute exploits TTL to **map the route** between two hosts:

1. Send packet with TTL=1 → first router drops it and reveals its IP
2. Send packet with TTL=2 → second router drops it and reveals its IP
3. Repeat until the destination finally replies

**The flag is the TTL value at which the destination first replied.**

---

## Exploitation

### Method 1: Wireshark GUI

1. Open: `wireshark ch7.pcap`
2. Apply filter: `icmp`
3. Look for the first **Echo Reply** (ICMP type 0) — not "TTL Exceeded" (type 11)
4. Click the Echo Request that triggered it → check the **TTL field** in the IP header

The first Echo Reply appears at packet 72, in response to the request at packet 71 with **TTL=13**.

### Method 2: Python parsing

```python
import struct

with open('ch7.pcap', 'rb') as f:
    data = f.read()

offset = 24  # skip pcap global header
packets = []
while offset < len(data):
    if offset + 16 > len(data): break
    incl_len = struct.unpack('<I', data[offset+8:offset+12])[0]
    pkt = data[offset+16:offset+16+incl_len]
    packets.append(pkt)
    offset += 16 + incl_len

for i, pkt in enumerate(packets):
    eth_type = struct.unpack('>H', pkt[12:14])[0]
    if eth_type != 0x0800: continue           # IPv4 only
    ip = pkt[14:]
    ihl = (ip[0] & 0x0f) * 4
    proto = ip[9]
    ttl   = ip[8]
    src   = '.'.join(str(b) for b in ip[12:16])
    dst   = '.'.join(str(b) for b in ip[16:20])
    if proto != 1: continue                   # ICMP only
    icmp_type = ip[ihl]
    if icmp_type == 0:                        # Echo Reply
        print(f"Pkt {i+1}: Echo Reply from {src} → {dst}, request TTL was {ttl}")
        break
```

**Output:**
```
Pkt 72: Echo Reply from 198.173.244.32 → 24.6.126.218
```

Check the corresponding Echo Request (pkt 71): **TTL = 13**

### Method 3: tshark one-liner

```bash
# Show all ICMP types and TTL values
tshark -r ch7.pcap -Y "icmp.type == 8" -T fields \
  -e frame.number -e ip.ttl -e icmp.type -e ip.dst

# Find the first request that got a reply (not TTL exceeded)
tshark -r ch7.pcap -Y "icmp.type == 0" -T fields -e frame.number -e ip.src
# → First Echo Reply at frame 72, from 198.173.244.32
# → Corresponding request at frame 71 had TTL=13
```

---

## Full Traceroute Reconstruction

| Hop | Router IP | TTL sent |
|-----|-----------|----------|
| 1 | `12.244.25.161` | 1 |
| 2 | `12.244.67.17` | 2 |
| 3 | `12.244.72.210` | 3 |
| 4 | `12.122.2.250` | 4 |
| 5 | `12.123.28.129` | 5 |
| 6 | `129.250.9.109` | 6 |
| 7 | `129.250.2.112` | 7 |
| 8 | `129.250.4.197` | 8 |
| 9 | `129.250.5.35` | 9 |
| 10 | `129.250.27.187` | 10 |
| 11 | `204.2.121.162` | 11–12 |
| **12** | **`198.173.244.32`** ← destination | **13** ✅ |

Each hop replies 3 times (standard traceroute sends 3 probes per TTL). The destination `198.173.244.32` responds with an **Echo Reply** at TTL=13 — 12 routers in between + the destination itself.

**Note:** Packet 64 is an ICMP type 3 (Port Unreachable) to `216.148.227.68` — a DNS resolution attempt made during the traceroute, unrelated to the main path.

---

## Key Concepts

### TTL in the IP Header

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |     DSCP      |         Total Length          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|     Fragment Offset     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |       Header Checksum         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

TTL is byte 8 of the IP header (offset 8, 1 byte). Default values by OS:

| OS | Default TTL |
|----|-------------|
| Linux | 64 |
| Windows | 128 |
| Cisco IOS | 255 |
| macOS | 64 |

The response TTL of 51 (`256 - 51 = 205`... or `64 - 13 = 51`) indicates the destination is a **Linux/Unix host** that started with TTL=64 and lost 13 hops worth of TTL on the return path.

### ICMP Types Used in Traceroute

| ICMP Type | Code | Meaning | Direction |
|-----------|------|---------|-----------|
| **8** | 0 | Echo Request | Source → Target |
| **0** | 0 | Echo Reply | Target → Source ✅ |
| **11** | 0 | Time Exceeded (TTL=0) | Router → Source |
| **3** | 3 | Port Unreachable | Router → Source |

---

## Key Takeaways

**Technical Skills:**
- Read and interpreted a PCAP containing ICMP traceroute traffic
- Distinguished between Echo Request (type 8), Echo Reply (type 0), and TTL Exceeded (type 11)
- Reconstructed the full network path from source to destination
- Parsed raw pcap binary format in Python without external libraries

**Security Concepts:**
- TTL is a fundamental IP mechanism for loop prevention and network diagnostics
- Traceroute reveals internal network topology — useful for recon (MITRE ATT&CK T1590)
- ICMP can be blocked by firewalls, causing `* * *` (no response) at certain hops
- The return TTL of a host can reveal its OS (TTL fingerprinting)

---

## References

- [RFC 793 - Transmission Control Protocol](https://datatracker.ietf.org/doc/html/rfc793)
- [RFC 1035 - Domain Names - Implementation and Specification](https://datatracker.ietf.org/doc/html/rfc1035)
- [RFC 792 - Internet Control Message Protocol (ICMP)](https://datatracker.ietf.org/doc/html/rfc792)
- [RFC 791 - Internet Protocol (IP Header / TTL field)](https://datatracker.ietf.org/doc/html/rfc791)
- [MITRE ATT&CK T1590: Gather Victim Network Information](https://attack.mitre.org/techniques/T1590/)