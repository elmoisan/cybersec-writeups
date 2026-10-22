# HTB Try-Outs — "Shush Protocol" (ICS)

**Category:** ICS  
**Difficulty:** Very Easy

---

## Challenge Description

> The crew sets their sights on an abandoned fertilizer plant, a desolate structure rumored to hold a cache of ammonium nitrate—crucial for their makeshift explosives. Navigating through the plant's crumbling corridors, they reach the main control room where a dusty, outdated PLC still hums faintly with power. The crew's hackers spring into action, connecting their equipment to the network of the PLC and starting the process of extracting data. They know that finding the password the control device uses to connect to the PLC is key to gaining full access to it. The hackers deploy network enumeration tools to scan for active devices on the plant's internal network. They meticulously sift through IP addresses, looking for clues that might reveal the password. After several tense hours, they pinpoint the device—a ruggedized industrial computer buried under layers of dust, still linked to the PLC that performs certain diagnostic operations under a custom protocol on a specific interval. Having captured the traffic from that connection the only thing that remains is to locate the packet that contains the secret information.

We're given a zip archive containing a single network capture:

```text
ics_shush_protocol/
└── traffic.pcapng
```

The hints in the story are worth reading carefully:

- "a **custom protocol**" → not everything in the capture will be dissected by default.
- "on a **specific interval**" → one connection sends periodic requests (a heartbeat or polling loop).
- "locate **the packet** that contains the secret" → the password is in a single packet.

---

## Tooling

- [Wireshark](https://www.wireshark.org/) — filter, follow a TCP stream, inspect raw bytes.
- `python3` with only the standard library — handy for parsing the capture by hand (`struct`), which is what I did for the analysis below.

Despite its extension, `traffic.pcapng` is a classic **pcap** file (`file` reports "pcap capture file, version 2.4, Ethernet"), but Wireshark opens it without any issue.

---

## First Look at the Capture

The capture holds **110 packets**, all TCP and all with **port 502** on one side, the well-known port of **Modbus/TCP**, a very common industrial protocol:

| Role | Address |
|---|---|
| Client (control device) | `192.168.178.105` |
| PLC | `192.168.178.23` |

A quick filter in Wireshark is enough to confirm there is nothing else:

```text
tcp.port == 502
```

---

## Separating Standard Modbus from the Custom Protocol

Modbus/TCP frames start with a 7-byte header (MBAP):

```text
 00 0c | 00 00 | 00 33 | 00
  tid    proto   length  unit id
```

followed by a **function code** and its data. Looking at the payloads, the traffic splits into two families.

### 1. Standard Modbus reads (noise)

Requests such as these use a new source port every time and standard function codes `0x01` (read coils) and `0x03` (read holding registers):

```text
00 01 00 00 00 06 00 03 00 0a 00 64     # FC 0x03, address 10, quantity 100
00 01 00 00 00 06 00 01 00 7b 00 64     # FC 0x01, address 123, quantity 100
```

The replies are mostly zeros and carry no useful data.

### 2. A custom function code on one long-lived connection

One connection (client source port **39888**) uses the non-standard function code **`0x66`** (102). It sends a 10-byte request roughly every 100 ms, which is the "specific interval" from the description:

```text
00 02 00 00 00 04 00 66 00 47           → request  (FC 0x66, address 0x0047)
00 02 00 00 00 0a 00 66 00 47 ff 01 00 01 00 01   → reply (status data)
```

This is the "diagnostic operation" of the story: a polling loop that repeats the same request over and over.

---

## Spotting the Anomaly in the Polling Loop

Following this connection (**Follow → TCP Stream** on the packets from port 39888) shows the loop being broken near the beginning. Two packets after the regular polling requests are different:

```text
# Packet 33 → 34: a different address (0x0012)
33  00 0b 00 00 00 04 00 66 00 12
34  00 0b 00 00 00 0f 00 66 00 12 ff 01 00 6f 70 65 72 61 74 6f 72
                                            └─ "operator"

# Packet 35 → 36: address 0x0010, with a long payload
35  00 0c 00 00 00 33 00 66 00 10 2e 48 54 42 7b 35 30 6d 33 ...
36  00 0c 00 00 00 07 00 66 00 10 f0 e0 06
```

- Address `0x0012` returns a readable string: **`operator`**, which looks like a **username**.
- Address `0x0010` is a **write** of a length-prefixed string: after the function code and address, the byte `0x2e` (**46**) gives the length, followed by 46 ASCII bytes. This is the **password** the control device sends to the PLC.

The length checks out: the MBAP length field is `0x33` = 51 = unit id (1) + function code (1) + address (2) + length byte (1) + 46 data bytes.

The same data is clearly visible in the Follow TCP Stream view, between the username and the end of the exchange:

```text
...f f  operator  3f .HTB{50m371m35_cu570m_p2070c01_423_n07_3n0u9h7} f...
```

---

## Extracting the Password

The hex bytes of packet 35 after the length byte:

```text
48 54 42 7b 35 30 6d 33 37 31 6d 33 35 5f 63 75 35 37 30 6d 5f 70 32 30 37 30 63 30 31 5f 34 32 33 5f 6e 30 37 5f 33 6e 30 75 39 68 37 7d
```

Decoding them as ASCII (in Wireshark: right-click the bytes → **Copy → …as Printable Text**, or with Python):

```python
payload = bytes.fromhex(
    "48 54 42 7b 35 30 6d 33 37 31 6d 33 35 5f 63 75 35 37 30 6d 5f 70 32 30 "
    "37 30 63 30 31 5f 34 32 33 5f 6e 30 37 5f 33 6e 30 75 39 68 37 7d"
)
print(len(payload), payload.decode())
```

```text
46 HTB{50m371m35_cu570m_p2070c01_423_n07_3n0u9h7}
```

A quick scan of every packet for printable ASCII runs confirms that only two strings exist in the whole capture: `operator` (packet 34) and the flag (packet 35).

---

## Putting It Together

Decoding the leetspeak:

| Leet | Decoded |
|---|---|
| `50m371m35` | SOMETIMES |
| `cu570m` | CUSTOM |
| `p2070c01` | PROTOCOL |
| `423` | ARE |
| `n07` | NOT |
| `3n0u9h7` | ENOUGH |

→ "Sometimes custom protocols are not enough" — the point being that a proprietary protocol does not protect a secret if it is sent **in clear text** and the traffic can be captured.

---

## What Happens After the Password

After the PLC answers packet 35 with `f0 e0 06`, the polling requests change from `66 00 47` to `66 e0 47`. This suggests that the reply contains a session identifier or token that the client reuses afterwards. This part is my interpretation of the traffic and is not needed to solve the challenge.

---

## Flag

```text
HTB{REDACTED}
```

---

## Takeaways

- In ICS captures, start by identifying the **protocol and ports** (here Modbus/TCP on 502), then separate the standard traffic from anything that deviates, such as a **non-standard function code**.
- A **periodic loop** is useful for spotting what breaks the pattern: the interesting packets are the ones that differ in size, address or timing from the repeating heartbeat.
- Large or unusual payloads are the first thing to check. Here the one 57-byte request among 10-byte polls was the password.
- "Custom" or proprietary industrial protocols give **security through obscurity** only. Without encryption or authentication on the wire, any credential sent over the network can be read by anyone who captures the traffic.
- Wireshark's **Follow TCP Stream** and a plain printable-text search are often enough to solve beginner ICS forensics challenges, even when the protocol is not dissected.
