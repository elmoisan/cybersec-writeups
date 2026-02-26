# Bluetooth - Fichier inconnu

`Network` • `Easy` • `15 pts`

## TL;DR

BTSnoop Bluetooth capture analysis. Extract the remote device's MAC address and name from an HCI event packet, then compute `SHA1(MAC + DeviceName)`.

**Flag:** `[REDACTED]`

---

## Challenge Description

> Votre ami travaillant à l'ANSSI a récupéré un fichier illisible dans l'ordi d'un hacker. Tout ce qu'il sait est que cela provient d'un échange entre un ordinateur et un téléphone. À vous d'en apprendre le plus possible sur ce téléphone.
>
> La réponse est le hash SHA1 de la concaténation de l'adresse MAC (en majuscules) et du nom du téléphone.

**Example given:**
```
AB:CD:EF:12:34:56monTelephone -> 836eca0d42f34291c5fefe91010873008b53c129
```

**Given:** `ch18.bin` (unknown binary file)

---

## Recon

### File Identification

```bash
$ file ch18.bin
ch18.bin: BTSnoop version 1, HCI UART (H4)
```

The file is a **BTSnoop capture** — a standard format for logging Bluetooth HCI (Host Controller Interface) traffic, analogous to PCAP for network traffic. The hint "Google est ton ami" points to needing to identify the device model from its name.

### BTSnoop Format

| Field | Size | Description |
|-------|------|-------------|
| Magic | 8 bytes | `btsnoop\x00` |
| Version | 4 bytes (BE) | `1` |
| Datalink | 4 bytes (BE) | `1002` = HCI UART (H4) |
| Packets | variable | Each packet: 24-byte header + payload |

Each packet record:

```
[4B orig_len][4B incl_len][4B flags][4B drops][8B timestamp][payload]
```

---

## Exploitation

### Step 1: Parse the BTSnoop file

```python
import struct

with open('ch18.bin', 'rb') as f:
    data = f.read()

offset = 16  # skip 16-byte file header
packets = []
while offset < len(data):
    orig_len = struct.unpack('>I', data[offset:offset+4])[0]
    incl_len = struct.unpack('>I', data[offset+4:offset+8])[0]
    pkt_data = data[offset+24:offset+24+incl_len]
    packets.append(pkt_data)
    offset += 24 + incl_len

print(f"Total packets: {len(packets)}")  # 27 packets
```

### Step 2: Identify the key packet

Inspecting packet 8 (index 8):

```
04 07 ff 00 c6 4f b9 19 b3 0c 47 54 2d 53 37 33 39 30 47 00 ...
```

This is an **HCI Event: Remote Name Request Complete** (`0x07`):

| Bytes | Value | Meaning |
|-------|-------|---------|
| `04` | — | HCI Event indicator |
| `07` | — | Event code: Remote Name Request Complete |
| `ff 00` | 255 | Parameter total length |
| `c6 4f b9 19 b3 0c` | — | **BD_ADDR (MAC, little-endian)** |
| `47 54 2d 53 37 33 39 30 47` | `GT-S7390G` | **Remote device name (UTF-8)** |

### Step 3: Extract MAC and name

```python
pkt = packets[8]

# MAC address: bytes 4-9, little-endian → reverse for standard notation
mac_bytes = pkt[4:10]
mac = ':'.join(f'{b:02X}' for b in reversed(mac_bytes))
print(f"MAC: {mac}")  # 0C:B3:19:B9:4F:C6

# Device name: bytes 10 onward, null-terminated
name = pkt[10:].split(b'\x00')[0].decode('utf-8')
print(f"Name: {name}")  # GT-S7390G
```

### Step 4: Identify the device

```
GT-S7390G → Samsung Galaxy Trend Lite (Android 4.1)
```

A quick Google search for `GT-S7390G` confirms this is a **Samsung Galaxy Trend Lite** — a low-end Android smartphone released in 2013. This is what the hint "Google est ton ami" refers to.

### Step 5: Compute the flag

```python
import hashlib

mac  = "0C:B3:19:B9:4F:C6"
name = "GT-S7390G"

concat = mac + name
flag = hashlib.sha1(concat.encode()).hexdigest()
print(f"{concat} -> {flag}")
# 0C:B3:19:B9:4F:C6GT-S7390G -> c1d0349c153ed96fe2fadf44e880aef9e69c122b
```

**Flag:** `c1d0349c153ed96fe2fadf44e880aef9e69c122b`

---

## Key Concepts

### BTSnoop vs PCAP

| Feature | BTSnoop | PCAP |
|---------|---------|------|
| **Protocol** | Bluetooth HCI | Network (Ethernet, Wi-Fi, etc.) |
| **Tool** | Wireshark, hcidump | Wireshark, tshark, tcpdump |
| **Magic bytes** | `btsnoop\x00` | `\xd4\xc3\xb2\xa1` |
| **Byte order** | Big-endian headers | Little-endian headers |
| **Extension** | `.bin`, `.log`, `.btsnoop` | `.pcap`, `.pcapng` |

### HCI BD_ADDR Endianness

Bluetooth MAC addresses (**BD_ADDR**) are stored **little-endian** in HCI packets. Always reverse the 6 bytes before formatting:

```
Raw bytes:  c6 4f b9 19 b3 0c
Reversed:   0c b3 19 b9 4f c6
Formatted:  0C:B3:19:B9:4F:C6  ✅
```

Forgetting to reverse is the most common mistake on this challenge.

---

## Impact & Mitigation

### Real-World Implications

| Vulnerability | Impact |
|---------------|--------|
| **CWE-319** | Cleartext Transmission of Sensitive Information |
| **MITRE ATT&CK T1424** | Process Discovery (mobile) |
| **Risk** | Bluetooth device name and MAC passively leaked during device discovery/pairing |

Bluetooth Classic device discovery broadcasts the device name and MAC in plaintext. Any device in range with a Bluetooth sniffer (e.g., Ubertooth One, HackRF) can passively log this information — no pairing required.

### Secure Practices

| Recommendation | Details |
|----------------|---------|
| **Disable discovery mode** | Only enable Bluetooth pairing when needed |
| **Use Bluetooth LE Privacy** | BLE supports MAC address randomization (Classic does not) |
| **Rename devices** | Avoid using personal names or identifiable info as device names |
| **Physical awareness** | Be cautious in public spaces — Bluetooth has ~10–100m range |

---

## Key Takeaways

**Technical Skills:**
- Parsed a BTSnoop binary capture format manually in Python
- Identified HCI event types and their packet structure
- Correctly handled little-endian BD_ADDR byte ordering
- Correlated a device model string (`GT-S7390G`) with a real device via OSINT

**Security Concepts:**
- Bluetooth Classic device discovery leaks MAC and device name in plaintext
- BTSnoop is the Bluetooth equivalent of PCAP — readable with Wireshark
- OSINT (device name → manufacturer/model) is a valid forensic technique

---

## References

- [BTSnoop File Format Specification](https://www.fte.com/webhelp/bpa600/Content/Technical_Information/BTSnoop_File_Format.htm)
- [Bluetooth HCI Event Packet Structure (BT Core Spec)](https://www.bluetooth.com/specifications/specs/core-specification/)
- [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
- [MITRE ATT&CK T1424: Process Discovery](https://attack.mitre.org/techniques/T1424/)
- [Wireshark: Opening BTSnoop files](https://wiki.wireshark.org/Bluetooth)
- [Samsung GT-S7390G — GSMArena](https://www.gsmarena.com/samsung_galaxy_trend_lite-5234.php)