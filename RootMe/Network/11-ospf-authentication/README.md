# OSPF - Authentication

`Network` • `Easy` • `15 pts`

## TL;DR

Extract and crack MD5 authentication key from OSPF routing protocol packets captured in network traffic.

**Flag:** `[REDACTED]`

---

## Challenge Description

> You are hired to test the security of an enterprise network. You quickly managed to capture some OSPF packets.
> 
> Retrieve the OSPF authentication key to continue your investigation!

**SHA256 checksum:** `9CF709C4984B7EB6426A6B4B9B3B35604055B6040CCD46B30DF785D7D21F28AB`

---

## Recon

**OSPF (Open Shortest Path First)** is a link-state routing protocol used in enterprise networks. Routers exchange topology information to calculate optimal paths.

**OSPF Authentication Types:**
- **Type 0**: Null (no authentication)
- **Type 1**: Simple password (plaintext)
- **Type 2**: MD5 cryptographic authentication

**Vulnerability:** MD5 authentication keys can be extracted from packet captures and brute-forced offline.

---

## Exploitation

### Step 1: Analyze PCAP in Wireshark
```bash
wireshark ospf_authentication_hash.pcapng
```

**Apply filter:** `ospf`

**Observations:**
- Multiple OSPF Hello packets
- Source: `12.0.0.1` and `12.0.0.2`
- Destination: `224.0.0.5` (OSPF multicast)

**Inspect packet details:**
```
Open Shortest Path First
  OSPF Header
    Version: 2
    Message Type: Hello Packet (1)
    Auth Type: Cryptographic (2)
    Auth Crypt Key id: 10
    Auth Crypt Sequence Number: 1014941860
    Auth Crypt Data: debe4e93b093ade8a8bc34302c192ced
```

**MD5 hash extracted:** `debe4e93b093ade8a8bc34302c192ced`

---

### Step 2: Crack OSPF MD5 with Dictionary Attack

**Method 1: Using ospf_bruteforce.py**
```bash
# Clone the tool
git clone https://github.com/mauricelambert/OSPF_bruteforce.git
cd OSPF_bruteforce

# Install dependencies
pip3 install scapy --break-system-packages
wget https://raw.githubusercontent.com/wiki/secdev/scapy/attachments/Code/OSPF/scapy_ospf-v0.91.py -O scapy_ospf.py

# Run the attack
python3 ospf_bruteforce.py ospf_authentication_hash.pcapng rockyou.txt
```

**Result:**
```
[+] 0201003002020202...03030303 debe4e93b093ade8a8bc34302c192ced #10pokemonmaster
[+] Done !
```

**Password found:** `[REDACTED]` (Key ID: 10)

---

### Step 3: Verification

All OSPF packets in the capture use the same authentication key:
- **Key ID:** 10
- **Password:** pokemonmaster
- Multiple sequence numbers (1014941860, 1014941863, etc.)

---

## Impact & Mitigation

### Real-World Implications

| Vulnerability | Impact |
|---------------|--------|
| **CWE-916** | Use of Password Hash With Insufficient Computational Effort |
| **CVE-2013-0149** | Cisco OSPF MD5 authentication bypass |
| **MITRE ATT&CK T1557.002** | Man-in-the-Middle via ARP/routing manipulation |

**Attack Scenarios:**
1. **Route injection**: Attacker joins OSPF domain with cracked key
2. **Blackhole attacks**: Redirect traffic to attacker-controlled router
3. **Traffic interception**: Position as man-in-the-middle in routing path
4. **Denial of Service**: Inject invalid routes, disrupt network convergence

**Real-world incidents:**
- 2013: Cisco OSPF vulnerability allowed unauthenticated route injection
- Enterprise networks with weak OSPF keys compromised in APT campaigns
- ISP routing attacks leveraging OSPF misconfigurations

---

### Secure Configuration

**Cisco IOS:**
```
interface GigabitEthernet0/0
 ip ospf message-digest-key 1 md5 [strong-random-password]
 ip ospf authentication message-digest

router ospf 1
 area 0 authentication message-digest
```

**Juniper JunOS:**
```
set protocols ospf area 0.0.0.0 interface ge-0/0/0.0 authentication md5 1 key [password]
```

**Best Practices:**
1. **Use strong, random passwords** (≥16 characters, mixed case, symbols)
2. **Rotate keys regularly** (every 90 days minimum)
3. **Deploy IPsec** for OSPF packets (RFC 4552)
4. **Monitor OSPF events** (new neighbors, route changes)
5. **Consider migrating to OSPFv3** with IPsec AH/ESP
6. **Network segmentation**: Isolate routing domains
7. **Implement BFD** (Bidirectional Forwarding Detection) for fast failure detection

---

## Key Takeaways

**Technical Skills:**
- Analyzed OSPF routing protocol packets
- Extracted MD5 authentication data from network capture
- Performed offline dictionary attack against cryptographic hash
- Used specialized tools (ospf_bruteforce.py, Wireshark)

**Security Concepts:**
- Routing protocol authentication prevents unauthorized route injection
- MD5 hashes extracted from captures can be brute-forced offline
- Weak passwords in network protocols enable man-in-the-middle attacks
- Defense-in-depth: combine authentication + encryption (IPsec)

---

## References

- [RFC 2328 - OSPF Version 2](https://datatracker.ietf.org/doc/html/rfc2328)
- [RFC 2154 - OSPF with Digital Signatures](https://datatracker.ietf.org/doc/html/rfc2154)
- [CWE-916: Use of Password Hash With Insufficient Computational Effort](https://cwe.mitre.org/data/definitions/916.html)
- [Cisco: OSPF MD5 Authentication](https://www.cisco.com/c/en/us/support/docs/ip/open-shortest-path-first-ospf/13697-25.html)