# TELNET - Authentication

`Network` • `Very Easy` • `5 pts`

## TL;DR

Clear-text TELNET credential extraction from PCAP. Password transmitted in plaintext during login sequence.

**Flag:** `user`

---

## Challenge Description

> Retrieve the user's password in this TELNET session network capture.

**Given:** `ch2.pcap` (network capture file)

---

## Recon

**Protocol identification:**
```bash
$ tshark -r ch2.pcap -z "io,phs" | grep -i telnet
# TELNET traffic on port 23
```

TELNET operates on **port 23** and transmits all data (including credentials) in clear text with character-by-character echo.

---

## Exploitation

### Method 1: Wireshark GUI

1. Open capture: `wireshark ch2.pcap`
2. Apply display filter: `telnet`
3. Follow TCP stream (right-click → Follow → TCP Stream)

**Observations:**
- Login prompt: `login:`
- Username appears doubled: `ffaakkee` (each character echoed by server)
- Password prompt: `Password:`
- Password visible: `user`
- Successful authentication: `Last login: Thu Dec 2 21:32:59`

**Why doubled characters?** TELNET echoes each keystroke back to the client for display. The stream shows both the client's input and server's echo.

### Method 2: CLI Extraction
```bash
$ tshark -r ch2.pcap -Y "telnet" -T fields -e telnet.data | xxd -r -p | strings
login:
fake
Password:
user
```

Or directly with `strings`:
```bash
$ strings ch2.pcap | grep -A2 "Password"
Password:
user
Last login
```

---

## Impact & Mitigation

### Real-World Implications

| Vulnerability | Impact |
|---------------|--------|
| **CWE-319** | Cleartext Transmission of Sensitive Information |
| **MITRE ATT&CK T1040** | Network Sniffing |
| **Risk** | Any network position (MITM, rogue AP, compromised switch) exposes credentials |

**Historical Context:** TELNET predates modern security practices (RFC 854, 1983). Still found on legacy systems and IoT devices.

### Secure Alternatives

| Protocol | Port   | Encryption        | Status                  |
|----------|--------|-------------------|-------------------------|
| **SSH**  | 22     | Yes (RSA/Ed25519) |  Industry standard      |
| **Mosh** | 60000+ | Yes (AES-128)     |  Mobile-optimized SSH   |
| TELNET   | 23     | No                |  Deprecated             |

**Remediation:**
1. Disable TELNET on all production systems
2. Replace with SSH (key-based authentication preferred)
3. Network segmentation: isolate legacy TELNET devices if removal impossible

---

## Key Takeaways

**Technical Skills:**
- Analyzed TELNET protocol structure (character-by-character transmission)
- Distinguished between client input and server echo in TCP stream
- Applied multiple extraction techniques (GUI + CLI)

**Security Concepts:**
- Clear-text protocols expose credentials to passive network monitoring
- Legacy protocols remain in production environments (IoT, network equipment)
- Protocol understanding is essential for forensics and penetration testing

---

## References

- [RFC 854 - TELNET Protocol Specification](https://datatracker.ietf.org/doc/html/rfc854)
- [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
- [MITRE ATT&CK T1040: Network Sniffing](https://attack.mitre.org/techniques/T1040/)
- [NIST: Deprecated/Disallowed Functions](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-175Br1.pdf) (Section on TELNET)