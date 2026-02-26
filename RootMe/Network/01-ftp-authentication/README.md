# FTP - Authentication

`Network` • `Very Easy` • `5 pts`

## TL;DR

Clear-text FTP credentials extraction from PCAP file. Username and password transmitted in plaintext during authentication sequence.

**Flag:** `[REDACTED]`

---

## Challenge Description

> An authenticated FTP file transfer was captured. Retrieve the password used by the user.

**Given:** `ch1.pcap` (network capture file)

---

## Recon

**File inspection:**
```bash
$ file ch1.pcap
ch1.pcap: pcap capture file, microsecond ts (little-endian)

$ tcpdump -r ch1.pcap -n | head
reading from file ch1.pcap, link-type EN10MB (Ethernet)
# Multiple TCP streams on port 21 (FTP control channel)
```

**Protocol identification:** FTP operates on two channels:
- **Port 21** (control): commands and responses
- **Port 20** (data): actual file transfer

Authentication happens over the control channel in clear text.

---

## Exploitation

### Method 1: Wireshark GUI (Visual Analysis)

1. Open capture: `wireshark ch1.pcap`
2. Apply display filter: `ftp`
3. Follow TCP stream (right-click packet → Follow → TCP Stream)

**Result:**
```
220-QTCP at fran.csg.stercomm.com.
USER [USERNAME]
331 Enter password.
PASS [PASSWORD]
230 [USERNAME] logged on.
```

### Method 2: CLI (Automated)

```bash
$ strings ch1.pcap | grep -E "^(USER|PASS)"
USER [USERNAME]
PASS [PASSWORD]
```

Or with `tshark`:
```bash
$ tshark -r ch1.pcap -Y "ftp.request.command" -T fields -e ftp.request.command -e ftp.request.arg
USER    [USERNAME]
PASS    [PASSWORD]
```

---

## Impact & Mitigation

### Real-World Implications
- **CWE-319**: Cleartext Transmission of Sensitive Information
- **MITRE ATT&CK T1040**: Network Sniffing
- Passive network monitoring (e.g., ARP poisoning, rogue WiFi) exposes all FTP credentials

### Secure Alternatives
| Protocol | Port | Encryption | Notes                                  |
|----------|------|------------|----------------------------------------|
| **FTPS** | 990  | TLS/SSL    | FTP over TLS (explicit/implicit)       |
| **SFTP** | 22   | SSH        | Preferred: encrypted + key-based auth  |
| **SCP**  | 22   | SSH        | Secure copy, simple file transfer      |

**Remediation:** Disable FTP on production systems. Use SFTP with key-based authentication.

---

## Key Takeaways

**Technical Skills:**
- Analyzed network traffic with Wireshark and tshark
- Understood FTP protocol structure (control vs data channels)
- Applied protocol-specific filters for targeted analysis

**Security Concepts:**
- Clear-text protocols remain exploitable in modern networks
- Passive network sniffing requires no authentication
- Defense-in-depth: encrypt transport layer (TLS/SSH) even on "trusted" networks

---

## References

- [RFC 959 - File Transfer Protocol](https://datatracker.ietf.org/doc/html/rfc959)
- [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
- [MITRE ATT&CK T1040: Network Sniffing](https://attack.mitre.org/techniques/T1040/)
- [OWASP: Insecure Transport](https://owasp.org/www-community/vulnerabilities/Insecure_Transport)