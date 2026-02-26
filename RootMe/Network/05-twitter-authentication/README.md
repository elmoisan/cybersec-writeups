# Twitter - Authentication

`Network` • `Very Easy` • `15 pts`

## TL;DR

Clear-text HTTP Basic Auth credential extraction from PCAP. Password transmitted in plaintext (Base64-encoded, not encrypted) during Twitter API authentication.

**Flag:** `[REDACTED]`

---

## Challenge Description

> Une session d'authentification twitter a été capturée. Retrouvez le mot de passe de l'utilisateur dans cette capture réseau.
> *(A Twitter authentication session was captured. Find the user's password in this network capture.)*

**Given:** `ch3.pcap` (network capture file)

---

## Recon

**Protocol identification:**
```bash
$ tshark -r ch3.pcap -z "io,phs" | grep -i http
# HTTP traffic on port 80 — unencrypted
```

The capture contains a plain **HTTP** request to `twitter.com` (port 80). Twitter's old API used **HTTP Basic Authentication**, which encodes credentials in Base64 — providing zero encryption or confidentiality.

---

## Exploitation

### Method 1: Wireshark GUI

1. Open capture: `wireshark ch3.pcap`
2. Apply display filter: `http`
3. Inspect Packet 1 → Hypertext Transfer Protocol → Authorization

**Observations in the packet:**
- Request: `GET /statuses/replies.xml HTTP/1.1`
- Host: `twitter.com`
- Authorization header: `Basic dXNlcnRlc3Q6cGFzc3dvcmQ=`
- **Wireshark auto-decodes:** `Credentials: usertest:password`

Wireshark natively decodes HTTP Basic Auth credentials directly in the packet detail pane — no extra steps needed.

### Method 2: Manual Base64 Decoding

Extract and decode the Authorization header manually:

```bash
$ echo "dXNlcnRlc3Q6cGFzc3dvcmQ=" | base64 -d
usertest:`[REDACTED]`
```

Format is always `username:password` encoded in Base64.

### Method 3: CLI Extraction with tshark

```bash
$ tshark -r ch3.pcap -Y "http.authorization" -T fields -e http.authorization
Basic dXNlcnRlc3Q6cGFzc3dvcmQ=

$ tshark -r ch3.pcap -Y "http.authbasic" -T fields -e http.authbasic
usertest:`[REDACTED]`
```

Or with `strings`:
```bash
$ strings ch3.pcap | grep "Authorization"
Authorization: Basic dXNlcnRlc3Q6cGFzc3dvcmQ=
```

---

## Why Base64 ≠ Encryption

HTTP Basic Auth is a common misconception:

| Property     | Base64        | Encryption     |
|--------------|---------------|----------------|
| **Purpose**  | Encoding       | Confidentiality |
| **Reversible** | Trivially (no key) | Only with key |
| **Protection** | None         | Strong (if TLS) |
| **Example**  | `dXNlcnRlc3Q6cGFzc3dvcmQ=` | `(ciphertext)` |

Base64 is purely an **encoding scheme** — anyone intercepting the traffic can decode the credentials instantly.

---

## Impact & Mitigation

### Real-World Implications

| Vulnerability | Impact |
|---------------|--------|
| **CWE-319** | Cleartext Transmission of Sensitive Information |
| **CWE-522** | Insufficiently Protected Credentials |
| **MITRE ATT&CK T1040** | Network Sniffing |
| **Risk** | Any network position (MITM, rogue AP, Wi-Fi sniffing) fully exposes credentials |

**Historical Context:** This capture is from 2010. Twitter's early API used HTTP Basic Auth over plain HTTP — a well-known security issue at the time. Twitter deprecated Basic Auth in favor of **OAuth 1.0a** in August 2010, shortly after this capture was made.

### Secure Alternatives

| Method | Protocol | Protection | Status |
|--------|----------|------------|--------|
| **OAuth 2.0** | HTTPS | Token-based, no password transmission | ✅ Current standard |
| **OAuth 1.0a** | HTTPS | Signed requests, no password transmission | ✅ Replaced Basic Auth |
| **Basic Auth over HTTPS** | HTTPS | TLS encrypts the Base64 in transit | ⚠️ Acceptable only with TLS |
| Basic Auth over HTTP | HTTP | None — credentials exposed | ❌ Deprecated |

**Remediation:**
1. Never transmit credentials over plain HTTP — enforce HTTPS
2. Use token-based authentication (OAuth, API keys) instead of passwords
3. Enable HSTS (HTTP Strict Transport Security) to prevent downgrade attacks
4. Monitor network traffic for unauthorized credential exposure

---

## Key Takeaways

**Technical Skills:**
- Identified HTTP Basic Authentication in a PCAP
- Decoded Base64-encoded credentials manually and with tooling
- Used both Wireshark GUI and `tshark` CLI for credential extraction

**Security Concepts:**
- Base64 is encoding, not encryption — it offers zero security
- HTTP (unencrypted) exposes all headers including Authorization
- Legacy APIs often used insecure authentication schemes that are trivial to exploit passively

---

## References

- [RFC 7617 - HTTP Basic Authentication Scheme](https://datatracker.ietf.org/doc/html/rfc7617)
- [RFC 6749 - OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749)
- [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
- [CWE-522: Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html)
- [MITRE ATT&CK T1040: Network Sniffing](https://attack.mitre.org/techniques/T1040/)
- [Twitter API Basic Auth deprecation (2010)](https://developer.twitter.com/en/docs/authentication/oauth-1-0a)