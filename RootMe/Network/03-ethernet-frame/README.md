# ETHERNET - Frame

`Network` • `Easy` • `10 pts`

## TL;DR

Extract HTTP Basic Authentication credentials from raw Ethernet frame hexdump. Base64 decode the Authorization header to retrieve credentials.

**Flag:** `[REDACTED]`

---

## Challenge Description

> Retrieve the confidential data contained in this frame.

**Given:** `ch12.txt` (hexadecimal dump of an Ethernet frame)

---

## Recon

**File inspection:**
```bash
$ head -3 ch12.txt
00 05 73 a0 00 00 e0 69 95 d8 5a 13 86 dd 60 00
00 00 00 9b 06 40 26 07 53 00 00 60 2a bc 00 00
00 00 00 00 ba de c0 de 20 01 41 d0 00 02 42 33
```

This is a complete Ethernet frame in hexadecimal format, including:
- Ethernet header (Layer 2)
- IPv6 header (Layer 3) — indicated by `86 dd`
- TCP header (Layer 4)
- HTTP payload (Layer 7)

**Target:** Extract HTTP Basic Authentication credentials from the application layer.

---

## Exploitation

### Method 1: Hex to ASCII Conversion
```bash
$ cat ch12.txt | xxd -r -p | strings
GET / HTTP/1.1
Authorization: Basic [BASE64_CREDENTIALS]
User-Agent: InsaneBrowser
Host: www.myipv6.org
Accept: */*
```

### Method 2: Manual Extraction

**Locate Authorization header in hex:**
```
41 75 74 68 6f 72 69 7a 61 74 69 6f 6e 3a 20 42 61 73 69 63 20
[HEX_ENCODED_BASE64_CREDENTIALS]
```

**Convert to ASCII:**
- First line: `Authorization: Basic `
- Second line: `[BASE64_CREDENTIALS]`

### Method 3: Wireshark (Alternative)
```bash
$ text2pcap -o hex ch12.txt frame.pcap
$ wireshark frame.pcap
# Filter: http
# Right-click → Follow → HTTP Stream
```

---

## Decoding HTTP Basic Auth

**Base64 decode:**
```bash
$ echo "[BASE64_CREDENTIALS]" | base64 -d
[USERNAME]:[PASSWORD]
```

**Format:** `username:password`
- Username: `[USERNAME]`
- Password: `[PASSWORD]`

---

## Impact & Mitigation

### Real-World Implications

| Vulnerability | Impact |
|---------------|--------|
| **CWE-326** | Inadequate Encryption Strength |
| **RFC 7617** | HTTP Basic Auth over unencrypted channels |
| **Risk** | Credentials exposed to any network observer |

**HTTP Basic Authentication flaws:**
1. **Base64 is encoding, not encryption** — trivially reversible
2. No protection against replay attacks
3. Credentials sent with **every request**

### Secure Alternatives

| Method | Security | Use Case |
|--------|----------|----------|
| **OAuth 2.0** | ✅ Token-based, time-limited | Modern web APIs |
| **JWT** | ✅ Signed tokens, stateless | Microservices |
| **Digest Auth** | ⚠️ Better than Basic, still weak | Legacy systems |
| **mTLS** | ✅ Certificate-based | High-security environments |

**Mitigation:**
1. **Always use HTTPS** with Basic Auth (minimum requirement)
2. Prefer token-based authentication (OAuth 2.0, JWT)
3. Implement rate limiting and account lockout
4. Use API keys with proper rotation policies

---

## Key Takeaways

**Technical Skills:**
- Analyzed raw Ethernet frames (hex → ASCII → decode)
- Understood OSI layer structure (L2 → L7)
- Identified IPv6 traffic (EtherType `86dd`)
- Decoded Base64-encoded credentials

**Security Concepts:**
- HTTP Basic Auth is fundamentally insecure over HTTP
- Base64 encoding ≠ encryption (common misconception)
- Network layer analysis reveals application-layer secrets
- Defense-in-depth: encrypt transport layer (TLS) even with weak auth

---

## References

- [RFC 7617 - HTTP Basic Authentication](https://datatracker.ietf.org/doc/html/rfc7617)
- [CWE-326: Inadequate Encryption Strength](https://cwe.mitre.org/data/definitions/326.html)
- [OWASP: Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [Wireshark Display Filters](https://wiki.wireshark.org/DisplayFilters)