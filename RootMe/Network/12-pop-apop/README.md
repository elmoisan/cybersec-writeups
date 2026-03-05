# POP - APOP

`Network` • `Easy` • `15 pts`

## TL;DR

Extract APOP authentication data from POP3 network capture and crack MD5 hash using dictionary attack.

**Flag:** `[REDACTED]`

---

## Challenge Description

> Retrieve the user's password from the network capture.

---

## Recon

**APOP (Authenticated Post Office Protocol)** is a secure authentication mechanism for POP3 that prevents password transmission in plaintext.

**Authentication Flow:**
1. **Server** sends greeting with unique timestamp: `+OK <timestamp@server>`
2. **Client** calculates: `MD5(timestamp + password)`
3. **Client** sends: `APOP username md5_hash`

**Vulnerability:** The MD5 hash can be cracked offline with a dictionary attack if the timestamp is known.

---

## Exploitation

### Step 1: Analyze PCAP in Wireshark
```bash
wireshark ch23.pcapng
```

**Apply filter:** `pop`

**Key packets identified:**
- **Packet 29**: Server greeting with timestamp
- **Packet 264**: Client APOP authentication

---

### Step 2: Extract Authentication Data

**Packet 29 (Server greeting):**
```
+OK Hello little hackers. <1755.1.5f403625.BcWGgpKzUPRC8vscWn0wuA==@vps-7e2f5a72>
```

**Timestamp:** `<1755.1.5f403625.BcWGgpKzUPRC8vscWn0wuA==@vps-7e2f5a72>`

**Packet 264 (Client APOP command):**
```
APOP bsmith 4ddd4137b84ff2db7291b568289717f0
```

**Extracted data:**
- **Username:** `bsmith`
- **MD5 Hash:** `4ddd4137b84ff2db7291b568289717f0`

---

### Step 3: Crack APOP Hash

**Python script (`apop_crack.py`):**
```python
#!/usr/bin/env python3
import hashlib

timestamp = "<1755.1.5f403625.BcWGgpKzUPRC8vscWn0wuA==@vps-7e2f5a72>"
target_hash = "4ddd4137b84ff2db7291b568289717f0"

with open("rockyou.txt", 'r', encoding='latin-1', errors='ignore') as f:
    for i, password in enumerate(f):
        password = password.strip()
        
        # APOP: MD5(timestamp + password)
        apop_string = timestamp + password
        md5_hash = hashlib.md5(apop_string.encode()).hexdigest()
        
        if md5_hash == target_hash:
            print(f"PASSWORD FOUND: {password}")
            break
        
        if i % 10000 == 0:
            print(f"Tried {i} passwords...", end='\r')
```

**Execution:**
```bash
$ python3 apop_crack.py rockyou.txt
[*] Timestamp: <1755.1.5f403625.BcWGgpKzUPRC8vscWn0wuA==@vps-7e2f5a72>
[*] Target hash: 4ddd4137b84ff2db7291b568289717f0
    Tried 13470000 passwords...

[+] PASSWORD FOUND: 100%popprincess

[*] Username: bsmith
[*] Password: [REDACTED]
```

---

## Impact & Mitigation

### Real-World Implications

| Vulnerability | Impact |
|---------------|--------|
| **CWE-916** | Use of Password Hash With Insufficient Computational Effort |
| **RFC 1939** | APOP uses MD5 (cryptographically broken since 2004) |
| **MITRE ATT&CK T1110.002** | Password cracking |

**Attack Scenarios:**
1. **Email account compromise**: Access user's emails, contacts, calendar
2. **Credential reuse**: Users often reuse passwords across services
3. **Lateral movement**: Email access can lead to password resets for other accounts
4. **Data exfiltration**: Download entire mailbox contents

**Why APOP is vulnerable:**
- MD5 is cryptographically broken (collision attacks, rainbow tables)
- Timestamp provides known plaintext for dictionary attacks
- No salting or key derivation function (KDF)
- Single MD5 iteration (fast to bruteforce)

---

### Secure Alternatives

| Protocol | Port | Security | Status |
|----------|------|----------|--------|
| **POP3S** | 995 | TLS encryption | ✅ Recommended |
| **IMAP** | 143 | STARTTLS support | ✅ Modern standard |
| **IMAPS** | 993 | TLS encryption | ✅ Recommended |
| **APOP** | 110 | MD5 challenge-response | ❌ Deprecated (RFC 1939) |

**Best Practices:**
1. **Disable APOP**: Use TLS-encrypted POP3S/IMAPS instead
2. **Enforce strong passwords**: Minimum 16 characters, high entropy
3. **Implement rate limiting**: Prevent bruteforce attacks
4. **Use OAuth 2.0**: Modern authentication for email (Gmail, Outlook)
5. **Multi-factor authentication (MFA)**: Add second factor for email access
6. **Monitor failed login attempts**: Alert on suspicious authentication patterns

---

## Key Takeaways

**Technical Skills:**
- Analyzed POP3 protocol authentication flow
- Extracted APOP challenge-response data from network capture
- Performed offline MD5 hash cracking with dictionary attack
- Understood timestamp-based authentication mechanisms

**Security Concepts:**
- Challenge-response authentication prevents replay attacks but not offline cracking
- MD5 is cryptographically broken and should not be used for authentication
- Network captures expose authentication material for offline attacks
- Modern protocols use TLS encryption + strong password hashing (bcrypt, Argon2)

---

## References

- [RFC 1939 - Post Office Protocol - Version 3](https://datatracker.ietf.org/doc/html/rfc1939)
- [CWE-916: Use of Password Hash With Insufficient Computational Effort](https://cwe.mitre.org/data/definitions/916.html)
- [OWASP: Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [RFC 2195 - IMAP/POP AUTHorize Extension for Simple Challenge/Response (CRAM-MD5)](https://datatracker.ietf.org/doc/html/rfc2195)