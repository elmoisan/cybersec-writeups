# NTLM - Authentication

`Network` • `Easy` • `10 pts`

## TL;DR

Extract NTLMv2 hash from SMB authentication capture, crack with hashcat, and format credentials as flag.

**Flag:** `RM{[USERNAME]@[DOMAIN]:[PASSWORD]}`

---

## Challenge Description

> Retrieve the password of a user involved in a suspected NTLM over SMB connection.

**Flag format:** `RM{userPrincipalName:password}` (lowercase)

**Given:** `ntlm_auth.pcapng` (network capture file)

---

## Recon

**Protocol identification:**
```bash
$ tshark -r ntlm_auth.pcapng -z "io,phs" | grep -i ntlm
# NTLMSSP authentication over SMB2
```

NTLM operates in a **challenge-response** mechanism:
1. **NEGOTIATE** (client → server): capabilities negotiation
2. **CHALLENGE** (server → client): server sends random challenge
3. **AUTH** (client → server): client responds with encrypted hash

The NTLMv2 hash can be extracted from the AUTH packet and cracked offline.

---

## Exploitation

### Method 1: Wireshark Manual Extraction

**Step 1: Filter NTLMSSP packets**
```
Filter: ntlmssp
```

**Step 2: Extract Server Challenge (NTLMSSP_CHALLENGE packet)**
- Apply filter: `ntlmssp.messagetype == 0x00000002`
- Expand: `NTLM Secure Service Provider`
- Copy: **NTLM Server Challenge**: `[SERVER_CHALLENGE]`

**Step 3: Extract NTLMv2 Response (NTLMSSP_AUTH packet)**
- Apply filter: `ntlmssp.messagetype == 0x00000003`
- Expand: `NTLM Secure Service Provider`
- Note:
  - **User name**: `[USERNAME]`
  - **Domain name**: `[DOMAIN]`
  - **NTLMv2 Response**: `[NTLM_RESPONSE]...`

**Step 4: Format for hashcat**

NTLMv2 format (hashcat mode 5600):
```
username::domain:serverchallenge:ntproofstr:ntlmv2response
```

- **NTProofStr** = first 16 bytes (32 hex chars) of response
- **Blob** = remaining bytes

**Complete hash:**
```
[USERNAME]::[DOMAIN]:[SERVER_CHALLENGE]:[NTPROOF]:[BLOB]
```

### Method 2: tshark CLI Extraction
```bash
# Extract Server Challenge
tshark -r ntlm_auth.pcapng -Y "ntlmssp.messagetype == 0x00000002" -T fields -e ntlmssp.ntlmserverchallenge

# Extract AUTH components
tshark -r ntlm_auth.pcapng -Y "ntlmssp.messagetype == 0x00000003" -T fields -e ntlmssp.auth.username -e ntlmssp.auth.domain -e ntlmssp.ntlmv2_response
```

---

## Cracking

**With hashcat (mode 5600):**
```bash
hashcat -m 5600 ntlm_hash.txt rockyou.txt
```

**Result:**
```
[USERNAME]::[DOMAIN]:[SERVER_CHALLENGE]:[NTPROOF]..:[PASSWORD]
```

**Password:** `[REDACTED]`

---

## Impact & Mitigation

### Real-World Implications

| Vulnerability | Impact |
|---------------|--------|
| **CVE-2019-1040** | NTLM relay attacks bypass MIC |
| **CWE-916** | Use of Password Hash With Insufficient Computational Effort |
| **MITRE ATT&CK T1003.001** | Credential dumping via NTLM hashes |

**NTLM weaknesses:**
- Susceptible to **pass-the-hash** attacks (no password needed, just hash)
- **Relay attacks**: intercept and replay authentication
- **Offline cracking**: captured hashes can be brute-forced
- No mutual authentication (client can't verify server)

### Secure Alternatives

| Protocol | Security | Status |
|----------|----------|--------|
| **Kerberos** | ✅ Mutual auth, no password on wire | Windows default (AD) |
| **NTLM** | ❌ Hash-based, vulnerable | Legacy/fallback only |
| **Certificate-based auth** | ✅ PKI, no shared secrets | Enterprise recommended |

**Mitigation:**
1. **Disable NTLM** where possible (Group Policy: Network Security: Restrict NTLM)
2. Enforce **SMB signing** (prevents relay attacks)
3. Enable **Extended Protection for Authentication (EPA)**
4. Use **Kerberos** exclusively in Active Directory
5. Monitor for NTLM usage with Windows Event ID 4624 (Logon Type 3)

---

## Key Takeaways

**Technical Skills:**
- Extracted NTLMv2 challenge-response from SMB capture
- Understood NTLM 3-way handshake (Negotiate/Challenge/Auth)
- Formatted hash correctly for offline cracking tools
- Identified hash components (NTProofStr vs blob)

**Security Concepts:**
- Challenge-response protocols still vulnerable to offline attacks
- NTLM remains in Windows environments for legacy compatibility
- Pass-the-hash attacks bypass password requirement
- Network segmentation and SMB signing are critical defenses

---

## References

- [MS-NLMP: NT LAN Manager (NTLM) Authentication Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/)
- [CVE-2019-1040: NTLM Relay Attack Bypassing MIC](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-1040)
- [MITRE ATT&CK T1003.001: OS Credential Dumping - NTLM Hash](https://attack.mitre.org/techniques/T1003/001/)
- [Hashcat mode 5600: NetNTLMv2](https://hashcat.net/wiki/doku.php?id=example_hashes)