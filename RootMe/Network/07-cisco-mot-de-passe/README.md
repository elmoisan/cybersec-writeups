# CISCO - Mot de passe

`Network` • `Easy` • `15 pts`

## TL;DR

Cisco IOS configuration file analysis. Decode Type 7 "encrypted" passwords (trivial XOR) to identify the password pattern, then crack the Enable Secret (Type 5 / MD5-crypt) using the pattern as a wordlist hint.

**Flag:** `[REDACTED]`

---

## Challenge Description

> Trouvez le mot de passe "Enable".
> *(Find the "Enable" password.)*

**Hint:** *"Tous les hash n'en sont pas."* — Not all hashes are actually hashes.

**Given:** `ch15.txt` (Cisco IOS running configuration)

---

## Recon

### Configuration Overview

The file is a **Cisco IOS router config** (`hostname rmt-paris`, IOS 12.2) containing several password entries:

```
enable secret 5 $1$p8Y6$MCdRLBzuGlfOs9S.hXOp0.

username hub   password 7 025017705B3907344E
username admin password 7 10181A325528130F010D24
username guest password 7 124F163C42340B112F3830

line con 0
 password 7 144101205C3B29242A3B3C3927
```

### Cisco Password Types

| Type | Name | Algorithm | Reversible? | Security |
|------|------|-----------|-------------|----------|
| **0** | Plaintext | None | ✅ Trivially | ❌ None |
| **7** | Vigenère | XOR with fixed key | ✅ Trivially | ❌ None |
| **5** | Enable Secret | MD5-crypt (`$1$`) | ❌ No | ⚠️ Weak (MD5) |
| **8** | PBKDF2-SHA256 | PBKDF2 | ❌ No | ✅ Strong |
| **9** | scrypt | scrypt | ❌ No | ✅ Strong |

The hint *"Tous les hash n'en sont pas"* directly refers to **Type 7**: it looks like a hash but is merely an encoding — fully reversible with a publicly known key.

---

## Exploitation

### Step 1: Decode Type 7 passwords

Cisco Type 7 uses a fixed 26-byte XOR key hardcoded in IOS since the 1990s:

```
dsfd;kfoA,.iyewrkldJKDHSUB
```

The first 2 digits of the encoded string are the **seed** (starting offset into the key). The rest are hex-encoded XOR'd bytes.

```python
def cisco_type7_decode(encoded):
    xlat = [0x64, 0x73, 0x66, 0x64, 0x3b, 0x6b, 0x66, 0x6f,
            0x41, 0x2c, 0x2e, 0x69, 0x79, 0x65, 0x77, 0x72,
            0x6b, 0x6c, 0x64, 0x4a, 0x4b, 0x44, 0x48, 0x53,
            0x55, 0x42]
    seed    = int(encoded[:2])
    encoded = encoded[2:]
    decoded = ''
    for i in range(0, len(encoded), 2):
        byte = int(encoded[i:i+2], 16)
        decoded += chr(byte ^ xlat[(seed + i//2) % 26])
    return decoded

passwords = {
    "hub":     "025017705B3907344E",
    "admin":   "10181A325528130F010D24",
    "guest":   "124F163C42340B112F3830",
    "con 0":   "144101205C3B29242A3B3C3927",
}

for user, enc in passwords.items():
    print(f"{user:10s}: {cisco_type7_decode(enc)}")
```

**Output:**

| Username | Encoded (Type 7) | Decoded |
|----------|-----------------|---------|
| `hub` | `025017705B3907344E` | `6sK0_hub` |
| `admin` | `10181A325528130F010D24` | `6sK0_admin` |
| `guest` | `124F163C42340B112F3830` | `6sK0_guest` |
| `con 0` | `144101205C3B29242A3B3C3927` | `6sK0_console` |

### Step 2: Identify the password pattern

All Type 7 passwords follow the same pattern: `6sK0_<role>`. The admin follows this naming convention, so the Enable password is almost certainly `6sK0_enable`.

### Step 3: Crack the Enable Secret (Type 5)

The enable secret uses **MD5-crypt** (Unix `$1$` format):

```
$1$p8Y6$MCdRLBzuGlfOs9S.hXOp0.
 ↑  ↑↑↑↑  ↑
 │  salt   hash
 └─ algorithm: MD5-crypt
```

Verify the candidate with Python:

```python
import crypt

hash_str = "$1$p8Y6$MCdRLBzuGlfOs9S.hXOp0."
candidate = "6sK0_enable"

if crypt.crypt(candidate, hash_str) == hash_str:
    print(f"Password found: {candidate}")
# → Password found: 6sK0_enable
```

Or with hashcat:

```bash
echo '$1$p8Y6$MCdRLBzuGlfOs9S.hXOp0.' > hash.txt
hashcat -m 500 hash.txt -a 3 "6sK0_?l?l?l?l?l?l?l"
# Or simply:
hashcat -m 500 hash.txt wordlist.txt
```

**Flag:** `6sK0_enable`

---

## Impact & Mitigation

### Real-World Implications

| Vulnerability | Impact |
|---------------|--------|
| **CWE-261** | Weak Encoding for Password | Type 7 provides zero confidentiality |
| **CWE-916** | Use of Password Hash With Insufficient Computational Effort | MD5-crypt (Type 5) is fast to brute-force |
| **MITRE ATT&CK T1552.001** | Credentials in Files | Config backups expose all credentials |
| **Risk** | Full router compromise if config file is leaked (backup server, TFTP, Git, etc.) |

A leaked Cisco config is a **critical** finding in a pentest — it typically yields all credentials in seconds.

### Secure Configuration Recommendations

| Recommendation | Details |
|----------------|---------|
| **Never use Type 7** | Replace all `password 7` entries with Type 8 or 9 |
| **Use `enable secret` Type 9** | `algorithm-type scrypt secret <password>` |
| **Enable `service password-encryption`** | Minimum baseline — but only upgrades Type 0 → Type 7 |
| **Restrict config access** | Limit TFTP/SCP backup destinations, use ACLs |
| **Rotate credentials** | Any leaked config = full credential rotation required |

**Secure IOS password config:**
```
! Use scrypt (Type 9) for enable secret
enable algorithm-type scrypt secret <strong_password>

! Use Type 8 or 9 for local users
username admin algorithm-type sha256 secret <strong_password>

! Never use:
! username X password 7 ...   ← reversible
! enable password ...          ← plaintext or Type 7
```

---

## Key Takeaways

**Technical Skills:**
- Identified and decoded Cisco IOS Type 7 passwords using the known XOR key
- Recognized the MD5-crypt (`$1$`) format of the Enable Secret (Type 5)
- Leveraged password pattern analysis to crack the hash without a full wordlist

**Security Concepts:**
- Type 7 is **encoding**, not encryption — the key is public, built into IOS, and cannot be changed
- `service password-encryption` only applies Type 7 — it creates a false sense of security
- Password patterns across accounts (same prefix + role suffix) allow trivial targeted cracking
- Config files must be treated as **highly sensitive** — they contain all device credentials

---

## References

- [Cisco IOS Password Encryption Facts](https://www.cisco.com/c/en/us/support/docs/security-vpn/remote-authentication-dial-user-service-radius/107614-64.html)
- [Cisco Type 7 Password Decoder (online)](https://www.ifm.net.nz/cookbooks/passwordcracker.html)
- [CWE-261: Weak Encoding for Password](https://cwe.mitre.org/data/definitions/261.html)
- [CWE-916: Insufficient Computational Effort in Password Hash](https://cwe.mitre.org/data/definitions/916.html)
- [MITRE ATT&CK T1552.001: Credentials in Files](https://attack.mitre.org/techniques/T1552/001/)
- [Cisco: Protecting Passwords in IOS](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/d1/sec-d1-cr-book/sec-cr-e1.html)