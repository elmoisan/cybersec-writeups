# SNMP - Authentification

`Network` • `Protocol Cracking` • `35 pts`

## TL;DR

Dissect a captured SNMPv3 exchange, extract the USM security parameters (engine ID, username, HMAC-MD5 digest) from the raw BER-encoded PDUs, and run an offline dictionary attack: for each candidate password, derive the RFC 3414 localized key, recompute the HMAC-MD5-96 signature over the message, and compare it to the captured one.

**Password:** `REDACTED`

---

## Challenge Description

> Recover the password used to authenticate the SNMP exchange in the network capture.

**File:** `ch16.pcap`

**Context:** The capture (pcapng, 6 frames) shows an SNMPv3 `authNoPriv` session between `192.168.1.237` and `192.168.1.207`: a discovery exchange with no security, followed by two authenticated `GetNextRequest` / `Response` pairs for user `user`. Five resources are attached to the challenge: a paper on MD5 collisions, a dictionary (`rootmedict.txt`), and RFC 3414 / 2574 / 2571 (the SNMPv3 security and architecture RFCs).

---

## Recon

**Step 1: Identify the protocol**

The pcap holds only 6 UDP/161 packets. Reading the raw bytes with Scapy confirms SNMPv3 traffic:

```text
0  Ether / IP / UDP 192.168.1.237:36235 > 192.168.1.207:snmp
1  Ether / IP / UDP 192.168.1.207:snmp  > 192.168.1.237:36235
2  Ether / IP / UDP 192.168.1.237:36235 > 192.168.1.207:snmp
3  Ether / IP / UDP 192.168.1.207:snmp  > 192.168.1.237:36235
4  Ether / IP / UDP 192.168.1.237:36235 > 192.168.1.207:snmp
5  Ether / IP / UDP 192.168.1.207:snmp  > 192.168.1.237:36235
```

**Step 2: Know the SNMPv3 message layout**

SNMPv3 (RFC 3412/3414) wraps every PDU in a fixed structure:

| Field | Meaning |
|-------|---------|
| `msgVersion` | `3` for SNMPv3 |
| `msgGlobalData` | message ID, max size, **msgFlags** (auth/priv/reportable), security model |
| `msgSecurityParameters` | USM block: authoritative engine ID, engine boots/time, **username**, **authentication digest**, privacy parameters |
| `msgData` | the scoped PDU (plaintext here, since `msgFlags = 0x05` means authNoPriv, no encryption) |

**Observations:**
- Packets 0-1 are the **discovery exchange**: empty username, zero engine boots/time, and the server's `Report` reveals the real `msgAuthoritativeEngineID`
- Packets 2-5 are two **authenticated request/response pairs**, both using username `user` and carrying a 12-byte authentication digest (HMAC-MD5-96)
- `msgFlags = 0x05` (`101`₂: reportable + auth, no priv) confirms **authNoPriv**: the username, engine ID and PDU content are all in cleartext, only the digest is secret-dependent

**Hypothesis:** The engine ID and username are known in plaintext; only the password behind the digest is unknown. This is a classic offline dictionary attack on USM authentication.

---

## Exploitation

### Step 1: Extract the USM fields

A script (`parse_snmpv3.py`) BER-decodes each UDP payload and prints the fields:

```bash
$ python3 parse_snmpv3.py ch16.pcap
```

| | Packet 2 | Packet 3 | Packet 4 | Packet 5 |
|---|---|---|---|---|
| Direction | request | response | request | response |
| Username | `user` | `user` | `user` | `user`|
| Engine ID | `80001f8880e9bd0c1d12667a5100000000` | same | same | same |
| Engine boots / time | `5` / `32` | `5` / `32` | `5` / `32` | `5` / `32` |
| Auth digest | `b92621f4a93d1bf9738cd5bd` | `09445f87770f575221331c7c` | `cfdc4525f88882a4ac0a366a` | `70d7880b4f31cc4d19a07dcd` |

Four digests, all produced with the same key, give four independent checks: a correct password reproduces every one of them.

---

### Step 2: Understand how the digest is computed (RFC 3414)

HMAC-MD5-96 authentication derives its key from the password in two steps:

**a) Password → key (`Ku`)**

The password is repeated to fill exactly **1,048,576 bytes** (1 MB), and that buffer is hashed with MD5:

```text
Ku = MD5( password repeated to 1 MB )
```

**b) Localization (`Kul`)**

The key is bound to the specific SNMP engine so it can't be replayed against another agent:

```text
Kul = MD5( Ku || engineID || Ku )
```

**c) Signing the message**

The 12-byte `msgAuthenticationParameters` field is zeroed out, HMAC-MD5 is computed over the *entire* message with `Kul`, and the first 12 bytes of the result become the digest that replaces the zeroed field.

```text
digest = HMAC-MD5(Kul, message_with_zeroed_authParams)[:12]
```

I validated this implementation against the official RFC 3414 Appendix A test vector (`password = "maplesyrup"`, `engineID = 000000000000000000000002`) before trusting it on the real capture.

---

### Step 3: Dictionary attack

For each candidate password `pw` in `rootmedict.txt`:

```python
Ku  = MD5(pw repeated to 1 MB)
Kul = MD5(Ku + engine_id + Ku)
candidate_digest = HMAC-MD5(Kul, zeroed_message)[:12]
if candidate_digest == captured_digest:
    found!
```

Each candidate costs one MD5 pass over 1 MB of data (the expensive, intentional part of the RFC 3414 design — it slows down brute-forcing), so the attack is run in parallel across CPU cores:

```bash
$ python3 crack_snmpv3.py ch16.pcap rootmedict.txt
FOUND: REDACTED
```

Checked against all four captured digests, the password `REDACTED` reproduces every one of them, confirming the match.

---

## Impact & Mitigation

### Real-World Implications

| Weakness | Impact |
|----------|--------|
| **CWE-262 / CWE-263** | Not Using / Not Expiring Password Hash Algorithm (weak, crackable password) |
| **CWE-319** | Cleartext Transmission of Sensitive Information (username and engine ID visible even with authNoPriv) |
| **CWE-521** | Weak Password Requirements |

**Attack Scenarios:**
1. **Offline dictionary/brute-force cracking**: `authNoPriv` still leaks the username and a password-derived digest for every message; an attacker only needs one authenticated exchange to start cracking offline, with no rate limiting from the device
2. **Credential reuse**: a cracked SNMP password is often reused for device administration (web UI, SSH, Telnet)
3. **Full device takeover with `authPriv`**: the same localized key material also derives the privacy (encryption) key, so cracking the password can expose encrypted SNMP traffic too
4. **MD5 weaknesses**: MD5 is broken for collision resistance; while that's not directly exploited here, RFC 3414 recommends HMAC-SHA over HMAC-MD5 for new deployments

**Why this matters:**
- SNMPv3's "repeat to 1 MB" KDF is a deliberate slow-hash design, but it is still only as strong as the password chosen
- A capture of normal, authorized monitoring traffic is enough to mount this attack — no active interaction with the device is required
- Device management protocols are frequently overlooked in password policy enforcement compared to user-facing logins

---

### Secure Practices

**❌ NEVER rely on this (short, dictionary-guessable SNMP passwords):**

```text
authKey = "4dm1n"   # 5 characters, in common wordlists
```

**✅ DO this instead:**

**Option 1: Use long, random authentication and privacy passphrases**
```text
# net-snmp example
net-snmp-create-v3-user -A 'S9$kP2!vL7m#Qw4xR' -a SHA -X 'T6&nJ0@fG3z^Yc8p' -X AES user
```

**Option 2: Prefer SHA over MD5 for the authentication protocol**
```text
usmHMACSHAAuthProtocol  instead of  usmHMACMD5AuthProtocol
```

**Option 3: Always use `authPriv`, never `authNoPriv`**
```text
snmpget -v3 -l authPriv -u user -a SHA -A '<strong-pass>' -x AES -X '<strong-pass>' host oid
```

**Best Practices:**
1. **Treat SNMPv3 passwords like any other credential**: long, random, unique, rotated
2. **Use `authPriv`** so the PDU payload is encrypted, not just authenticated
3. **Restrict SNMP to a management VLAN/ACL** so captures of this traffic require prior network access
4. **Monitor for repeated authentication failures**, which indicate an online guessing attempt
5. **Rotate credentials** after any capture or suspected exposure, since USM keys are derived deterministically from the password

---

## Key Takeaways

**Technical Skills:**
- Parsed SNMPv3's BER/ASN.1 structure by hand: `msgGlobalData`, `msgSecurityParameters` (USM), `scopedPDU`
- Identified the security level from `msgFlags` and located the authentication digest to attack
- Implemented and validated the RFC 3414 password-to-key and key-localization algorithms against the official test vector
- Ran an offline, parallelized dictionary attack reproducing the HMAC-MD5-96 computation exactly

**Network Concepts:**
- SNMPv3 USM (RFC 3414) separates **authentication** (integrity + origin) from **privacy** (confidentiality); `authNoPriv` only protects integrity
- The authoritative engine ID and username are never secret — they are needed by design for key localization and appear in cleartext
- Key derivation deliberately costs one MD5 pass over 1 MB per guess, trading attacker speed for legitimate-device overhead — but a weak password defeats this entirely
- A captured digest is a long-lived target: unlike an online login, it can be attacked offline indefinitely, at whatever speed the attacker can afford

---

## References

- [RFC 3414: User-based Security Model (USM) for SNMPv3](https://www.rfc-editor.org/rfc/rfc3414)
- [RFC 2574: User-based Security Model (USM) for SNMPv3 (obsoleted by 3414)](https://www.rfc-editor.org/rfc/rfc2574)
- [RFC 2571: An Architecture for SNMP Management Frameworks](https://www.rfc-editor.org/rfc/rfc2571)
- [RFC 3412: Message Processing and Dispatching for SNMP](https://www.rfc-editor.org/rfc/rfc3412)
- [CWE-521: Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html)
- [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
