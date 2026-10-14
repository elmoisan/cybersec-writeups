# Hash - DCC

`Windows` • `Password Cracking` • `5 pts`

## TL;DR

Parse the output of Impacket's `secretsdump`, distinguish the **DCC1 (mscash)** entry from the **DCC2 (mscash2)** entries by format, and run an offline dictionary attack with hashcat to recover the Administrator password.

**Password:** `ilikethat`

---

## Challenge Description

> Recover the password of the Administrator user from the output produced by Impacket's `secretsdump` tool.

**File:** `ch50.txt`

**Context:** The file is a raw `secretsdump.py` dump containing four distinct sections: local SAM hashes, cached domain logon information (DCC), LSA secrets (`$MACHINE.ACC`, `DPAPI_SYSTEM`, `NL$KM`), and a service account's plaintext password (`_SC_sshd`). The challenge only asks for one specific value: the Administrator password hidden in the cached-credentials section.

---

## Recon

**Step 1: Read the dump section by section**

```text
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
```

The SAM hashes are all the empty-password placeholder (`aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0`), so they're a dead end. The LSA secrets section ($MACHINE.ACC, DPAPI, NL$KM) is machine/domain key material, not a user password, and is also a dead end for this question. That leaves the cached logon information:

```text
ROOTME.LOCAL/PODALIRIUS:$DCC2$10240#PODALIRIUS#9d3e8dbe4d9816fa1a5dda431ef2f6f1
ROOTME.LOCAL/SHUTDOWN:$DCC2$10240#SHUTDOWN#9d3e8dbe4d9816fa1a5dda431ef2f6f1
ROOTME.LOCAL/Administrator:15a57c279ebdfea574ad1ff91eb6ef0c:Administrator
```

**Step 2: Know the two cached-credential formats**

| Format | Example | Notes |
|---|---|---|
| **DCC2 (mscash2)** | `$DCC2$10240#user#hash` | Explicit `$DCC2$` prefix, includes the PBKDF2 iteration count (10240) |
| **DCC1 (mscash, v1)** | `hash:username` | No `$DCC2$` prefix — a single MD4-based iteration, the older/weaker format |

**Observation:** the `Administrator` line doesn't start with `$DCC2$`; it's a bare `hash:username` pair, i.e. **DCC1**. The two `$DCC2$...` lines (PODALIRIUS, SHUTDOWN) are a red herring for this specific question — they're the stronger format and not what's needed here.

**Hypothesis:** the Administrator DCC1 hash is weak enough to be dictionary-crackable directly.

---

## Exploitation

### Step 1: Extract the target hash

```bash
echo '15a57c279ebdfea574ad1ff91eb6ef0c:Administrator' > dcc1.txt
```

### Step 2: Crack it with hashcat (mode 1100 = DCC1/MS Cache)

```bash
hashcat -m 1100 -a 0 dcc1.txt /usr/share/wordlists/rockyou.txt
```

```text
15a57c279ebdfea574ad1ff91eb6ef0c:administrator:ilikethat

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1100 (Domain Cached Credentials (DCC), MS Cache)
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
```

### Step 3: Confirm

```bash
$ hashcat -m 1100 dcc1.txt --show
15a57c279ebdfea574ad1ff91eb6ef0c:administrator:ilikethat
```

`rockyou.txt` alone was enough — the hash cracked in under a second, within the first ~150K candidates.

---

## Impact & Mitigation

### Real-World Implications

| Weakness | Impact |
|----------|--------|
| **CWE-521** | Weak Password Requirements (password present in a common wordlist) |
| **CWE-916** | Use of Password Hash With Insufficient Computational Effort (DCC1 is a single MD4 round, far weaker than DCC2's PBKDF2-style iteration) |
| **CWE-522** | Insufficiently Protected Credentials (cached domain credentials recoverable by any process/tool with local admin access, e.g. `secretsdump`) |

**Attack Scenarios:**
1. **Offline cracking of cached credentials**: any attacker with local admin/SYSTEM on a domain-joined box can dump the SAM and cached logon data, then crack weak passwords offline with no lockout policy
2. **Privilege escalation / lateral movement**: cached Administrator credentials, once cracked, often grant access well beyond the single machine they were cached on
3. **Legacy downgrade risk**: coexistence of DCC1 and DCC2 entries on the same system suggests legacy accounts or an older caching policy that never got remediated

**Why this matters:**
- Cached domain credentials exist specifically so a laptop can authenticate a user when the domain controller is unreachable — a convenience feature that also creates an offline-crackable artifact on every domain-joined endpoint
- DCC1 vs DCC2 is a visible, easy-to-spot format difference; recognizing it immediately tells you which hash is the weaker, more attractive target
- As with SNMP's "repeat to 1 MB" KDF, the strength of the scheme (even DCC2's iterated hashing) is meaningless against a short, dictionary-listed password

---

### Secure Practices

**❌ NEVER rely on this (short, dictionary-guessable account password):**

```text
Administrator password = "ilikethat"
```

**✅ DO this instead:**

**Option 1: Enforce long, random passwords for privileged accounts**
```text
Administrator password = "Xk9$mQ2vL#pR7zN4wT"
```

**Option 2: Disable or limit cached logon counts where not needed**
```text
# Group Policy: Interactive logon: Number of previous logons to cache
CachedLogonsCount = 0   # or a low value, on hardened/high-value hosts
```

**Option 3: Rotate and monitor privileged credentials after any dump exposure**
```text
# Any secretsdump / LSASS access event on a DC or admin workstation
# should trigger an immediate credential rotation for affected accounts
```

**Best Practices:**
1. **Use strong, unique passwords for Administrator and service accounts** — these are exactly the accounts attackers target first
2. **Limit `CachedLogonsCount`** on endpoints to reduce the offline-crackable attack surface
3. **Restrict and monitor access to SAM/LSASS/registry hives** that `secretsdump`-style tools rely on
4. **Prefer DCC2 over DCC1 wherever supported** — it's not a silver bullet, but it raises the cracking cost significantly
5. **Treat a credential dump as a full compromise event**: rotate every password it could have exposed, not just the one that was cracked first

---

## Key Takeaways

**Technical Skills:**
- Parsed a full `secretsdump.py` output and identified which section actually answers the question, ignoring SAM/LSA noise
- Distinguished DCC1 (`hash:username`) from DCC2 (`$DCC2$iterations#user#hash`) purely by format
- Used the correct hashcat mode (1100) for DCC1/MS Cache and ran a straightforward dictionary attack

**Windows/AD Concepts:**
- Cached domain credentials (DCC) let a domain-joined machine validate a logon without contacting a DC — a resilience feature that doubles as an offline attack target
- DCC1 and DCC2 are two generations of the same idea, with meaningfully different cracking costs
- A credential dump exposes far more than one hash; triage by format and context before spending compute on the wrong target

---

## References

- [Impacket - secretsdump.py](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py)
- [hashcat - Domain Cached Credentials (DCC), MS Cache (mode 1100)](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [hashcat - Domain Cached Credentials 2 (DCC2), MS Cache 2 (mode 2100)](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [CWE-521: Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html)
- [CWE-916: Use of Password Hash With Insufficient Computational Effort](https://cwe.mitre.org/data/definitions/916.html)
- [CWE-522: Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html)
