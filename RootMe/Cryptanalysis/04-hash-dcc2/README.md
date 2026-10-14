# Hash - DCC2

Windows • Password Cracking • 5 pts

## TL;DR

Parse the output of Impacket's `secretsdump`, identify the Administrator entry as a **DCC2 (mscash2)** hash, and run an offline dictionary attack with hashcat's PBKDF2-backed mode to recover the password.

**Password:** `ihatepasswords`

---

## Challenge Description

> Recover the password of the Administrator user from the output produced by Impacket's `secretsdump` tool.

**File:** `ch51.txt`

**Context:** Same `secretsdump.py` dump structure as the previous DCC challenge — local SAM hashes, cached domain logon information, LSA secrets, and a service account's plaintext password. This time, however, the Administrator cached-credential entry is in a different format from before.

---

## Recon

**Step 1: Locate the cached logon section**

```text
ROOTME.LOCAL/PODALIRIUS:$DCC2$10240#PODALIRIUS#9d3e8dbe4d9816fa1a5dda431ef2f6f1
ROOTME.LOCAL/SHUTDOWN:$DCC2$10240#SHUTDOWN#9d3e8dbe4d9816fa1a5dda431ef2f6f1
ROOTME.LOCAL/Administrator:$DCC2$10240#Administrator#23d97555681813db79b2ade4b4a6ff25
```

As with the previous challenge, the SAM hashes are all the empty-password placeholder and the LSA secrets are machine/domain key material — both dead ends for this question.

**Step 2: Confirm the format**

Unlike the earlier DCC challenge, the `Administrator` line here *does* start with `$DCC2$`, so it's already in the **DCC2 (mscash2)** format — no need to distinguish it from a bare `hash:username` DCC1 entry this time:

```text
$DCC2$10240#Administrator#23d97555681813db79b2ade4b4a6ff25
```

The `10240` is the PBKDF2-style iteration count baked into the hash itself, which is what makes DCC2 significantly more expensive to attack than DCC1.

**Hypothesis:** even with the added cost per guess, a weak/dictionary password will still fall to rockyou.

---

## Exploitation

### Step 1: Extract the target hash

hashcat accepts the `$DCC2$iterations#username#hash` string directly, no reformatting needed:

```bash
echo '$DCC2$10240#Administrator#23d97555681813db79b2ade4b4a6ff25' > dcc2.txt
```

### Step 2: Crack it with hashcat (mode 2100 = DCC2/MS Cache 2)

```bash
hashcat -m 2100 -a 0 dcc2.txt /usr/share/wordlists/rockyou.txt
```

```text
$DCC2$10240#administrator#23d97555681813db79b2ade4b4a6ff25:ihatepasswords

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 2100 (Domain Cached Credentials 2 (DCC2), MS Cache 2)
Speed.#1.........:    25092 H/s (8.04ms) @ Accel:512 Loops:512 Thr:1 Vec:16
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
```

### Step 3: Confirm

```bash
$ hashcat -m 2100 dcc2.txt --show
$DCC2$10240#administrator#23d97555681813db79b2ade4b4a6ff25:ihatepasswords
```

Cracked in ~6 seconds despite only reaching ~25 kH/s — roughly 170x slower than the DCC1 challenge's 4.3 MH/s, a direct, measurable consequence of DCC2's 10,240-iteration key stretching. The password was still weak enough to be in the first 150K candidates of rockyou.

---

## Impact & Mitigation

### Real-World Implications

| Weakness | Impact |
|----------|--------|
| **CWE-521** | Weak Password Requirements (password present in a common wordlist, despite the stronger hash) |
| **CWE-522** | Insufficiently Protected Credentials (cached domain credentials recoverable by any process/tool with local admin access, e.g. `secretsdump`) |
| **CWE-319** | Cleartext Transmission/Storage of Sensitive Information (username and iteration count are visible in plaintext alongside the digest) |

**Attack Scenarios:**
1. **Offline cracking, just slower**: DCC2's PBKDF2-style stretching raises the cost per guess by roughly two orders of magnitude versus DCC1, but it only *slows down* cracking — it doesn't stop it against a dictionary-listed password
2. **Cost-asymmetry still favors attackers for weak passwords**: at 25 kH/s, rockyou's 14M entries are exhaustible in minutes on a single CPU; a determined attacker with GPUs would be far faster still
3. **Same privilege-escalation path as DCC1**: a cracked Administrator password from cached credentials remains high-value regardless of which hash generation protected it

**Why this matters:**
- DCC2 is a genuine security improvement over DCC1 (iterated key derivation instead of one MD4 round), and that improvement is visible directly in the attack: ~170x slower per guess
- That improvement is still only a multiplier on attacker cost, not a ceiling — a password policy that allows dictionary words is defeated either way, just on a different timescale
- Comparing this challenge to the DCC1 one is a good illustration of why hash *strength* and password *strength* are separate, additive defenses: you need both

---

### Secure Practices

**❌ NEVER rely on this (short, dictionary-guessable account password):**

```text
Administrator password = "ihatepasswords"
```

**✅ DO this instead:**

**Option 1: Enforce long, random passwords for privileged accounts**
```text
Administrator password = "Rn4$vK8wXq#2TpL9mZ"
```

**Option 2: Limit or disable cached logons on high-value hosts**
```text
# Group Policy: Interactive logon: Number of previous logons to cache
CachedLogonsCount = 0   # or a low value, on hardened/high-value hosts
```

**Option 3: Treat a confirmed credential dump as a full compromise event**
```text
# Any secretsdump / LSASS access event on a DC or admin workstation
# should trigger immediate rotation of every exposed credential
```

**Best Practices:**
1. **Password strength matters more than hash strength** once an attacker has the hash — DCC2's extra cost buys time, not safety, against a weak password
2. **Use strong, unique passwords for Administrator and service accounts**, the accounts attackers target first
3. **Limit `CachedLogonsCount`** to reduce the offline-crackable attack surface on endpoints
4. **Restrict and monitor access to SAM/LSASS/registry hives** that `secretsdump`-style tools rely on
5. **Rotate credentials after any dump exposure**, regardless of which DCC generation protected them

---

## Key Takeaways

**Technical Skills:**
- Recognized the `$DCC2$iterations#username#hash` format directly and fed it to hashcat without reformatting
- Used the correct hashcat mode (2100) for DCC2/MS Cache 2
- Observed and interpreted the real-world cost difference between DCC1 and DCC2 via hashcat's reported speed (4.3 MH/s vs 25 kH/s)

**Windows/AD Concepts:**
- DCC2 replaces DCC1's single MD4 pass with an iterated, PBKDF2-style derivation (10,240 rounds here), making each guess markedly more expensive
- The iteration count is stored alongside the hash in plaintext, so an attacker always knows exactly how expensive each guess will be — it's a visible cost parameter, not a secret
- A stronger KDF raises the bar but doesn't remove the need for a strong password: the two defenses are complementary, not substitutes for each other

---

## References

- [Impacket - secretsdump.py](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py)
- [hashcat - Domain Cached Credentials 2 (DCC2), MS Cache 2 (mode 2100)](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [hashcat - Domain Cached Credentials (DCC), MS Cache (mode 1100)](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [CWE-521: Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html)
- [CWE-522: Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html)
- [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
