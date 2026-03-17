# ELF x86 - 0 Protection

`Cracking` • `Very Easy` • `5 pts`

## TL;DR

The password is stored in plaintext inside the binary. Extracting it with `strings` is enough.

**Flag:** `[REDACTED]`

---

## Challenge Description

> Find the password to validate this challenge.

**File:** `ch1.bin`

**Context:** First cracking challenge, written in C with vi and compiled with GCC32. The name "0 protection" hints that no obfuscation or anti-reversing technique is in place.

---

## Recon

### Step 1 — Identify the file type

```bash
$ file ch1.bin
ch1.bin: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV),
         dynamically linked, interpreter /lib/ld-linux.so.2,
         for GNU/Linux 2.6.9, not stripped
```

**Key observations:**
- 32-bit ELF binary (Linux executable)
- **Not stripped** → symbol names (functions, variables) are still present
- Dynamically linked → uses standard libc functions

---

### Step 2 — Extract readable strings

```bash
$ strings ch1.bin
...
strcmp
123456789
Veuillez entrer le mot de passe :
Bien joue, vous pouvez valider l'epreuve avec le pass : %s!
Dommage, essaye encore une fois.
...
```

**Findings:**
- `strcmp` is imported → the program compares two strings
- `123456789` is the only string that looks like a password
- The success message uses `%s` → it prints the password back, confirming it is stored as a string

---

## Exploitation

### Step 3 — Confirm with disassembly

```bash
$ objdump -d ch1.bin | grep -A 30 "<main>"
```

Relevant excerpt:
```asm
movl  $0x8048841, -0x8(%ebp)   ; load address of hardcoded password
call  getString                  ; read user input
call  strcmp                     ; compare input with password
test  %eax, %eax                 ; strcmp returns 0 if equal
jne   <fail>                     ; jump to "Dommage" if not equal
; else → print success + password
```

Extracting the string at address `0x8048841` (file offset `0x841`):

```python
with open('ch1.bin', 'rb') as f:
    data = f.read()
offset = 0x841
end = data.index(b'\x00', offset)
print(data[offset:end].decode())  # → 123456789
```

✅ **Password confirmed: `[REDACTED]`**

---

## Why It Works

The binary stores the password **in plaintext** in its `.rodata` (read-only data) section. There is:
- ❌ No encryption
- ❌ No obfuscation
- ❌ No hash comparison
- ❌ No anti-debug protection

The `strcmp` call directly compares the user input against the raw string `123456789` sitting in memory.

---

## Impact & Mitigation

### Real-World Implications

| Vulnerability | Impact |
|---------------|--------|
| **CWE-259** | Use of Hard-coded Password |
| **CWE-312** | Cleartext Storage of Sensitive Information |

**Attack Scenarios:**
1. **License bypass**: Commercial software storing serial keys in plaintext can be cracked in seconds
2. **Firmware analysis**: Embedded devices often store default credentials in their firmware image
3. **Mobile apps**: APKs and IPAs frequently expose API keys and passwords via `strings`
4. **CTF / malware analysis**: First step in any binary analysis is always `strings`

---

### Secure Implementation

**❌ NEVER do this (vulnerable code):**
```c
// C - INSECURE: hardcoded plaintext password
char *password = "123456789";
if (strcmp(input, password) == 0) {
    printf("Access granted!\n");
}
```

**✅ DO this instead:**

**Option 1 — Hash comparison (never store plaintext):**
```c
// C - MORE SECURE: compare against a hash
#include <openssl/sha.h>

// Store only the SHA-256 hash of the password
unsigned char expected_hash[32] = { 0x15, 0xe2, /* ... */ };

unsigned char input_hash[32];
SHA256((unsigned char*)input, strlen(input), input_hash);

if (memcmp(input_hash, expected_hash, 32) == 0) {
    printf("Access granted!\n");
}
```

**Option 2 — Server-side authentication:**
```c
// Never validate credentials locally in a client binary.
// Send credentials to a server over TLS and validate there.
// The secret never lives in the binary.
```

**Best Practices:**
1. **Never hardcode passwords** in a binary — they are trivially extractable with `strings`
2. **Use server-side validation** — the client should never hold the ground truth
3. **Hash + salt** passwords if local comparison is unavoidable
4. **Strip binaries** in production (`strip binary`) — reduces information leakage (though not a security measure on its own)
5. **Use obfuscation as a speed bump**, not a solution — it raises the bar but does not prevent reverse engineering

---

## Methodology Summary

For any cracking challenge, always start with these steps in order:

| Step | Tool | Purpose |
|------|------|---------|
| 1 | `file` | Identify architecture, format, and whether stripped |
| 2 | `strings` | Look for plaintext passwords, flags, URLs |
| 3 | `objdump -d` / `ghidra` / `radare2` | Disassemble and understand the logic |
| 4 | `ltrace` | Trace library calls (e.g., `strcmp`) at runtime |
| 5 | `strace` | Trace syscalls at runtime |
| 6 | `gdb` | Dynamic analysis — set breakpoints, inspect registers |

> 💡 **Rule of thumb:** Always run `strings` first. On "0 protection" binaries, it often gives you the answer immediately.

---

## Key Takeaways

**Technical Skills:**
- Used `file` to identify a 32-bit ELF binary
- Used `strings` to extract the plaintext password in seconds
- Confirmed with `objdump -d` by locating the `strcmp` call and the hardcoded address
- Extracted the string at a specific file offset using Python

**Security Concepts:**
- Anything stored in a binary is readable by an attacker — **no secrets in binaries**
- `strcmp` against a hardcoded string is the most basic (and broken) authentication pattern
- "Not stripped" binaries leak function names, making analysis significantly easier
- The `.rodata` section stores string literals — always a prime target in reverse engineering

---

## References

- [The GNU Binary Utils](https://www.gnu.org/software/binutils/)
- [Executable and Linkable Format (ELF)](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format)
- [Reverse Engineering for Beginners - Dennis Yurichev](https://beginners.re/)
- [CWE-259: Use of Hard-coded Password](https://cwe.mitre.org/data/definitions/259.html)
- [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
