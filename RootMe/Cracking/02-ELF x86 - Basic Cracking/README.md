# ELF x86 - Basic Cracking

`Cracking` • `Very Easy` • `5 pts`

## TL;DR

Two hardcoded credentials (`john` / `the ripper`) gate access to the real validation password (`[REDACTED]`), which is what Root-Me expects as the flag. The binary is statically linked, making `strings` noisy — filtering and disassembly are required.

**Flag:** `[REDACTED]`

---

## Challenge Description

> Find the password to validate this challenge.

**File:** `ch2.bin`

**Context:** Another cracking challenge, still compiled with GCC32 on x86. Slightly harder than ch1 because the binary is statically linked and requires two-step credential validation.

---

## Recon

### Step 1 — Identify the file type

```bash
$ file ch2.bin
ch2.bin: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV),
         statically linked, for GNU/Linux 2.6.8,
         with debug_info, not stripped
```

**Key differences from ch1:**
- **Statically linked** → the entire libc is embedded in the binary → `strings` produces thousands of lines of noise
- **Not stripped** → function names are still present (helpful for disassembly)
- **With debug_info** → source-level debug symbols included

---

### Step 2 — Filter `strings` output

Running plain `strings` produces too much output. Filtering on relevant keywords:

```bash
$ strings ch2.bin | grep -E "john|ripper|pass|user|Bad|joue"
john
the ripper
username:
password:
[REDACTED]
Bad password
Bad username
Bien joue, vous pouvez valider l'epreuve avec le mot de passe : %s !
```

**Observations:**
- Two suspicious strings: `john` and `the ripper` → likely username/password
- `[REDACTED]` appears near the success message → the **validation flag** printed on success
- The program asks for both a username and a password
- `[REDACTED]` is printed via `%s` — it is the flag to submit, **not** the login password

> ⚠️ **Trap:** `[REDACTED]` is visible in `strings` output but it is the *output* flag, not the input password. You must supply `john` / `the ripper` to reach it.

---

## Exploitation

### Step 3 — Confirm with disassembly

```bash
$ objdump -d ch2.bin | grep -A 60 "<main>"
```

Relevant excerpt — two sequential `strcmp` calls:

```asm
; --- USERNAME CHECK ---
movl  $0x80a6b19, -0xc(%ebp)    ; address of "john"
movl  $0x80a6b1e, -0x10(%ebp)   ; address of "the ripper"

call  getString                   ; read username input
call  strcmp                      ; compare with "john"
test  %eax, %eax
jne   → "Bad username"            ; wrong username → fail

; --- PASSWORD CHECK ---
call  getString                   ; read password input
call  strcmp                      ; compare with "the ripper"
test  %eax, %eax
jne   → "Bad password"            ; wrong password → fail

; --- SUCCESS ---
movl  $0x80a6c00, 0x4(%esp)      ; address of "[REDACTED]"
movl  $0x80a6c0c, (%esp)         ; address of success format string
call  printf                      ; print "Bien joue ... [REDACTED]"
```

### Step 4 — Extract all key strings by address

```python
with open('ch2.bin', 'rb') as f:
    data = f.read()

base = 0x8048000
addrs = {
    'username':     0x80a6b19,
    'password':     0x80a6b1e,
    'flag':         0x80a6c00,
    'success_msg':  0x80a6c0c,
}
for label, addr in addrs.items():
    offset = addr - base
    end = data.index(b'\x00', offset)
    print(f'{label}: {data[offset:end].decode()}')
```

Output:
```
username:     john
password:     the ripper
flag:         [REDACTED]
success_msg:  Bien joue, vous pouvez valider l'epreuve avec le mot de passe : %s !
```

**Credentials to enter:** `john` / `the ripper`
**Flag to submit on Root-Me:** `[REDACTED]` ✅

---

## Key Difference from ch1

| | ch1 | ch2 |
|---|---|---|
| Linking | Dynamic | **Static** (libc embedded) |
| Credentials | Password only | **Username + Password** |
| Flag | Input password | **Separate output string** |
| `strings` noise | Low | **High — must filter** |
| Checks | 1× `strcmp` | **2× `strcmp`** |

The main new challenge here is understanding that the **flag is not what you type in**, but what the program prints on success.

---

## Impact & Mitigation

### Real-World Implications

| Vulnerability | Impact |
|---------------|--------|
| **CWE-259** | Use of Hard-coded Password |
| **CWE-312** | Cleartext Storage of Sensitive Information |
| **CWE-798** | Use of Hard-coded Credentials |

**Why two hardcoded credentials is still broken:**
- Both the username and password are stored in plaintext in `.rodata`
- A static binary does not add security — all data is still extractable with `strings` + filtering
- The "flag" string is also stored in plaintext and trivially found

---

### Secure Implementation

**❌ NEVER do this:**
```c
// Both credentials AND the secret stored in plaintext
char *username = "john";
char *password = "the ripper";
char *secret   = "[REDACTED]";

if (strcmp(input_user, username) == 0 &&
    strcmp(input_pass, password) == 0) {
    printf("Flag: %s\n", secret);  // All three visible in strings output
}
```

**✅ DO this instead:**
```c
// Hash credentials server-side, never store plaintext
// Never ship secrets inside a local binary
// Use proper authentication (OAuth, JWT, bcrypt hashing)
```

**Best Practices:**
1. **Never store credentials in a binary** — use server-side authentication
2. **Filter `strings` output** when analyzing real binaries — grep for keywords
3. **Distinguish input from output** — the flag is what the program *prints*, not what you *type*
4. **Static linking ≠ more secure** — it just adds more noise to analysis

---

## Methodology

```
1. file        → statically linked, not stripped
2. strings + grep → find: john, the ripper, [REDACTED], Bad username/password
3. objdump -d  → locate two strcmp calls and the success printf
4. python      → extract strings at hardcoded addresses to confirm
5. Understand  → credentials = john/the ripper | flag = [REDACTED]
```

---

## Key Takeaways

**Technical Skills:**
- Handled high `strings` noise from a statically linked binary using `grep` filtering
- Read a two-step authentication flow in x86 assembly
- Distinguished between *input* credentials and *output* flag
- Extracted multiple strings at specific addresses using Python

**Security Concepts:**
- Static linking embeds the entire libc but does not protect the binary's own data
- Multiple hardcoded checks do not add meaningful security
- Always look for what the program *prints on success*, not just what it *compares against*
- `strings` output should always be grepped — raw output is rarely useful on real binaries

---

## References

- [The GNU Binary Utils](https://www.gnu.org/software/binutils/)
- [Executable and Linkable Format (ELF)](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format)
- [Reverse Engineering for Beginners - Dennis Yurichev](https://beginners.re/)
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [CWE-259: Use of Hard-coded Password](https://cwe.mitre.org/data/definitions/259.html)

