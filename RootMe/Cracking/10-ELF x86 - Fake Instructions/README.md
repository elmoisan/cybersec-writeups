# ELF x86 - Fake Instructions

`Reverse Engineering` • `Easy` • `15 pts`

---

## TL;DR

An x86 ELF crackme that builds an expected password **at runtime** by patching
a heap-allocated buffer in several passes. Six of the 22 password bytes are
`0x0d`, `0x0a`, `0xc3`, `0x87`, `0xc3`, `0x80` — bytes that look like x86
machine code (`ret`, `xchg`, `ret`, partial instruction), hence "Fake
Instructions". Tracing the six mutations applied to the buffer recovers the
exact byte sequence.

**Flag:** `liberté!`
The binary prints it on success: `sh 3.0 # password: liberté!`
The argv trigger is a 22-byte raw sequence; the *submitted* flag is `liberté!`.

---

## Challenge Description

> Il peut être aisément cracké si l'on prend le temps de l'analyser et de
> réfléchir sans pour autant aller chercher trop loin.

The provided archive contains `crackme`, a 32-bit ELF that takes a password as
`argv[1]` and prints a success or failure message.

---

## Recon

### File identification

```bash
$ file crackme
crackme: ELF 32-bit LSB executable, Intel 80386, dynamically linked,
         with debug_info, not stripped

$ nm crackme | grep "^[0-9a-f]* T"
08048821 T AES
08048803 T RS4
080486c4 T WPA
0804872c T blowfish
08048554 T main
```

The function names (`WPA`, `blowfish`, `RS4`, `AES`) are deliberate red
herrings — none of them implement any cryptographic algorithm. This is the
"Fake" theme carried throughout the binary.

### Quick strings scan

```bash
$ strings crackme
_0cGj35m9V5T3          ← raw seed (in .rodata, before runtime patches)
8CJ0
9H95h3xdh
_Celebration
(*) -Syntaxe: %s [password]
sh 3.0 # password: %s  ← printed on success
```

The seed `_0cGj35m9V5T3` looks like the password, but several bytes are
replaced at runtime before `strcmp` is called.

---

## Static Analysis

### Program flow (`main`)

```
main
  ├─ argc != 2 → print usage, exit
  ├─ malloc(29)                          ; allocate expected-password buffer
  ├─ memcpy(buf, "_0cGj35m9V5T3Ç8CJ0À9H95h3xdh", 31) ; seed
  ├─ buf[5]  = 'c'   (0x63)             ; patch 1 — '3' → 'c'
  ├─ buf[22] = 0x00                      ; patch 2 — null terminator
  ├─ function_ptr = WPA                  ; indirect call setup
  ├─ strcpy(local_buf, argv[1])          ; copy user input
  ├─ buf[8]  = '_'   (0x5f)             ; patch 3 — '9' → '_'
  ├─ buf[9]  = '.'   (0x2e)             ; patch 4 — 'V' → '.'
  └─ call function_ptr(local_buf, buf)  → WPA(user_input, buf)

WPA
  ├─ buf[11] = 0x0d  ('\r')             ; patch 5 — 'T' → '\r'
  ├─ buf[12] = 0x0a  ('\n')             ; patch 6 — '3' → '\n'
  ├─ puts("Vérification de votre mot de passe..")
  ├─ strcmp(user_input, buf) == 0 ?
  │   ├─ YES → blowfish()  → success, print "sh 3.0 # password: liberté!"
  │   └─ NO  → RS4()       → print hint, exit(0)
```

### The six buffer mutations

Starting from the 31-byte seed at `0x8048910`:

```
Offset  Original  After   Meaning
  [5]    0x33 '3'  0x63 'c'   plain char patch (main)
  [8]    0x39 '9'  0x5f '_'   plain char patch (main)
  [9]    0x56 'V'  0x2e '.'   plain char patch (main)
 [11]    0x54 'T'  0x0d '\r'  "fake instruction" — CR byte (WPA)
 [12]    0x33 '3'  0x0a '\n'  "fake instruction" — LF byte (WPA)
 [22]    0x48 'H'  0x00       null terminator (main)
```

The bytes `0x0d`, `0x0a`, `0xc3` (×2), `0x87`, `0x80` embedded in positions
11–21 look like x86 opcodes (`0xc3` = `ret`, `0x87 0x38` = `xchg`, …) if you
try to disassemble the buffer as code — these are the **fake instructions**.

### Reconstructing the password in Python

```python
buf = bytearray(b'_0cGj35m9V5T3\xc3\x878CJ0\xc3\x809H95h3xdh\x00')

# Six runtime mutations
buf[5]  = 0x63  # 'c'
buf[22] = 0x00  # null terminator
buf[8]  = 0x5f  # '_'
buf[9]  = 0x2e  # '.'
buf[11] = 0x0d  # '\r'
buf[12] = 0x0a  # '\n'

password = bytes(buf[:buf.index(0)])
print(password.hex())
# 5f3063476a63356d5f2e350d0ac38738434a30c38039
```

---

## Exploitation

Because the password contains non-printable and non-ASCII bytes it cannot be
typed directly in a shell. Passing it requires Python subprocess or a `$'...'`
bash literal:

```python
import subprocess

pw = bytes.fromhex('5f3063476a63356d5f2e350d0ac38738434a30c38039')
result = subprocess.run(['./crackme', pw], capture_output=False)
```

```
Vérification de votre mot de passe..
'+) Authentification réussie...
 U'r root!

 sh 3.0 # password: liberté!
```

---

## Why does this work?

The binary deliberately confuses static analysis at two levels:

**1 — Misleading function names.** `WPA`, `blowfish`, `RS4`, `AES` imply
crypto but implement none. The real logic is a plain `strcmp`.

**2 — Fake instruction bytes in the password.** The expected buffer is never
stored as a complete string in `.rodata`. Instead, the seed contains bytes
`0xc3 0x87` and `0xc3 0x80` in the middle (valid UTF-8 for `Ç` and `À`, but
also matching x86 `ret` / `xchg` opcodes). Two more non-printable bytes
(`0x0d`, `0x0a`) are injected at runtime by `WPA`. Any tool that tries to
disassemble or pretty-print the buffer will be confused by these "fake
instructions" embedded in what is actually a data string.

**3 — Incremental patching via indirect call.** The buffer is never complete
until the very last moment (`WPA` adds the final two bytes before `strcmp`),
making it harder to spot in a memory snapshot.

```
Password bytes breakdown:
  5f 30 63 47 6a 63 35 6d  → _0cGjc5m  (printable)
  5f 2e 35                  → _.5       (printable)
  0d 0a                     → \r\n      ← fake instructions / non-printable
  c3 87 38 43 4a 30         → Ç8CJ0     (c3 87 = x86 ret+xchg / UTF-8 Ç)
  c3 80 39                  → À9        (c3 80 = x86 ret / UTF-8 À)
```

---

## Key Takeaways

- **"Fake Instructions"** = non-printable and x86-opcode bytes embedded inside
  a data string, not inside executable code. The trick misleads the analyst,
  not the CPU.
- **Incremental buffer construction**: the expected value is assembled across
  multiple functions (`main` → `WPA`). Follow every write to the heap buffer.
- **Indirect `call *%edx`** with a `function_ptr` global: don't assume the
  called function is obvious from static analysis — check what value is stored
  in the pointer.
- **Non-printable bytes in passwords**: `strcmp` compares raw bytes; `\r`,
  `\n`, and high-bit characters are valid in C strings. Use `subprocess` or
  shell `$'...'` syntax to pass them as `argv`.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `file` / `nm` | Identify ELF, list symbols |
| `strings` | Spot the raw seed in `.rodata` |
| `objdump -d` | Disassemble `main`, `WPA`, `blowfish`, `RS4` |
| Python | Reconstruct buffer mutations and compute exact password bytes |
| `LD_PRELOAD` hook | Intercept `strcmp` to confirm expected bytes at runtime |
| `subprocess.run` | Pass raw byte password as `argv[1]` |

---

## References

- [x86 opcode 0xC3 — `ret` instruction](https://www.felixcloutier.com/x86/ret)
- [Anti-disassembly techniques — OpenSecurityTraining](https://opensecuritytraining.info)
- [ELF-32 ABI](https://refspecs.linuxbase.org/elf/elf.pdf)
- [Root-Me — ELF x86 - Fake Instructions](https://www.root-me.org/en/Challenges/Cracking/ELF32-Fake-Instructions)