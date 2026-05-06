# ELF MIPS - Basic Crackme

`Reverse Engineering` • `Easy` • `15 pts`

## TL;DR

A 32-bit MIPS little-endian ELF crackme, stripped, with no obfuscation.
The password validation logic is a series of hardcoded single-byte comparisons
spread across the `.text` section. Static disassembly with Capstone is enough
to reconstruct every check and recover the password.

---

## Challenge Description

> Find the validation password.

The provided file `ch27.bin` is a 32-bit MIPS little-endian ELF executable,
dynamically linked against uClibc, and fully stripped (no debug symbols).
It reads a password from stdin and prints either `well done!` or `fail!`.

---

## Recon

### File identification

```bash
$ file ch27.bin
ch27.bin: ELF 32-bit LSB executable, MIPS, MIPS32 rel2 version 1 (SYSV),
          dynamically linked, interpreter /lib/ld-uClibc.so.0, stripped
```

Key details:

| Property | Value |
|----------|-------|
| Architecture | MIPS 32-bit little-endian |
| Linking | Dynamic (uClibc) |
| Symbols | Stripped |
| Analysis mode | Static only (not native x86) |

### Strings extraction

```bash
$ strings ch27.bin
well done!
fail!
crack-me for Root-me by s4r
Enter password please
```

The password itself is not stored as a plain string — it is checked
character by character against hardcoded immediate values. Disassembly is required.

### ELF layout

```
Entry point     : 0x400610
.text           : addr=0x400610  offset=0x610  size=0x5e0
.rodata         : addr=0x400cb0  offset=0xcb0  size=0x50
```

---

## Exploitation

### MIPS quick reference

| Register | Role |
|----------|------|
| `$a0`–`$a3` | Function arguments |
| `$v0`–`$v1` | Return values / temporaries |
| `$fp` | Frame pointer (base of local variables) |
| `$t9` + `jalr` | Dynamic function call |
| `$ra` | Return address |
|
> **Delay slot:** in MIPS, the instruction immediately after a branch/jump
> executes *before* the jump takes effect.

### Disassembly with Capstone

Since the binary targets MIPS and cannot be run on x86, Capstone is used
to disassemble the `.text` section statically:

```python
import capstone

with open('ch27.bin', 'rb') as f:
    data = f.read()

# .text: file offset 0x610, size 0x5e0, load address 0x400610
text = data[0x610:0x610 + 0x5e0]

md = capstone.Cs(capstone.CS_ARCH_MIPS,
                 capstone.CS_MODE_MIPS32 + capstone.CS_MODE_LITTLE_ENDIAN)
for insn in md.disasm(text, 0x400610):
    print(f'0x{insn.address:08x}:  {insn.mnemonic:10s} {insn.op_str}')
```

### Main function analysis (0x400868)

#### Step 1 — Print prompt and read input

```asm
addiu  $a0, $v0, 0xce0      ; "Enter password please"
jalr   $t9                   ; puts()

addiu  $a0, $fp, 0x1c        ; buffer at fp+0x1c
addiu  $a1, $zero, 0x40      ; max 64 bytes
jalr   $t9                   ; fgets(buffer, 64, stdin)
```

The input is stored at `$fp+0x1c` — this is the base address (offset 0) used
for all subsequent character checks.

#### Step 2 — Strip trailing newline and check length

```asm
jalr   $t9                   ; strlen(buffer) → $v0
addiu  $v1, $v0, -1
; buffer[strlen-1] = '\0'    ← overwrites the '\n' left by fgets

jalr   $t9                   ; strlen again → $v0
addiu  $v0, $zero, 0x13      ; 0x13 = 19
beq    $v1, $v0, 0x400960    ; length == 19 → continue
; else → "fail!"
```

**➜ The password must be exactly 19 characters long.**

#### Step 3 — Loop over indices 8–16

```asm
addiu  $v0, $zero, 8
sw     $v0, 0x18($fp)        ; index = 8

; loop while index < 0x11 (17)
lb     $v1, 4($v0)           ; buffer[index]
addiu  $v0, $zero, 0x69      ; 'i'
beq    $v1, $v0, next        ; buffer[index] == 'i' → ok
; else → fail
addiu  $v0, $v0, 1           ; index++
```

**➜ `buffer[8]` through `buffer[16]` must all equal `'i'` (0x69).**

#### Step 4 — Individual byte checks

```asm
lb    $v1, 0x2e($fp)         ; buffer[18]
addiu $v0, $zero, 0x73       ; 's'
beq   $v1, $v0, ...

lb    $v1, 0x2d($fp)         ; buffer[17]
addiu $v0, $zero, 0x70       ; 'p'
beq   $v1, $v0, ...

; ... (see full table below)
```

Full table of hardcoded comparisons:

| Offset | Hex | Char |
|--------|-----|------|
| `[0]`  | `0x63` | `c` |
| `[1]`  | `0x61` | `a` |
| `[2]`  | `0x6e` | `n` |
| `[3]`  | `0x74` | `t` |
| `[4]`  | `0x72` | `r` |
| `[6]`  | `0x6e` | `n` |
| `[7]`  | `0x6d` | `m` |
| `[8]`–`[16]` | `0x69` | `i` (×9, from loop) |
| `[17]` | `0x70` | `p` |
| `[18]` | `0x73` | `s` |

#### Step 5 — Arithmetic check at offset 5

```asm
lb     $v1, 0x21($fp)        ; buffer[5]
lb     $v0, 0x20($fp)        ; buffer[4]  = 'r' = 0x72
addiu  $v0, $v0, 3           ; 0x72 + 3   = 0x75
beq    $v1, $v0, success     ; buffer[5] must == buffer[4] + 3
```

**➜ `buffer[5]` = `'r' + 3` = `'u'` (0x75)**

This is the only non-trivial check: the expected value is derived at runtime
from another character rather than being a fixed immediate.

### Password reconstruction

Assembling all checks at indices 0–18:

```
Index:  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18
Char:   c  a  n  t  r  u  n  m  i  i  i  i  i  i  i  i  i  p  s
```

---

## Why does this work?

The binary performs no hashing, no XOR encoding, and no self-modifying code.
Each character of the expected password is compared directly against a hardcoded
immediate value (or a trivial arithmetic expression) using MIPS `beq`/`bne`
instructions. Static analysis alone is sufficient — no emulation or dynamic
execution needed.

The only mild anti-analysis measure is that the checks are performed in
**non-sequential order** (indices `18, 17, 7, 6, 0, 1, 3, 4` then the loop
for `8–16`), making the password slightly less obvious when skimming the disassembly.

---

## Key Takeaways

- **`strings`** is always the first step — it immediately reveals the success/failure
  messages and confirms what kind of comparison logic to look for.
- **Capstone** disassembles any architecture without needing a native emulator;
  specifying `CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN` is essential here.
- **MIPS delay slots** mean the instruction after a `beq`/`jalr` executes before
  the branch — keep this in mind when tracing control flow.
- **Non-sequential byte checks** are a trivial obfuscation technique that only
  requires careful bookkeeping to defeat.
- **Arithmetic checks** (`buffer[5] == buffer[4] + 3`) are slightly harder to spot
  than fixed immediates but equally transparent in the disassembly.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `file` | Identify ELF architecture and linking |
| `strings` | Extract printable strings and locate I/O messages |
| Python `struct` | Parse ELF header to locate `.text` and `.rodata` |
| Python `capstone` | Disassemble MIPS32 LE bytecode statically |

---

## References

- [Capstone disassembly framework](https://www.capstone-engine.org/)
- [MIPS32 Architecture Reference Manual](https://www.mips.com/products/architectures/mips32-2/)
- [ELF specification](https://refspecs.linuxfoundation.org/elf/elf.pdf)
- [Root-Me — ELF MIPS - Basic Crackme](https://www.root-me.org/en/Challenges/Cracking/ELF-MIPS-Basic-Crackme)
