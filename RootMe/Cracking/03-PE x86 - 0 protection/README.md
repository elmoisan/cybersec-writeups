# PE x86 - 0 protection

`Reverse Engineering` • `Easy` • `5 pts`

## TL;DR

A Windows PE32 executable from GreHack CTF 2012 with absolutely no obfuscation.
The password check is a straightforward byte-by-byte comparison in plaintext assembly —
reading the `cmp` instructions directly gives the flag.

**Flag:** `SPaCIoS`

---

## Challenge Description

> Épreuve issue du CTF GreHack 2012.
>
> Retrouvez le mot de passe permettant de valider ce challenge.

The provided file `ch15.exe` is a 32-bit Windows console executable.
It expects the password as a command-line argument: `ch15.exe <password>`.

---

## Recon

### File identification

```bash
$ file ch15.exe
ch15.exe: PE32 executable (console) Intel 80386 (stripped to external PDB),
          for MS Windows, 7 sections
```

A plain, unpackaged PE32 binary. No UPX, no custom packer — static analysis will work directly.

### Strings extraction

The first reflex on any unknown binary:

```bash
$ strings ch15.exe
...
Usage: %s pass
Gratz man :)
Wrong password
...
strncmp
```

Key observations:

| String | Meaning |
|--------|---------|
| `Usage: %s pass` | Password is passed as `argv[1]` |
| `Gratz man :)` | Success path |
| `Wrong password` | Failure path |
| `strncmp` in imports | String comparison is used somewhere |

The password is not visible in plaintext, but the strings give us exact targets to locate in the disassembly.

### PE header parsing

The binary's sections were parsed to map virtual addresses (VAs) to file offsets,
which is required to disassemble the right bytes:

| Section | VA | Raw Offset | Size |
|---------|----|------------|------|
| `.text` | `0x1000` | `0x400` | `0x1a00` |
| `.rdata` | `0x4000` | `0x2000` | `0x400` |
| `.data` | `0x3000` | `0x1e00` | `0x200` |

The entry point RVA is `0x14e0` (image base `0x400000`).

---

## Exploitation

### Step 1 — Locate the strings in `.rdata`

Scanning the `.rdata` section reveals the exact virtual addresses of our target strings:

```
0x00404044 : "Usage: %s pass"
0x00404053 : "Gratz man :)"
0x00404060 : "Wrong password"
```

### Step 2 — Find cross-references in `.text`

Searching for the values `0x404053` and `0x404060` as 32-bit little-endian constants
inside the `.text` section points directly to the password-checking function:

```
Ref to "Gratz man :)"   → VA 0x00401792
Ref to "Wrong password" → VA 0x004017ad
```

Both references sit inside the same function starting at `0x401726`.

### Step 3 — Disassemble the check function

Disassembly of the function at `0x401726` with **Capstone**:

```asm
0x00401733  cmp  dword ptr [ebp+0xc], 7   ; length must be exactly 7
0x00401737  jne  0x4017aa                 ; → "Wrong password"

0x0040173f  cmp  al, 0x53                 ; char[0] == 'S'
0x00401741  jne  0x4017aa

0x0040174c  cmp  al, 0x50                 ; char[1] == 'P'
0x0040174e  jne  0x4017aa

0x00401759  cmp  al, 0x61                 ; char[2] == 'a'
0x0040175b  jne  0x4017aa

0x00401766  cmp  al, 0x43                 ; char[3] == 'C'
0x00401768  jne  0x4017aa

0x00401773  cmp  al, 0x49                 ; char[4] == 'I'
0x00401775  jne  0x4017aa

0x00401780  cmp  al, 0x6f                 ; char[5] == 'o'
0x00401782  jne  0x4017aa

0x0040178d  cmp  al, 0x53                 ; char[6] == 'S'
0x0040178f  jne  0x4017aa

0x00401791  mov  eax, 0x404053            ; → "Gratz man :)"
```

### Step 4 — Decode the bytes

Converting each hexadecimal constant to ASCII:

| Index | Hex | Char |
|-------|-----|------|
| 0 | `0x53` | `S` |
| 1 | `0x50` | `P` |
| 2 | `0x61` | `a` |
| 3 | `0x43` | `C` |
| 4 | `0x49` | `I` |
| 5 | `0x6f` | `o` |
| 6 | `0x53` | `S` |

**Password: `SPaCIoS`**

---

## Why does this work?

The title says it all: *"0 protection"*. The developer stored the password as a
sequence of hardcoded byte constants compared one by one, with no:

- Hashing or encryption
- Obfuscation or packing
- Anti-debugging tricks
- Control-flow flattening

This is the most naive form of password check possible. Any disassembler exposes
the secret in seconds.

For comparison, a minimally hardened binary would at least hash the input and
compare it to a stored digest, forcing an attacker to crack the hash rather than
read the plaintext.

---

## Key Takeaways

- **`strings`** is always the first step on an unknown binary — it costs nothing
  and frequently reveals architecture, libraries, and logic.
- **Cross-referencing known strings** (success/failure messages) is the fastest
  way to navigate to the relevant code in a stripped binary.
- **Byte-by-byte `cmp` chains** in x86 are an immediate red flag: the expected
  value is sitting right there in the instruction operand.
- For real reverse engineering work, tools like **Ghidra** or **IDA** do all of
  this automatically and additionally decompile the function to readable C,
  making analysis even faster.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `file` | Identify binary format |
| `strings` | Extract printable constants |
| Python `struct` | Parse PE headers manually |
| Python `capstone` | Disassemble x86 instructions |

---

## References

- [PE Format — Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Capstone Engine](https://www.capstone-engine.org/)
- [Ghidra — NSA reverse engineering tool](https://ghidra-sre.org/)
- [Root-Me — PE x86 - 0 protection](https://www.root-me.org/en/Challenges/Cracking/PE-x86-0-protection)