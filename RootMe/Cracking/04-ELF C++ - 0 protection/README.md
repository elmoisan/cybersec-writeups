# ELF C++ - 0 protection

`Reverse Engineering` • `Easy` • `10 pts`

## TL;DR

A Linux ELF32 C++ executable with no obfuscation whatsoever.
The binary XORs two hardcoded byte arrays at runtime using a custom `plouf()` function,
then compares the result against `argv[1]`.
Extracting both arrays from `.rodata` and replaying the XOR gives the flag directly — no execution required.

**Flag:** `Here_you_have_to_understand_a_little_C++_stuffs`

---

## Challenge Description

> std::string
>
> Find the validation password.

The provided file `ch25.bin` is a 32-bit Linux ELF executable.
It expects the password as a command-line argument: `./ch25.bin <password>`.

---

## Recon

### File identification

```bash
$ file ch25.bin
ch25.bin: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV),
          dynamically linked, interpreter /lib/ld-linux.so.2,
          for GNU/Linux 2.6.24, not stripped
```

A plain, unstripped ELF32 binary. No packer, no obfuscation — symbols are intact and
static analysis works directly. The `not stripped` flag means function names survive
in the symbol table, which saves a lot of time.

### Strings extraction

```bash
$ strings ch25.bin
...
Bravo, tu peux valider en utilisant ce mot de passe...
Congratz. You can validate with this password...
Password incorrect.
...
_Z5ploufSsSs
main
```

Key observations:

| String / Symbol | Meaning |
|----------------|---------|
| `Congratz. You can validate with this password...` | Success path |
| `Password incorrect.` | Failure path |
| `_Z5ploufSsSs` | Mangled C++ symbol → `plouf(std::string, std::string)` |
| `_ZNSspLEc` | `std::string::operator+=` — result is built char by char |
| `_ZNSsixEj` | `std::string::operator[]` — indexed character access |
| `_ZNKSs6lengthEv` | `std::string::length()` — used as the modulo divisor |

The password is not in plaintext, but the presence of `plouf` alongside indexed access
and `length()` immediately suggests a character-by-character transformation using one
string as a key.

### Section layout

Sections were mapped to correlate virtual addresses (VAs) with file offsets:

| Section | VMA | File Offset | Size |
|---------|-----|-------------|------|
| `.text` | `0x08048890` | `0x890` | `0x502` |
| `.rodata` | `0x08048da8` | `0x0da8` | `0xd8` |
| `.data` | `0x0804b054` | `0x2054` | `0x8` |

Both hardcoded byte arrays live in `.rodata`:

| Address | Role | Length |
|---------|------|--------|
| `0x8048dc4` | XOR key | 6 bytes |
| `0x8048dcc` | Ciphertext | 47 bytes |

---

## Exploitation

### Step 1 — Demangle the key symbol

```bash
$ c++filt _Z5ploufSsSs
plouf(std::string, std::string)
```

The function `plouf` takes two `std::string` arguments. Combined with the C++ operators
visible in the symbol table (`operator[]`, `length`, `operator+=`), this points to a
classic repeating-key XOR cipher.

### Step 2 — Disassemble `plouf`

```bash
$ objdump -d ch25.bin | grep -A 80 '<_Z5ploufSsSs>'
```

The loop body, cleaned up:

```asm
; esi = ciphertext[i]          — str at 0xc(%ebp), indexed by i
; edi = key.length()           — str at 0x10(%ebp)
; i % edi → ecx                — wrap-around index into the key
; eax = key[ecx]               — key byte for this position
xor    %esi, %eax              ; plaintext_char = ciphertext[i] XOR key[i % key_len]
call   _ZNSspLEc               ; result += plaintext_char
```

The algorithm is a classic repeating-key XOR:

```
result[i] = ciphertext[i] XOR key[i % len(key)]
```

The loop terminates when `ciphertext[i] == '\0'`, processing the full 47-character string.

### Step 3 — Identify argument order from `main`

```asm
lea  -0x14(%ebp), %eax    ; result      → (%esp)      → plouf output buffer
lea  -0xc(%ebp),  %edx    ; str_a       → 0x8(%esp)   → plouf arg2  (key)
lea  -0x10(%ebp), %edx    ; str_b       → 0x4(%esp)   → plouf arg1  (ciphertext)
call _Z5ploufSsSs
...
call _ZSteqIcSt11char_traitsIcESaIcEEbRKSbIT_T0_T1_EPKS3_
; std::operator==(std::string const&, char const*)
; compares plouf result with argv[1]
```

So the program computes `plouf(str_b, str_a)` and checks whether the output equals
the user-supplied argument. The argument order matters: `str_b` is the ciphertext
(iterated), `str_a` is the key (cycled).

### Step 4 — Extract both byte arrays from `.rodata`

`.rodata` starts at VMA `0x08048da8`, file offset `0x0da8`.

```
Address     File offset   Raw bytes (hex)
----------  -----------   ---------------------------------------------------
0x8048dc4   0x0dc4        18 d6 15 ca fa 77               ← key (6 bytes)
0x8048dcc   0x0dcc        50 b3 67 af a5 0e 77 a3 ...     ← ciphertext (47 bytes)
```

### Step 5 — Replay the XOR offline

```python
with open('ch25.bin', 'rb') as f:
    data = f.read()

rodata_vma = 0x08048da8
rodata_off  = 0x0da8

def read_cstr(vma):
    off = rodata_off + (vma - rodata_vma)
    end = data.index(b'\x00', off)
    return data[off:end]

key        = read_cstr(0x8048dc4)   # 6 bytes
ciphertext = read_cstr(0x8048dcc)  # 47 bytes

password = bytes(c ^ key[i % len(key)] for i, c in enumerate(ciphertext))
print(password.decode())
# Here_you_have_to_understand_a_little_C++_stuffs
```

---

## Why does this work?

The title says it all: *"0 protection"*. The developer hardcoded both the ciphertext
and the key directly in `.rodata`, with no:

- Hashing or key derivation
- Obfuscation or packing
- Anti-debugging tricks
- Dynamic key generation

The XOR cipher looks more sophisticated than a raw byte comparison, but because the key
is stored alongside the ciphertext in the same binary, it provides zero actual security.
Any static analysis tool can recover both values instantly.

The only "noise" added by the C++ implementation is the boilerplate around `std::string`
— constructors, destructors, operator calls — which clutters the disassembly but does
not change the fundamental transparency of the algorithm.

---

## Key Takeaways

- **`strings` + `c++filt`** together are the first step on any C++ binary — mangled
  symbols reveal the function signatures without even opening a disassembler.
- **Unstripped binaries** leave all symbol names intact: locating `plouf`, `main`, and
  the C++ string operators takes seconds.
- **Repeating-key XOR** is not encryption when the key is stored in the same file as
  the ciphertext — both are equally readable to a static analyst.
- **Argument order in x86 cdecl** must be read carefully: `mov` to `(%esp)` is the
  first argument, `0x4(%esp)` the second, `0x8(%esp)` the third. Getting it wrong
  swaps key and ciphertext and produces garbage.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `file` | Identify binary format |
| `strings` | Extract printable constants and C++ mangled symbols |
| `c++filt` | Demangle C++ symbol names |
| `objdump` | Disassemble ELF sections |
| Python `struct` | Parse ELF headers and section offsets |

---

## References

- [ELF Format — Wikipedia](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format)
- [C++ Name Mangling — Itanium ABI](https://itanium-cxx-abi.github.io/cxx-abi/abi.html#mangling)
- [Capstone Engine](https://www.capstone-engine.org/)
- [Ghidra — NSA reverse engineering tool](https://ghidra-sre.org/)
- [Root-Me — ELF C++ - 0 protection](https://www.root-me.org/en/Challenges/Cracking/ELF-C-0-protection)
