# ELF x64 - Golang basique

`Reverse Engineering` • `Easy` • `15 pts`

---

## TL;DR

An unobfuscated Go binary with debug symbols intact. `main.main` reads user
input, XORs every byte with the repeating key `"rootme"`, and compares the
result against 14 hardcoded bytes in `.rodata`. XORing the expected bytes with
the key directly recovers the plaintext password.

**Flag:** `ImLovingGoLand`

---

## Challenge Description

> Retrouvez le mot de passe permettant de valider ce challenge.

The provided file `ch32.bin` is a 64-bit Linux ELF that prompts for a password
and prints a success or failure message.

---

## Recon

### File identification

```bash
$ file ch32.bin
ch32.bin: ELF 64-bit LSB executable, x86-64, version 1 (SYSV),
statically linked, Go BuildID=2cf6d44559551c6185a598406fb67318d5b2396e,
with debug_info, not stripped

$ wc -c ch32.bin
1968737
```

Key observations:

- **Go BuildID** tag confirms a Go binary.
- **not stripped** means all symbol names are preserved — a huge help for
  static analysis.
- **statically linked** is normal for Go: the entire runtime is bundled,
  hence the ~2 MB size.

### Symbol table

Because the binary is not stripped, `nm` exposes every function in the
`main` package:

```bash
$ nm ch32.bin | grep "main\."
0000000000493120 T main.init
000000000055cca5 B main.initdone.
0000000000492e70 T main.main
00000000004d60d0 R main.statictmp_0
00000000004d60e0 R main.statictmp_1
00000000004d6040 R main.statictmp_2
```

There is only one user function (`main.main`) and three read-only static
values. `statictmp_0` and `statictmp_1` are the success/failure message
objects; `statictmp_2` holds the expected XOR-encrypted password.

---

## Static Analysis

### Disassembling `main.main`

```bash
$ objdump -d ch32.bin --start-address=0x492e70 --stop-address=0x493120
```

The function breaks down into four logical blocks:

#### 1 — Read user input

```asm
call   fmt.Scanln          ; read input into a *string on the heap
```

#### 2 — Load the XOR key

```asm
lea    0x3153a(%rip), %rax   ; rax → 0x4c446d  ("rootme", 6 bytes)
movq   $0x6, 0x10(%rsp)      ; key length = 6
call   runtime.stringtoslicebyte
```

The 6-byte key `"rootme"` lives in `.rodata` at `0x4c446d`.

#### 3 — XOR loop

```asm
; r9  = loop index i
; rbx = pointer into input bytes
; r8  = pointer to XOR key

loop:
  cmp  %rsi, %r9           ; i < input_len ?
  jge  done

  movzbl (%rbx), %r10d     ; r10 = input[i]
  cqto
  idiv %rdi                ; rdx = i % key_len
  movzbl (%r8,%rdx,1), %edx ; edx = key[i % 6]
  xor  %edx, %r10d         ; r10 = input[i] ^ key[i%6]
  mov  %r10b, (%r12,%r9,1) ; result[i] = r10
  inc  %rbx
  inc  %r9
  jmp  loop
```

Each input byte is XORed with `key[i % 6]`.

#### 4 — Compare and branch

```asm
; compare result (14 bytes) with statictmp_2 (14 bytes)
movq   $0xe, 0x8(%rsp)     ; expected length = 14
mov    %rdx, 0x18(%rsp)    ; result slice
lea    0x42(%rsp), %rbx    ; pointer to statictmp_2 copy on stack
call   bytes.Compare

test   %rax, %rax
jne    fail                ; rax != 0 → "Bad password"
                           ; rax == 0 → "Well done"
```

---

## Exploitation

### Extract the encrypted expected value

The 14 expected bytes come from `main.statictmp_2` at virtual address
`0x4d6040`. Mapping that address to a file offset using the ELF LOAD
segments:

| Segment | VAddr | File offset | Size |
|---------|-------|-------------|------|
| 1 | `0x400000` | `0x000000` | `0x93180` |
| 2 | `0x494000` | `0x094000` | `0x97785` |
| 3 | `0x52c000` | `0x12c000` | `0x12680` |

`0x4d6040` falls in segment 2: `file_offset = 0x094000 + (0x4d6040 - 0x494000) = 0xd6040`.

### Recover the password

```python
import struct

with open('ch32.bin', 'rb') as f:
    data = f.read()

# Virtual address → file offset helper
segments = [
    (0x400000, 0x000000, 0x93180),
    (0x494000, 0x094000, 0x97785),
    (0x52c000, 0x12c000, 0x12680),
]

def va2off(va):
    for base, off, size in segments:
        if base <= va < base + size:
            return off + (va - base)

# XOR key at 0x4c446d, length 6
xor_key = data[va2off(0x4c446d) : va2off(0x4c446d) + 6]
print(f"XOR key : {xor_key}")           # b'rootme'

# Expected ciphertext at statictmp_2 = 0x4d6040, length 14
expected = data[va2off(0x4d6040) : va2off(0x4d6040) + 14]
print(f"Expected: {expected.hex()}")    # 3b02231b1b0c1c08281b21041c0b

# Decrypt: password[i] = expected[i] ^ key[i % 6]
password = bytes(expected[i] ^ xor_key[i % len(xor_key)] for i in range(len(expected)))
print(f"Password: {password.decode()}")  # ImLovingGoLand
```

```
$ python3 solve.py
XOR key : b'rootme'
Expected: 3b02231b1b0c1c08281b21041c0b
Password: ImLovingGoLand
```

The password is **`ImLovingGoLand`**.

---

## Why does this work?

Go binaries compiled without `-trimpath` and without a separate strip pass
retain full DWARF debug info and symbol names. There is no obfuscation layer
at all: the XOR key and the encrypted blob both sit in `.rodata` as plain
byte sequences, and the algorithm is a textbook single-byte XOR with a short
repeating key.

```go
// Pseudocode reconstructed from the disassembly
func main() {
    var input string
    fmt.Scanln(&input)

    key      := []byte("rootme")
    expected := []byte{0x3b,0x02,0x23,0x1b,0x1b,0x0c,0x1c,0x08,0x28,0x1b,0x21,0x04,0x1c,0x0b}

    result := make([]byte, len(input))
    for i, b := range []byte(input) {
        result[i] = b ^ key[i%len(key)]
    }

    if bytes.Compare(result, expected) == 0 {
        fmt.Print("Well done!")    // statictmp_0
    } else {
        fmt.Print("Bad password")  // statictmp_1
    }
}
```

A proper implementation would at minimum hash the input (e.g. with bcrypt or
SHA-256) before comparing, keeping the expected value irrecoverable from a
static dump. Using the challenge name itself (`rootme`) as the XOR key makes
recovery even more trivial.

---

## Key Takeaways

- **Go binaries are not stripped by default** — symbol names (`main.main`,
  `statictmp_*`) survive and dramatically accelerate static analysis.
- **`nm` + `objdump`** are enough to fully reverse a simple Go crackme when
  debug info is present; no dynamic execution needed.
- **XOR with a short repeating key** provides zero security: knowing the
  key (visible in `.rodata`) immediately decrypts the expected ciphertext.
- **ELF virtual addresses ≠ file offsets** — always use the LOAD segment map
  (`p_vaddr`, `p_offset`) to read the correct bytes from disk.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `file` | Identify ELF, Go build ID, strip status |
| `nm` | List symbols — locate `main.main` and `statictmp_*` |
| `objdump -d` | Disassemble `main.main` and trace the XOR logic |
| Python `struct` | Parse ELF LOAD segments and extract raw bytes |

---

## References

- [Go compiler flags — cmd/compile](https://pkg.go.dev/cmd/compile)
- [ELF-64 Object File Format specification](https://uclibc.org/docs/elf-64-gen.pdf)
- [Dalvik vs Go bytecode — static analysis differences](https://github.com/golang/go/wiki/AssemblyPolicy)
- [Root-Me — ELF x64 - Golang basique](https://www.root-me.org/en/Challenges/Cracking/ELF64-Golang-basique)