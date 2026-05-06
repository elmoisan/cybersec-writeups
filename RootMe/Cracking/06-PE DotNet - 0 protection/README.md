# PE DotNet - 0 protection

`Reverse Engineering` • `Easy` • `10 pts`

## TL;DR

A Visual Basic .NET WinForms crackme with absolutely no obfuscation.
In .NET assemblies, all string literals are stored verbatim as UTF-16LE in the `#US`
(User Strings) metadata heap — including the password. One `strings -el` call is enough.

**Flag:** `DotNetOP`

---

## Challenge Description

> Retrouvez le mot de passe de validation demandé par le binaire.

The provided file `ch22.exe` is a 32-bit Windows GUI executable built with
Visual Basic .NET (Mono/.NET assembly). It displays a WinForms dialog with a
text field and a validation button; the correct password must be entered to get
the success message.

---

## Recon

### File identification

```bash
$ file ch22.exe
ch22.exe: PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows, 4 sections
$ wc -c ch22.exe
26624
```

The `Mono/.Net assembly` tag from `file` is the key detail: this is not native x86
machine code but a managed CIL (Common Intermediate Language) binary. The CPU
instructions in the PE are just a stub that hands off execution to the .NET runtime.
All actual logic — including string constants — lives in the managed metadata.

### Strings extraction

The quickest first step on any .NET binary is `strings` with the UTF-16LE flag,
since .NET stores all literals in that encoding:

```bash
$ strings -el ch22.exe
Label1
Password
TextBox1
Button1
Valider
Form1
CrackMe DotNet bat86
DotNetOP
Bravo! Vous pouvez valider avec ce mot de passe
Well done! You can validate with this password
Mauvais mot de passe
Bad password
...
```

The password appears in plaintext immediately. No disassembly required.

Key observations:

| String | Meaning |
|--------|---------|
| `CrackMe DotNet bat86` | Window title — confirms VB.NET origin |
| `Valider` | Submit button label |
| **`DotNetOP`** | **The password** |
| `Bravo! Vous pouvez valider...` | Success branch |
| `Mauvais mot de passe` | Failure branch |

### .NET metadata structure

To understand *why* the password is so accessible, it helps to know the .NET
assembly format. The PE file wraps a metadata payload identified by the `BSJB` magic:

```
CLR header RVA  : 0x2008
Metadata RVA    : 0x2a1c  (file offset 0xe1c)
Runtime version : v4.0.30319
```

The metadata contains five streams:

| Stream | File offset | Size | Role |
|--------|-------------|------|------|
| `#~` | `0xe88` | 3 400 B | Compressed tables (types, methods, fields…) |
| `#Strings` | `0x1bd0` | 3 724 B | Identifier names (class, method, field names) |
| `#US` | `0x2a5c` | 640 B | **User Strings — all string literals from source** |
| `#GUID` | `0x2cdc` | 16 B | Assembly GUIDs |
| `#Blob` | `0x2cec` | 1 540 B | Signatures, constants |

The `#US` heap is where every string written in the source code ends up, stored
as raw **UTF-16LE** with a compressed length prefix. No encryption, no hashing —
the .NET specification requires this format so the JIT compiler can load strings
at runtime without any transformation.

---

## Exploitation

### Method 1 — One liner (fastest)

```bash
$ strings -el ch22.exe
```

`-e l` tells `strings` to scan for little-endian 16-bit characters (UTF-16LE),
which is the .NET `#US` heap encoding. The password appears directly in the output.

### Method 2 — Parse the `#US` heap manually

```python
import pefile, struct

pe   = pefile.PE('ch22.exe')
data = open('ch22.exe', 'rb').read()

# Locate CLR header → metadata root
clr_off  = pe.get_offset_from_rva(pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress)
meta_rva = struct.unpack_from('<I', data, clr_off + 8)[0]
meta_off = pe.get_offset_from_rva(meta_rva)

# Parse stream directory
ver_len      = struct.unpack_from('<I', data, meta_off + 12)[0]
pos          = meta_off + 16 + ver_len
pos         += (4 - pos % 4) % 4           # align to 4 bytes
stream_count = struct.unpack_from('<H', data, pos + 2)[0]
pos += 4

streams = {}
for _ in range(stream_count):
    off  = struct.unpack_from('<I', data, pos)[0]
    size = struct.unpack_from('<I', data, pos + 4)[0]
    ne   = data.index(b'\x00', pos + 8)
    name = data[pos + 8:ne].decode()
    pos  = (ne + 4) & ~3
    streams[name] = (meta_off + off, size)

# Dump every string in #US
us_off, us_size = streams['#US']
pos = us_off + 1
while pos < us_off + us_size:
    b0 = data[pos]
    if b0 == 0:
        break
    if b0 & 0xC0 == 0x80:
        length = ((b0 & 0x3F) << 8) | data[pos + 1]; pos += 2
    else:
        length = b0; pos += 1
    if length == 0:
        break
    print(data[pos:pos + length - 1].decode('utf-16-le'))
    pos += length
```

Output:

```
Label1
Password
TextBox1
Button1
Valider
Form1
CrackMe DotNet bat86
DotNetOP
Bravo! Vous pouvez valider avec ce mot de passe
Well done! You can validate with this password
Mauvais mot de passe
Bad password
```

---

## Why does this work?

The .NET specification mandates that all string literals used in CIL bytecode are
stored verbatim in the `#US` heap so the JIT can materialise them as
`System.String` objects at runtime. There is no optional encryption layer —
the format is fully public and parseable by any tool that understands PE + ECMA-335.

The developer stored the expected password as a plain string literal, most likely
in a direct comparison like:

```vb
If TextBox1.Text = "DotNetOP" Then
    MsgBox("Bravo! ...")
Else
    MsgBox("Mauvais mot de passe")
End If
```

This compiles to a `ldstr "DotNetOP"` CIL instruction, which dumps the string
straight into `#US`. A proper implementation would at minimum hash the input
and compare digests, keeping the plaintext password out of the binary entirely.

---

## Key Takeaways

- **`strings -el`** is the .NET equivalent of `strings`: always run it first on
  any managed assembly — it dumps the entire `#US` heap in one command.
- **The `#US` heap** stores every string literal from the source code in UTF-16LE
  with no encryption. This is mandated by ECMA-335 and cannot be avoided without
  an obfuscator.
- **Plain string comparison** (`If input = "secret"`) is the most naive form of
  password check in .NET — the secret is literally embedded as a `ldstr` instruction.
- **Dedicated .NET decompilers** (dnSpy, ILSpy) go further: they reconstruct the
  full VB.NET or C# source, making the comparison logic fully readable in seconds.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `file` | Identify managed .NET assembly |
| `strings -el` | Dump UTF-16LE string literals from `#US` heap |
| Python `pefile` | Parse PE headers and locate CLR metadata |
| Python `struct` | Navigate ECMA-335 metadata streams manually |

---

## References

- [ECMA-335 — Common Language Infrastructure specification](https://ecma-international.org/publications-and-standards/standards/ecma-335/)
- [.NET PE format — dotnet/runtime source](https://github.com/dotnet/runtime/blob/main/docs/design/specs/PE-COFF.md)
- [dnSpy — .NET debugger and decompiler](https://github.com/dnSpy/dnSpy)
- [ILSpy — open-source .NET decompiler](https://github.com/icsharpcode/ILSpy)
- [Root-Me — PE DotNet - 0 protection](https://www.root-me.org/en/Challenges/Cracking/PE-DotNet-0-protection)
