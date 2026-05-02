# PE x86 - 0 protection

`Reverse Engineering` • `Easy` • `5 pts`

## TL;DR

A Windows PE32 executable from GreHack CTF 2012 with absolutely no obfuscation.
The password check is a straightforward byte-by-byte comparison in plaintext assembly —
reading the `cmp` instructions directly gives the flag.

**Flag:** `[REDACTED]`

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

A plain, unpackaged PE32 binary. No UPX, no custom packer — static analysis will
work directly.

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

The password is not visible in plaintext, but the strings give us exact targets to
locate in the disassembly.

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
