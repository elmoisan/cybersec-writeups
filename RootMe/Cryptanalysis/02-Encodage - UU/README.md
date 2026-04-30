# Encodage - UU

`Encodage` • `Easy` • `5 pts`

## TL;DR

A classic UUencoding challenge. The provided file is a standard UUencoded archive — decoding it with `uudecode` or Python's `uu` module reveals the password directly in plaintext.

**Flag:** `[REDACTED]`

---

## Challenge Description

> Très utilisé par le protocole HTTP.
>
> Retrouver le mot de passe de validation.

The provided file `ch1.txt` contains a UUencoded payload.

---

## Recon

### File analysis

The file structure is immediately recognisable as **UUencoding** thanks to its markers:

```
_=_ Part 001 of 001 of file root-me_challenge_uudeview

begin 644 root-me_challenge_uudeview
B5F5R>2!S:6UP;&4@.RD*4$%34R`](%5,5%)!4TE-4$Q%"@``
`
end
```

Key indicators:

| Element | Meaning |
|---------|---------|
| `begin 644 <filename>` | Start of UU block — `644` is the Unix file permission |
| Line starting with `B` | Encoded data line — the leading char encodes the byte count |
| Backtick `` ` `` alone | Encoded empty line (end of data) |
| `end` | End of UU block |

### What is UUencoding?

UUencoding (Unix-to-Unix encoding) converts binary data to printable ASCII by:
1. Grouping input bytes into chunks of 3 (24 bits)
2. Splitting each chunk into four 6-bit values
3. Adding 32 to each value to land in the printable ASCII range (`!` to `` ` ``)
4. Prepending each line with a character encoding the number of bytes on that line

It was widely used in early Usenet and email systems to transfer binary files over text-only channels.

---

## Exploitation

### Method 1 — Command line (`uudecode`)

```bash
uudecode ch1.txt
cat root-me_challenge_uudeview
```

### Method 2 — Python

```python
import uu, io

data = b"""begin 644 result
B5F5R>2!S:6UP;&4@.RD*4$%34R`](%5,5%)!4TE-4$x%"@``
`
end
"""

in_file = io.BytesIO(data)
out_file = io.BytesIO()
uu.decode(in_file, out_file)
print(out_file.getvalue().decode())
```

### Output

```
Very simple ;)
PASS = ULTRASIMPLE
```

The password is written in plaintext in the decoded file.

---

## Why does this work?

UUencoding is, like ASCII hex, a pure **encoding** — not encryption. There is no key and no secret: anyone with a `uudecode` binary or equivalent can reverse it instantly. The `begin`/`end` wrapper is part of the format spec and makes the encoding immediately identifiable.

The challenge hint *"Très utilisé par le protocole HTTP"* refers to the broader family of content-transfer encodings (Base64 being the modern HTTP standard), of which UUencoding is a historical predecessor.

---

## Key Takeaways

- **UUencoding** is identifiable by its `begin <perms> <filename>` / `end` markers and printable-ASCII-shifted data lines.
- It is a lossless, keyless encoding — trivially reversible with `uudecode` or Python's `uu` module.
- The leading character of each data line encodes the **number of bytes** on that line, not data — don't confuse it with Base64.
- Modern systems replaced UUencoding with **Base64** for HTTP and email (MIME), but UU still appears in legacy formats and CTF challenges.

---

## References

- [UUencoding — Wikipedia](https://en.wikipedia.org/wiki/Uuencoding)
- [Python `uu` module documentation](https://docs.python.org/3/library/uu.html)
- [RFC 2045 — MIME Part One (successor encoding context)](https://datatracker.ietf.org/doc/html/rfc2045)
- [Root-Me — Encodage UU challenge](https://www.root-me.org/en/Challenges/Cryptanalysis/UU)