# Encodage - ASCII

`Encodage` • `Easy` • `5 pts`

## TL;DR

A simple encoding challenge. A hex string is provided — decoding it from hexadecimal to ASCII directly reveals the flag embedded in a sentence.

**Flag:** `2ac376481ae546cd689d5b91275d324e`

---

## Challenge Description

> Décoder la chaîne.

The provided file contains a single hex-encoded string:

```
4C6520666C6167206465206365206368616C6C656E6765206573743A203261633337363438316165353436636436383964356239313237356433323465
```

---

## Recon

### File analysis

The file `ch8.txt` contains a raw hexadecimal string with no separators or delimiters. Each pair of hex characters represents one ASCII byte.

Breaking it down:

| Hex | ASCII |
|-----|-------|
| `4C` | `L` |
| `65` | `e` |
| `20` | ` ` |
| `66` | `f` |
| `6C` | `l` |
| `61` | `a` |
| `67` | `g` |
| `20` | ` ` |
| `…`  | `…` |

---

## Exploitation

### Decoding the hex string

The conversion is straightforward — interpret each pair of hex digits as an ASCII character code.

**Using Python:**

```python
data = "4C6520666C6167206465206365206368616C6C656E6765206573743A203261633337363438316165353436636436383964356239313237356433323465"
print(bytes.fromhex(data).decode())
```

**Using the command line:**

```bash
echo "4C6520666C61672064652..." | xxd -r -p
```

**Output:**

```
Le flag de ce challenge est : 2ac376481ae546cd689d5b91275d324e
```

The flag is revealed verbatim in the decoded sentence.

---

## Why does this work?

ASCII (American Standard Code for Information Interchange) maps integers 0–127 to characters. Hexadecimal is simply base-16 representation of those integers. Any hex string can be decoded to its ASCII equivalent in a single pass — no key, no cipher, no brute-force required.

This is **encoding**, not **encryption**: there is no secret involved, only a representation change.

---

## Key Takeaways

- **Hex → ASCII** is a one-step, lossless conversion requiring no key.
- Recognising the encoding format (hex, base64, binary…) is the first and most important step of any encoding challenge.
- Python's `bytes.fromhex()` and the Unix `xxd -r -p` pipe are the fastest tools for this job.
- Always check the length of the string: a hex string always has an **even** number of characters.

---

## References

- [ASCII Table — asciitable.com](https://www.asciitable.com/)
- [Python `bytes.fromhex()` documentation](https://docs.python.org/3/library/stdtypes.html#bytes.fromhex)
- [xxd man page](https://linux.die.net/man/1/xxd)
- [Root-Me — Encodage ASCII challenge](https://www.root-me.org/en/Challenges/Cryptanalysis/ASCII)