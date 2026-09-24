# Level 9

| Item | Details |
|------|---------|
| Level | 9 |
| Game | Bandit |
| Difficulty | Beginner |
| Status | Completed |
| Last update | Sep 2026 |

---

## Objective

Log in to `bandit9` and retrieve the password for `bandit10`. This time `data.txt` is a binary or mixed-content file, and the password is the only human-readable string preceded by several consecutive `=` characters.

## Connection

```bash
ssh bandit9@bandit.labs.overthewire.org -p 2220
```

Password: the credential obtained at the end of Level 8.

## Enumeration

```bash
ls
```

Output:

```text
data.txt
```

Given the level hint — the password is preceded by several `=` characters — `data.txt` is expected to mix binary data with a few readable strings, one of which contains the target sequence.

## Solution

```bash
strings data.txt | grep '=='
```

- `strings data.txt` — extracts readable character sequences from the mixed-content file, discarding raw binary noise that would otherwise make the file unreadable in a terminal.
- `grep '=='` — filters that output to lines containing the separator pattern described by the level.

Output:

```text
cL0========== the
========== password
>========== is
R========== B0s2khmbT9u0geKuOoVGW3JZKhndE3BG
```

Several lines match the separator pattern, most of them fragments of surrounding text attached to filler words such as `the`, `password`, and `is`. The last line is the real one: after the separator, it contains the actual password.

## Result

| Item | Value |
|---|---|
| Command that solved the level | `strings data.txt | grep '=='` |
| Next user | `bandit10` |
| Password for `bandit10` | `B0s2khmbT9u0geKuOoVGW3JZKhndE3BG` |

## Why it works

`strings` is built to pull readable text out of a binary or mixed-content file, which is necessary here since using `cat` directly would print unreadable binary garbage to the terminal. Filtering that output with `grep` then narrows a potentially large number of extracted strings down to the handful that match the separator pattern the level describes, making the correct line easy to spot.

## Lessons learned

- `strings` is the go-to tool for extracting readable text from a binary or otherwise non-plain-text file.
- Combining `strings` with `grep` on a known pattern is an efficient way to filter a large amount of extracted text down to the relevant lines.
- Not every match from a filter is necessarily the answer; the surrounding context helps identify the real credential.

## References

- [OverTheWire Bandit wargame](https://overthewire.org/wargames/bandit/)
- [Bandit Level 9 details](https://overthewire.org/wargames/bandit/bandit9.html)
- `strings(1)` manual page
