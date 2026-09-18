# Level 7

| Item | Details |
|------|---------|
| Level | 7 |
| Game | Bandit |
| Difficulty | Beginner |
| Status | Completed |
| Last update | Sep 2026 |

---

## Objective

Log in to `bandit7` and retrieve the password for `bandit8`. The password is stored somewhere inside a large text file, `data.txt`, next to the word `millionth`.

## Connection

```bash
ssh bandit7@bandit.labs.overthewire.org -p 2220
```

Password: the credential obtained at the end of Level 6.

## Enumeration

```bash
ls
```

Output:

```text
data.txt
```

A single file, `data.txt`, sits in the home directory. Given the challenge hint — find the password next to the word `millionth` — the file is expected to contain a large list of key/value pairs, too large to search manually.

## Solution

```bash
grep "millionth" data.txt
```

`grep` scans `data.txt` line by line and prints every line containing the string `millionth`, avoiding the need to open or scroll through the whole file.

Output:

```text
millionth	VR1ljMayciFxbnUokuQmJFw6QC9VKtub
```

The matching line consists of the word `millionth`, a tab character, and the password.

## Result

| Item | Value |
|---|---|
| Command that solved the level | `grep "millionth" data.txt` |
| Next user | `bandit8` |
| Password for `bandit8` | `VR1ljMayciFxbnUokuQmJFw6QC9VKtub` |

## Why it works

`grep` performs pattern matching across the file's content and returns only the matching lines, which is far more efficient than manually scanning or paging through a file that could contain thousands of lines. Since the level description provided the exact keyword (`millionth`) to search for, a single `grep` call is enough to isolate the relevant line from the whole dataset.

## Lessons learned

- `grep "pattern" file` is the standard tool for finding a known string inside a large text file without opening it in an editor or paging through it manually.
- When a challenge gives an exact keyword to search for, that is usually a direct hint to use `grep` instead of `cat` or `less` and eyeballing the content.
- Output formatting, such as a tab-separated key/value line, is worth paying attention to — it tells you exactly what `grep`'s output represents.

## References

- [OverTheWire Bandit wargame](https://overthewire.org/wargames/bandit/)
- [Bandit Level 7 details](https://overthewire.org/wargames/bandit/bandit7.html)
- `grep(1)` manual page
