# Level 8

| Item | Details |
|------|---------|
| Level | 8 |
| Game | Bandit |
| Difficulty | Beginner |
| Status | Completed |
| Last update | Sep 2026 |

---

## Objective

Log in to `bandit8` and retrieve the password for `bandit9`. The password is the only line in `data.txt` that appears exactly once — every other line is duplicated at least once.

## Connection

```bash
ssh bandit8@bandit.labs.overthewire.org -p 2220
```

Password: the credential obtained at the end of Level 7.

## Enumeration

```bash
ls
```

Output:

```text
data.txt
```

A single file, `data.txt`, is present. Given the challenge hint — the password is the only line that occurs once — the file is expected to contain many repeated lines plus one unique line.

## Solution

```bash
sort data.txt | uniq -u
```

- `sort data.txt` — orders the file's lines alphabetically. This step is required because `uniq` only detects duplicates between adjacent lines, so the file must be sorted first for identical lines to end up next to each other.
- `uniq -u` — reads the sorted output and prints only the lines that have no duplicate, meaning lines that appear exactly once.

Output:

```text
EjmOSvuAu7sGAHqHVcBDPirRe9T03kxl
```

## Result

| Item | Value |
|---|---|
| Command that solved the level | `sort data.txt | uniq -u` |
| Next user | `bandit9` |
| Password for `bandit9` | `EjmOSvuAu7sGAHqHVcBDPirRe9T03kxl` |

## Why it works

`uniq` is a line-deduplication tool, but it only compares consecutive lines. It has no knowledge of the file as a whole. Piping through `sort` first guarantees that every occurrence of a given line ends up grouped together, which makes `uniq -u` able to correctly identify the single line with no duplicate anywhere in the file.

## Lessons learned

- `uniq` requires sorted input to work correctly across the whole file — `sort file | uniq` or its variants are the standard idiom, not `uniq` alone.
- `uniq -u` isolates lines with no duplicates, as opposed to plain `uniq` or `uniq -d`.
- `sort | uniq -u` is a common and efficient pattern for finding the odd one out in a large dataset without writing a custom script.

## References

- [OverTheWire Bandit wargame](https://overthewire.org/wargames/bandit/)
- [Bandit Level 8 details](https://overthewire.org/wargames/bandit/bandit8.html)
- `sort(1)` and `uniq(1)` manual pages
