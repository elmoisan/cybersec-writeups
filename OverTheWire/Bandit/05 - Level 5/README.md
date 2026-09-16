# Level 5

| Item | Details |
|------|---------|
| Level | 5 |
| Game | Bandit |
| Difficulty | Beginner |
| Status | Completed |
| Last update | Sep 2026 |

---

## Objective

Log in to `bandit5` and retrieve the password for `bandit6`. The target file is hidden inside a nested directory tree and can be identified only by its exact size: **1033 bytes**.

## Connection

```bash
ssh bandit5@bandit.labs.overthewire.org -p 2220
```

Password: the credential obtained at the end of Level 4.

## Enumeration

```bash
ls
cd inhere
```

Output:

```text
inhere
```

Inside `inhere`, the challenge creates many nested directories containing decoy files of various sizes and formats. A manual traversal would be time-consuming and error-prone, so a targeted search is the appropriate approach.

## Solution

```bash
find . -type f -size 1033c
```

- `-type f` restricts the search to regular files.
- `-size 1033c` matches files whose exact size is 1033 bytes.

Output:

```text
./maybehere07/.file2
```

A single match is returned: a hidden file named `.file2`, nested in the `maybehere07` directory.

```bash
cat ./maybehere07/.file2
```

Output:

```text
pXa26xhMWaC2SvDotA4r9EgZkulOeSBW
```

## Result

| Item | Value |
|------|-------|
| Command that solved the level | `find . -type f -size 1033c` then `cat ./maybehere07/.file2` |
| Next user | `bandit6` |
| Password for `bandit6` | `pXa26xhMWaC2SvDotA4r9EgZkulOeSBW` |

## Why it works

`find` recursively walks the directory tree and filters results based on metadata. Here, the exact file size is the decisive clue, so the file can be identified without manual inspection of every directory. This is much more efficient than repeatedly using `ls` and `cd` across a large decoy tree.

## Lessons learned

- `find . -type f -size <N>c` is the standard method for locating a file of an exact size in bytes.
- Recursive searches are far more efficient than manual directory traversal when several levels of decoy content are involved.
- Hidden files (names beginning with `.`) are common in CTF tasks and can be discovered recursively with `find`.
- When the challenge provides a numerical clue such as an exact file size, that value is usually intended to drive an automated search rather than a manual inspection.

## References

- [OverTheWire Bandit wargame](https://overthewire.org/wargames/bandit/)
- [Bandit Level 5 details](https://overthewire.org/wargames/bandit/bandit5.html)
- `find(1)` manual page — size and type predicates
