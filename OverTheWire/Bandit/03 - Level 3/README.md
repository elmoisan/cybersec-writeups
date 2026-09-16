# Level 3

| Item | Details |
|------|---------|
| Level | 3 |
| Game | Bandit |
| Difficulty | Beginner |
| Status | Completed |
| Last update | Sep 2026 |

---

## Objective

Log in to `bandit3` and retrieve the password for `bandit4`. The password file is hidden inside a subdirectory and uses a name that resembles a directory structure, but it is in fact a regular file.

## Connection

```bash
ssh bandit3@bandit.labs.overthewire.org -p 2220
```

Password: the credential obtained at the end of Level 2.

## Enumeration

```bash
ls
```

Output:

```text
inhere
```

A single subdirectory called `inhere` is present. Moving into it:

```bash
cd inhere
ls
```

The directory appears empty when hidden entries are not shown. This is the first clue that something may be hidden inside.

```bash
ls -a
```

Output:

```text
.  ..  ...Hiding-From-You
```

A hidden entry named `...Hiding-From-You` appears. The name starts with three dots (`...`), which is easy to misread as the parent directory entry `..` plus some extra text.

## Failed attempts

```bash
cd .../Hiding-From-You
```

```text
-bash: cd: .../Hiding-From-You: No such file or directory
```

```bash
cd Hiding-From-You
```

```text
-bash: cd: Hiding-From-You: No such file or directory
```

Both attempts assume that the hidden entry is a directory and try to navigate into it. Both fail because the entry is not a directory at all.

## Solution

```bash
cat ...Hiding-From-You
```

By treating the object as a regular file and using its exact name, the content can be read directly.

Output:

```text
xzTXq1rDJQVVAzdv5cHq1TQytTWufAMq
```

## Result

| Item | Value |
|------|-------|
| Command that solved the level | `cat ...Hiding-From-You` |
| Next user | `bandit4` |
| Password for `bandit4` | `xzTXq1rDJQVVAzdv5cHq1TQytTWufAMq` |

## Why it works

`ls` hides any entry beginning with a dot by default. This is how Unix marks hidden files. The name `...Hiding-From-You` is a single regular file, not a directory, even though it begins with dots. The leading dots are an obfuscation trick, not a path component. Attempting to `cd` into it fails because `cd` only works for directories, while the correct response is to inspect the file with a reading command such as `cat`.

## Lessons learned

- `ls -a` is essential whenever a directory appears empty or suspiciously bare.
- A leading dot or three-dot prefix does not imply a directory; it may simply be a hidden file.
- Do not over-interpret dot-based names as path separators; `...Hiding-From-You` is a literal filename, not `..` followed by another path.
- When `cd` fails on a file that clearly exists, the correct next step is usually to inspect the file rather than assume it is a directory.

## References

- [OverTheWire Bandit wargame](https://overthewire.org/wargames/bandit/)
- [Bandit Level 3 details](https://overthewire.org/wargames/bandit/bandit3.html)
