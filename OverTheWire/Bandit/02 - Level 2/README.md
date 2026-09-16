# Level 2

| Item | Details |
|------|---------|
| Level | 2 |
| Game | Bandit |
| Difficulty | Beginner |
| Status | Completed |
| Last update | Sep 2026 |

---

## Objective

Log in to `bandit2` and retrieve the password for `bandit3`. This time, the target file name contains spaces, which makes a naive interpretation of the name fail if the exact filename is not read carefully.

## Connection

```bash
ssh bandit2@bandit.labs.overthewire.org -p 2220
```

Password: the credential obtained at the end of Level 1.

## Enumeration

```bash
ls
```

Output:

```text
--spaces in this filename--
```

At first glance, this looks like a file named `spaces in this filename`, but the actual name includes a leading and trailing double dash (`--`). This detail is easy to miss and explains why the early attempts below all failed.

## Failed attempts

```bash
cat "spaces in this filename"
```

```text
cat: 'spaces in this filename': No such file or directory
```

```bash
cat spaces\ in\ this\ filename
```

```text
cat: 'spaces in this filename': No such file or directory
```

Both commands correctly handle the spaces, but they target the wrong filename: they omit the leading and trailing `--` that `ls` actually printed. Because the name starts with `-`, it also risks being interpreted as a command option, similar to the issue seen in Level 1. The correct fix therefore needs to solve both problems at once: the spaces and the leading dashes.

## Solution

```bash
cat "./--spaces in this filename--"
```

- The full filename, `--spaces in this filename--`, is used exactly as displayed by `ls`.
- Double quotes preserve the internal spaces as part of a single argument.
- The `./` prefix prevents the leading `--` from being interpreted as command-line options by `cat`.

Output:

```text
7ZZ2LFrykP2zEyvBl4m3clcL7tGYJPME
```

## Result

| Item | Value |
|------|-------|
| Command that solved the level | `cat "./--spaces in this filename--"` |
| Next user | `bandit3` |
| Password for `bandit3` | `7ZZ2LFrykP2zEyvBl4m3clcL7tGYJPME` |

## Why it works

Two separate shell and CLI quirks are involved:

1. Spaces split arguments. Without quoting, the shell treats `spaces in this filename` as multiple arguments instead of one filename. Quotes group the value back into a single token.
2. A leading `-` may be interpreted as an option. As with Level 1, a filename beginning with `-` may be mistaken for a flag. Prefixing it with `./` forces the program to treat the argument as a path instead of an option.

The key lesson is to always trust the exact output of `ls` rather than assuming the filename layout. A missing `--` is enough to cause a misleading `No such file or directory` error.

## Lessons learned

- Always copy the exact filename shown by `ls` instead of guessing its structure.
- A filename can combine multiple pitfalls at once: spaces and a leading dash.
- Quote the filename to preserve spaces, and use `./` or an absolute path to avoid option parsing issues.
- `ls -b` or `ls -Q` can help expose special characters and ambiguous filenames more clearly when the output is unclear.

## References

- [OverTheWire Bandit wargame](https://overthewire.org/wargames/bandit/)
- [Bandit Level 2 details](https://overthewire.org/wargames/bandit/bandit2.html)
