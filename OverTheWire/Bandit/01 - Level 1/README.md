# Level 1

| Item | Details |
|------|---------|
| Level | 1 |
| Game | Bandit |
| Difficulty | Beginner |
| Status | Completed |
| Last update | Sep 2026 |

---

## Objective

Log in to `bandit1` and recover the password stored in a file located in the home directory. The challenge is that the filename itself is a single dash (`-`), which collides with the conventional meaning of `-` in many Unix command-line tools.

## Connection

```bash
ssh bandit1@bandit.labs.overthewire.org -p 2220
```

Password: the credential obtained at the end of Level 0.

## Enumeration

```bash
ls -la
```

Output:

```text
.  ..  .bash_logout  .bashrc  .profile
```

A more detailed listing confirms the file's metadata:

```bash
ls -l
```

```text
total 4
-rw-r----- 1 bandit2 bandit1 33 Jun 24 14:59 -
```

The target file is literally named `-`, and it is owned by `bandit2` while being readable by the `bandit1` group.

## Why the naive approach fails

The obvious attempt is:

```bash
cat -
```

This does not work as expected. In Unix, a bare `-` passed as an argument is conventionally interpreted by many command-line tools as `stdin` rather than as a literal filename. As a result, `cat -` waits for input from the keyboard instead of reading the file.

## Solution

To force the program to interpret `-` as a real filename instead of a reserved argument, prefix it with a relative path that makes it unambiguous:

```bash
cat ./-
```

The `./` prefix tells the shell that the argument is a file in the current directory. The command now receives `./-` as a literal path, not the special token `-`.

Output:

```text
PK8fYLZg2hnHSz83plBL1iEPKdD3QToB
```

An equivalent alternative is to use the absolute path:

```bash
cat /home/bandit1/-
```

## Result

| Item | Value |
|------|-------|
| Command that solved the level | `cat ./-` |
| Next user | `bandit2` |
| Password for `bandit2` | `PK8fYLZg2hnHSz83plBL1iEPKdD3QToB` |

## Why it works

Command-line tools such as `cat`, `grep`, or `rm` follow the POSIX convention that a lone `-` argument often means "read from standard input" or "write to standard output". When a real file is named `-`, this convention creates ambiguity. Prefixing the filename with `./` or using an absolute path removes the ambiguity because the argument no longer matches the reserved token pattern.

## Lessons learned

- Filenames that resemble CLI-special tokens such as `-`, `--`, or hidden names require careful handling.
- `./` and absolute paths are standard methods used to force a tool to treat a filename literally.
- `ls -l` is not only useful for file listing; it also confirms ownership and permissions before access assumptions are made.
- Unexpected command behavior, such as `cat -` hanging, is often diagnostic evidence rather than a random error.

## References

- [OverTheWire Bandit wargame](https://overthewire.org/wargames/bandit/)
- [Bandit Level 1 details](https://overthewire.org/wargames/bandit/bandit1.html)
