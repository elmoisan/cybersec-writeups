# Level 4

| Item | Details |
|------|---------|
| Level | 4 |
| Game | Bandit |
| Difficulty | Beginner |
| Status | Completed |
| Last update | Sep 2026 |

---

## Objective

Log in to `bandit4` and retrieve the password for `bandit5`. This time, ten candidate files are present in the same directory, and only one of them contains readable human text while the others are decoys in various binary formats.

## Connection

```bash
ssh bandit4@bandit.labs.overthewire.org -p 2220
```

Password: the credential obtained at the end of Level 3.

## Enumeration

```bash
ls
cd inhere
ls
```

Output:

```text
-file00  -file02  -file04  -file06  -file08
-file01  -file03  -file05  -file07  -file09
```

Ten files are present, all named `-fileNN` and all beginning with a leading dash. This is the same filename trap seen in Level 1. A detailed listing confirms they are all owned by `bandit5` and readable by the `bandit4` group:

```bash
ls -l
```

```text
total 40
-rw-r----- 1 bandit5 bandit4 33 Jun 24 14:59 -file00
...
-rw-r----- 1 bandit5 bandit4 33 Jun 24 14:59 -file09
```

All ten files are 33 bytes long, which means the size is not a useful discriminator here.

## Failed attempts

```bash
cat -file00
```

```text
error: unexpected argument '-f' found
```

As in Level 1, `cat` interprets the leading `-` as the start of an option rather than as part of the filename.

```bash
cat file00
```

```text
cat: file00: No such file or directory
```

Dropping the leading dash entirely points to a file that does not exist; the dash is part of the actual filename and cannot be omitted.

## Identifying the real target

With ten similarly named candidates and only one valid password, the next step is to identify the actual content type rather than opening files blindly:

```bash
file ./*
```

Output:

```text
./-file00: data
./-file01: data
./-file02: data
./-file03: data
./-file04: data
./-file05: data
./-file06: OpenPGP Public Key
./-file07: ASCII text
./-file08: data
./-file09: Motorola S-Record; binary data in text format
```

The `file` command inspects the actual content signatures of each file rather than relying on names or extensions. Only `-file07` is identified as `ASCII text`, which makes it the only credible candidate for a plaintext password.

## Solution

```bash
cat ./-file07
```

The `./` prefix prevents the leading dash from being parsed as an option.

Output:

```text
6C7h9GD8M6ai5nr7wo1RonrzFjj9yIrG
```

## Result

| Item | Value |
|------|-------|
| Command that solved the level | `cat ./-file07` |
| Next user | `bandit5` |
| Password for `bandit5` | `6C7h9GD8M6ai5nr7wo1RonrzFjj9yIrG` |

## Why it works

The `file` command reads the actual content signature of each file rather than trusting its name or extension. This is useful when a directory is filled with decoys such as binary blobs, OpenPGP data, and Motorola S-Record payloads. Combined with the `./` prefix to evade the leading-dash trap, this narrows ten visually similar files down to a single plaintext candidate without dumping binary garbage into the terminal.

## Lessons learned

- When multiple files look similar, `file ./*` is a much safer and faster way to identify the genuine target than manually reading each file.
- The leading-dash trap returns here at scale: prefixing with `./` remains the reliable fix.
- File size and naming conventions alone are not enough to distinguish the target; content inspection is more trustworthy.

## References

- [OverTheWire Bandit wargame](https://overthewire.org/wargames/bandit/)
- [Bandit Level 4 details](https://overthewire.org/wargames/bandit/bandit4.html)
