# Level 0

| Item | Details |
|------|---------|
| Level | 0 |
| Game | Bandit |
| Difficulty | Beginner |
| Status | Completed |
| Last update | Sep 2026 |

---

## Objective

Log in as `bandit0`, inspect the home directory, and identify the file that contains the password for the next level.

## Connection

```bash
ssh bandit0@bandit.labs.overthewire.org -p 2220
```

## Initial assessment

The first step in Bandit is to inspect the current working directory and determine which file contains the credential needed to progress.

## Steps

### 1. List the files in the current directory

```bash
ls -la
```

This reveals the files present in the user's home directory. In this challenge, the relevant file is clearly visible and contains the information required for the next stage.

### 2. Read the file contents

```bash
cat readme
```

The content of the file contains the credential needed to proceed to the next level.

## Solution

The objective of this level is to locate the correct file and read its contents. The key observation is that the password is stored in a readable file in the home directory.

- `ls -la` helps identify the relevant file.
- `cat readme` reads the file content.
- The recovered credential can then be used to log in to the next account.

## Password for the next level

`6y2kwnwK6grgvwvpvLaa2T1cpFEKOhNR`

## What I learned

- How to connect to a remote Linux environment via SSH.
- How to inspect the contents of a directory with `ls`.
- How to read file contents with `cat`.
- Why local enumeration is the first essential step in CTF and Linux-based exploitation challenges.

## References

- OverTheWire Bandit wargame: https://overthewire.org/wargames/bandit/
- Bandit Level 0 information: https://overthewire.org/wargames/bandit/bandit0.html
- Linux shell fundamentals: `ls`, `cat`, and file inspection commands.

## Notes

This is the first level of the Bandit wargame and is designed to introduce the user to basic Linux navigation and file inspection. The challenge is intentionally simple, but it establishes the workflow used throughout the rest of the game: enumerate, inspect, and extract the next credential.