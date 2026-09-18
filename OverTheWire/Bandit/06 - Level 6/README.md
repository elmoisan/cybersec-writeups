# Level 6

| Item | Details |
|------|---------|
| Level | 6 |
| Game | Bandit |
| Difficulty | Beginner |
| Status | Completed |
| Last update | Sep 2026 |

---

## Objective

Log in to `bandit6` and retrieve the password for `bandit7`. This time there is no local directory to search — the target file is located somewhere on the entire filesystem and must be found using ownership and size as filters.

## Connection

```bash
ssh bandit6@bandit.labs.overthewire.org -p 2220
```

Password: the credential obtained at the end of Level 5.

## Enumeration

```bash
ls -a
```

Output:

```text
.  ..  .bash_logout  .bashrc  .profile
```

The home directory is empty of any useful lead — only the default dotfiles are present, and `.bash_logout` is just a standard login-cleanup script with nothing relevant. This confirms the target is not hidden locally: the level description states the file is owned by `bandit7`, belongs to the `bandit6` group, and is exactly 33 bytes, so the search must span the whole filesystem.

## Solution

```bash
find / -user bandit7 -group bandit6 -size 33c 2>/dev/null
```

- `/` — the search starts from the filesystem root, meaning everywhere.
- `-user bandit7` — only files owned by user `bandit7`.
- `-group bandit6` — only files belonging to group `bandit6`.
- `-size 33c` — only files exactly 33 bytes.
- `2>/dev/null` — discards stderr, silencing the large volume of `Permission denied` errors generated when `find` hits directories the current user cannot access.

Output:

```text
/var/lib/dpkg/info/bandit7.password
```

```bash
cat /var/lib/dpkg/info/bandit7.password
```

Output:

```text
Bmnnvf82KzQlfxgAI2d1zYbr1u9pr3E3
```

## Result

| Item | Value |
|---|---|
| Command that solved the level | `find / -user bandit7 -group bandit6 -size 33c 2>/dev/null` then `cat` on the match |
| Next user | `bandit7` |
| Password for `bandit7` | `Bmnnvf82KzQlfxgAI2d1zYbr1u9pr3E3` |

## Why it works

A system-wide search needs criteria specific enough to isolate one file among thousands, so `find` is given three independent filters (owner, group, size) instead of a single broad match. `2>/dev/null` is essential in practice: without it, the huge number of `Permission denied` messages from restricted system directories (`/root`, other users' home directories, `/proc`, etc.) buries the actual result in noise and makes it easy to miss even when the command succeeds.

## Common pitfalls encountered

- **Wrong size on the first pass.** The initial attempt used `-size 1033c` (reused from Level 5's clue) instead of the size actually specified for this level, `33c` — it returned no results until the correct size was used.
- **Trying to `cd` into a file.** After locating `/var/lib/dpkg/info/bandit7.password`, an initial `cd` into that path failed with `Not a directory` — a reminder that `find` returning a path does not tell you whether it is a file or a directory; `cat` (or `ls -l` first) is the correct next step for a file.
- **A stray escape sequence in the terminal** (`cd ^[[200~/path...`) appeared from a paste/bracketed-paste artifact and produced a harmless but confusing error — not a real command, just terminal input noise.

## Lessons learned

- `find / -user X -group Y -size Zc` is the general pattern for locating a file anywhere on disk once its ownership and size are known.
- Always redirect `find`'s stderr (`2>/dev/null`) when searching from `/`, or genuine results get lost in permission-denied spam.
- A file can live far outside a user's home directory (here, inside `/var/lib/dpkg/info/`) — system-wide searches should not assume the target is in an expected location.
- Double-check size and ownership clues against the current level's instructions rather than reusing values from a previous one.

## References

- [OverTheWire Bandit wargame](https://overthewire.org/wargames/bandit/)
- [Bandit Level 6 details](https://overthewire.org/wargames/bandit/bandit6.html)
- `find(1)` manual page — `-user`, `-group`, and `-size` predicates
