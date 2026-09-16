# Bandit

`Bandit` is a beginner-friendly wargame focused on Linux shell basics, file inspection, and user-privilege progression.

## Overview

| Item | Details |
|------|---------|
| Game | Bandit |
| Focus | Linux fundamentals, SSH access, shell navigation |
| Status | In progress |
| Last update | Sep 2026 |
| Current level | [04 - Level 4](./04%20-%20Level%204/README.md) |

---

## Goal

Connect through SSH, enumerate the system, and recover the password for the next level.

---

## Connection command

```bash
ssh bandit0@bandit.labs.overthewire.org -p 2220
```

Use the password recovered from the previous level to continue to the next challenge.

---

## Level progression

| Level | Status | Notes |
|-------|--------|-------|
| [00 - Level 0](./00%20-%20Level%200/README.md) | Completed | Initial Linux file enumeration |
| [01 - Level 1](./01%20-%20Level%201/README.md) | Completed | Handling a file named `-` |
| [02 - Level 2](./02%20-%20Level%202/README.md) | Completed | Handling spaces and leading dashes in filenames |
| [03 - Level 3](./03%20-%20Level%203/README.md) | Completed | Hidden files and file-versus-directory checks |
| [04 - Level 4](./04%20-%20Level%204/README.md) | Completed | Identifying the only readable file among decoys |

---

## Documentation format

Each writeup follows a consistent structure using the project template in `LEVEL_TEMPLATE.md` to keep the notes clear and reusable.

---

## Last Updated

📅 **Sep 16, 2026** — Documented Bandit Levels 0 to 4 and refreshed the writeup index.
