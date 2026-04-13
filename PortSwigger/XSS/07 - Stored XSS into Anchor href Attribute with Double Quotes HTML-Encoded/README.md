# PortSwigger — Stored XSS into Anchor `href` Attribute with Double Quotes HTML-Encoded

`Web Security Academy` • `Cross-Site Scripting` • `Apprentice`

## TL;DR

The comment functionality stores and reflects user-supplied input from the **Website** field directly inside the `href` attribute of an anchor tag wrapping the comment author's name. Double quotes are HTML-encoded, preventing attribute breakout. However, the application does not validate the URL scheme, allowing the `javascript:` pseudo-protocol to be injected as a valid `href` value. Any visitor who clicks the author's name executes the injected JavaScript in their browser.

**Lab URL:** `https://0a51008504bd730e8098033900fa0035.web-security-academy.net/`

---

## Challenge Description

> This lab contains a stored cross-site scripting vulnerability in the comment functionality. To solve this lab, submit a comment that calls the `alert` function when the comment author name is clicked.

**Context:**
- Difficulty: **Apprentice**
- Category: **Cross-Site Scripting — Stored**
- Goal: Inject a payload into the comment form that executes `alert()` when the author name is clicked

---

## Recon

### Step 1 — Identify the comment form fields

Navigate to any blog post and scroll to the comment section. The form contains four fields:

| Field | Reflected in the page? |
|---|---|
| Name | ✅ Yes — displayed as the author name |
| Email | ❌ No — not rendered in the HTML |
| Website | ✅ Yes — injected into `href` of the author link |
| Comment | ✅ Yes — displayed as comment body |

### Step 2 — Observe how the Website field is rendered

Post a test comment with `https://example.com` in the Website field and inspect the resulting HTML:

```html
<section class="comment">
  <p>
    <a id="author" href="https://example.com">TestUser</a>
  </p>
  <p>Test comment body</p>
</section>
```

The Website value is placed **directly inside the `href` attribute** of an `<a>` tag. The author's name becomes a clickable hyperlink pointing to whatever URL was submitted.

### Step 3 — Test for quote encoding

Submit a double quote in the Website field:

```
"test
```

Inspect the response:

```html
<a href="&quot;test">TestUser</a>
```

The `"` is encoded to `&quot;` — attribute breakout via quote injection is blocked. The standard `" onmouseover="alert(1)` technique used in reflected attribute XSS will not work here.

### Step 4 — Identify the `javascript:` attack surface

Since the input lands inside a `href` attribute and the application only controls quote encoding, the question becomes: **does the application validate the URL scheme?**

Submit the following in the Website field:

```
javascript:alert(1)
```

Inspect the stored HTML:

```html
<a id="author" href="javascript:alert(1)">TestUser</a>
```

No encoding, no rejection. The `javascript:` scheme is stored and rendered as-is. Clicking the link will execute `alert(1)`.

---

## Understanding the Vulnerability

The `href` attribute of an `<a>` tag accepts more than just `http://` and `https://` URLs. Browsers also support the `javascript:` pseudo-protocol, which executes the expression that follows as JavaScript when the link is activated by the user.

```html
<!-- Standard link — navigates to a URL -->
<a href="https://example.com">Click me</a>

<!-- javascript: pseudo-protocol — executes JS on click -->
<a href="javascript:alert(1)">Click me</a>
```

The application encodes `"` correctly, preventing the attacker from escaping the attribute context. However, it does not sanitise the **content** of the `href` value itself — specifically, it does not block or strip the `javascript:` scheme. This makes the `href` a direct JavaScript execution sink.

| Protection in place | What it blocks | What it does NOT block |
|---|---|---|
| `"` → `&quot;` | Attribute breakout | `javascript:` scheme injection |
| None | — | URL scheme validation |

---

## Exploitation

### The Payload

Enter the following in the **Website** field of the comment form:

```
javascript:alert(1)
```

Fill in the remaining fields with any valid values:

| Field | Value |
|---|---|
| Name | Any (e.g. `attacker`) |
| Email | Any valid format (e.g. `a@a.com`) |
| Website | `javascript:alert(1)` ← payload |
| Comment | Any |

### What is stored in the database and rendered

```html
<a id="author" href="javascript:alert(1)">attacker</a>
```

### Step-by-step

1. Navigate to a blog post on the lab
2. Fill in the comment form with `javascript:alert(1)` in the **Website** field
3. Click **Post Comment**
4. Return to the blog post page
5. Click on the comment author's name
6. `alert(1)` executes → **lab solved** ✅

### Execution Flow

```
Attacker submits Website field: javascript:alert(1)
        ↓
Server stores the value in the database without scheme validation
        ↓
Page renders: <a href="javascript:alert(1)">attacker</a>
        ↓
Any visitor views the blog post — the malicious link is present in the DOM
        ↓
Victim clicks the author name
        ↓
Browser interprets javascript: pseudo-protocol → alert(1) executes
        ↓
LAB SOLVED ✅
```

---

## Stored vs Reflected — Key Difference

| | Reflected XSS | Stored XSS (this lab) |
|---|---|---|
| Persistence | None — payload is in the URL | ✅ Stored in the database |
| Victim requirement | Must click a crafted link | Simply visits the page |
| Impact | Targets one victim at a time | Targets every visitor automatically |
| Delivery | Phishing / link sharing | Passive — no interaction required from the attacker after posting |

---

## Why `javascript:` Works in `href` but Not in Other Attributes

The `javascript:` pseudo-protocol is only dangerous in attributes that the browser treats as **navigation targets** or **resource URLs** — primarily `href` on `<a>` and `<area>`, and `src` on `<iframe>`. In attributes like `value`, `class`, or `title`, the string is treated as plain text and is never interpreted as a URL or executed.

| Attribute | `javascript:` executed on interaction? |
|---|---|
| `<a href="javascript:...">` | ✅ Yes — on click |
| `<iframe src="javascript:...">` | ✅ Yes — on load |
| `<input value="javascript:...">` | ❌ No — plain text |
| `<img src="javascript:...">` | ❌ No — modern browsers block it |

---

## Key Takeaways

- **Encoding quotes is not enough** — when user input is placed inside a `href` attribute, the application must also validate the URL scheme, not just prevent attribute breakout
- **`javascript:` is a browser-native code execution primitive** — any `href` that accepts arbitrary user input without scheme validation is a stored XSS sink
- **Stored XSS is significantly more dangerous than reflected XSS** — the payload persists and executes for every subsequent visitor without any additional attacker interaction
- **The fix:** validate that the URL scheme is `http://` or `https://` before storing or rendering any user-supplied URL. Use a strict allowlist: `if (!url.startsWith('http://') && !url.startsWith('https://')) reject()`. A well-configured Content Security Policy with `script-src` can also serve as a defence-in-depth layer

---

## References

- [PortSwigger — Stored XSS](https://portswigger.net/web-security/cross-site-scripting/stored)
- [PortSwigger — XSS into HTML attributes](https://portswigger.net/web-security/cross-site-scripting/contexts#xss-into-html-tag-attributes)
- [PortSwigger — XSS in the `href` attribute](https://portswigger.net/web-security/cross-site-scripting/contexts#xss-in-the-href-attribute)
- [PortSwigger — XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [OWASP — XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [MDN — javascript: URLs](https://developer.mozilla.org/en-US/docs/Web/URI/Schemes/javascript)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)