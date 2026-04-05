# PortSwigger — DOM XSS in innerHTML Sink Using Source location.search

`Web Security Academy` • `Cross-Site Scripting` • `Apprentice`

## TL;DR

The search functionality assigns `location.search` directly to an element's `innerHTML` without any sanitisation. Because `innerHTML` silently blocks `<script>` tags, the payload uses an `<img>` tag with an `onerror` handler — the browser attempts to load a non-existent image, fails, and executes the attached JavaScript, triggering `alert(1)` and solving the lab.

**Lab URL:** `https://0a770097037368b6811e52980008005d.web-security-academy.net/`

---

## Challenge Description

> This lab contains a DOM-based cross-site scripting vulnerability in the search blog functionality. It uses an `innerHTML` assignment, which changes the HTML contents of a `div` element, using data from `location.search`.
>
> To solve this lab, perform a cross-site scripting attack that calls the `alert` function.

**Context:**
- Difficulty: **Apprentice**
- Category: **Cross-Site Scripting — DOM-based**
- Goal: Inject a payload via the URL search parameter that triggers `alert(1)` in the browser

---

## Recon

### Step 1 — Identify the source and sink

Inspecting the page's JavaScript source reveals the vulnerable snippet:

```javascript
function doSearchQuery(query) {
    document.getElementById('searchMessage').innerHTML = query;
}

var query = (new URLSearchParams(window.location.search)).get('search');
if (query) {
    doSearchQuery(query);
}
```

- **Source:** `location.search` — fully attacker-controlled via the URL
- **Sink:** `innerHTML` — writes a raw HTML string into the DOM of a `<div>` element

Unlike the previous `document.write` lab, the input here lands **directly as HTML content inside a div**, not inside an attribute — so no attribute breakout is needed. However, the sink itself introduces a new constraint.

### Step 2 — Understand the innerHTML constraint

The HTML5 specification explicitly defines that **`<script>` tags injected via `innerHTML` are not executed** by the browser. This is a built-in safety behaviour — the following payload does nothing:

```
?search=<script>alert(1)</script>
```

The tag is written into the DOM but never evaluated. A different execution vector is required: an HTML element that triggers JavaScript through an **event handler attribute** rather than a `<script>` block.

---

## Exploitation

### Step 3 — Craft an event-handler payload

The `<img>` tag provides a reliable alternative. When the browser tries to load an image and fails, it fires the `onerror` event. Pointing `src` at a guaranteed-invalid value (`x`) forces the error immediately:

```html
<img src=x onerror=alert(1)>
```

Execution flow:
1. `innerHTML` writes `<img src=x onerror=alert(1)>` into the div
2. The browser attempts to fetch the image at `x` — a relative URL that does not exist
3. The request fails → `onerror` fires → `alert(1)` executes

### Step 4 — Deliver the payload

Entering the payload directly in the search bar:

```
<img src=x onerror=alert(1)>
```

The JS assigns it to `innerHTML`, the image load fails, the error handler executes.

```
✅ Congratulations, you solved the lab!
```

---

## Sink Comparison — document.write vs innerHTML vs script tags

| Sink | `<script>` executes | Attribute breakout needed | Reliable vector |
|---|---|---|---|
| `document.write()` | ✅ Yes | Only if inside an attribute | `<script>alert(1)</script>` |
| `innerHTML` | ❌ No (spec-blocked) | No — input is already HTML content | `<img src=x onerror=...>` |
| `element.textContent` | ❌ No | N/A — output is plain text, not HTML | Not injectable |

---

## Attack Chain Summary

```
/?search=<img src=x onerror=alert(1)>
        ↓
location.search parsed by JS → query = "<img src=x onerror=alert(1)>"
        ↓
document.getElementById('searchMessage').innerHTML = query
        ↓
Browser parses and renders the injected HTML:
  → <img> element created, browser attempts to load src="x"
  → Image load fails (invalid URL)
  → onerror handler fires → alert(1) executes
        ↓
Alert dialog fires → LAB SOLVED ✅
```

---

## Key Takeaways

- **`innerHTML`** is a dangerous sink — it parses and renders arbitrary HTML into the live DOM — but it intentionally does not execute injected `<script>` tags per the HTML5 spec
- When `<script>` is blocked, **event handler attributes** on valid HTML elements (`onerror`, `onload`, `onmouseover`...) are the go-to alternative execution vector
- `<img src=x onerror=...>` is one of the most reliable XSS payloads: no quotes needed around attribute values, `src=x` guarantees an immediate load failure, and `onerror` fires synchronously
- The fix: never assign user-controlled data to `innerHTML` — use `textContent` to insert plain text safely, or `DOMParser` with strict sanitisation if HTML rendering is genuinely required

---

## References

- [PortSwigger — DOM-based XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based)
- [PortSwigger — innerHTML sink](https://portswigger.net/web-security/cross-site-scripting/dom-based#html-injection-sinks)
- [PortSwigger — XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [OWASP — DOM Based XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
- [MDN — innerHTML security considerations](https://developer.mozilla.org/en-US/docs/Web/API/Element/innerHTML#security_considerations)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)