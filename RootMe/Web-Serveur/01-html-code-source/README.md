# HTML - Code source

`Web-Serveur` • `Very Easy` • `5 pts`

## TL;DR

Inspect HTML source code to find hardcoded password in plain text.

**Flag:** `[REDACTED]`

---

## Challenge Description

> Don't go too far!

**URL:** `http://challenge01.root-me.org/web-serveur/ch1/`

---

## Recon

The page displays a simple login form requesting a password. The URL parameter `?password=password` suggests the application validates credentials client-side.

**Key observation:** Client-side validation = secrets likely exposed in HTML/JavaScript.

---

## Exploitation

### Step 1: View Page Source

**Method 1 - Right-click:**
```
Right-click on page → View Page Source
```

**Method 2 - Keyboard shortcut:**
```
Ctrl+U (Firefox/Chrome)
```

**Method 3 - Developer Tools:**
```
F12 → Elements/Inspector tab
```

---

### Step 2: Analyze HTML Code

**Source code reveals:**
```html
<html>
  <head></head>
  <body>
    <link rel="stylesheet" property="stylesheet" id="s" type="text/css" href="/template/s.css" media="all">
    
    <iframe id="iframe" src="https://www.root-me.org/?page=externe_header"></iframe>
    
    <!--
    Bienvenue sur ce portail,
    Welcome on this portal,
    
    J'espère que vous passerez un agréable moment parmi nous, mais surtout que vous
    repartirez plein de choses dans la tête.
    I hope that you will enjoy your time among us, and above that all you will leave
    with lots of things in the head.
    
    @ très bientot
    See ya
    
    -->
    
    <h1>Login v0.00001</h1>
    
    <form action="" method="post">
      <h4>Mot de passe incorrect / Incorrect password</h4>
      
      <!--
      Je crois que c'est vraiment trop simple là !
      It's really too easy !
      
      password : [REDACTED]
      
      -->
      
      <!-- == $0 -->
    </form>
  </body>
</html>
```

**Password found in HTML comment:** `[REDACTED]`

---

### Step 3: Submit Password

**Navigate to:**
```
http://challenge01.root-me.org/web-serveur/ch1/?[REDACTED]
```

Or enter the password in the form and submit.

**Result:** Challenge validated ✓

---

## Impact & Mitigation

### Real-World Implications

| Vulnerability | Impact |
|---------------|--------|
| **CWE-798** | Use of Hard-coded Credentials |
| **CWE-200** | Exposure of Sensitive Information to Unauthorized Actor |
| **OWASP A01:2021** | Broken Access Control |

**Attack Scenarios:**
1. **Admin panel bypass**: Hardcoded admin passwords found in JS/HTML
2. **API key exposure**: Credentials leaked in client-side code
3. **Authentication bypass**: Client-side validation easily defeated
4. **Source code analysis**: All secrets visible to anyone with "View Source"

**Why this is critical:**
- Client-side code is **always** visible to users
- HTML comments are not security - they're documentation for attackers
- JavaScript obfuscation provides **zero** real protection
- Any "secret" in the browser can be extracted

**Real-world examples:**
- 2019: Telecom company exposed database credentials in JavaScript
- 2020: Government portal leaked admin password in HTML comments
- Countless sites with hardcoded API keys in React/Vue bundles

---

### Secure Implementation

**❌ NEVER do this:**
```html
<!-- Admin password: secret123 -->
<script>
  const API_KEY = "sk_live_51abc123...";
  if (password === "hardcoded_password") {
    // grant access
  }
</script>
```

**✅ DO this instead:**
```javascript
// Client-side: send credentials to server
fetch('/api/login', {
  method: 'POST',
  body: JSON.stringify({ username, password }),
  headers: { 'Content-Type': 'application/json' }
});

// Server-side: validate with bcrypt/Argon2
const bcrypt = require('bcrypt');
const hash = await bcrypt.hash(password, 10);
const match = await bcrypt.compare(inputPassword, storedHash);
```

**Best Practices:**
1. **Server-side validation ONLY** - never trust client-side checks
2. **Hash passwords** with bcrypt/Argon2/scrypt (never plaintext)
3. **Use environment variables** for secrets (`.env` files, not in code)
4. **API keys via backend** - proxy sensitive requests through your server
5. **Code review** - scan for hardcoded credentials before deployment
6. **Secret scanning tools** - GitGuardian, TruffleHog, detect-secrets
7. **Content Security Policy (CSP)** - limit what scripts can execute

---

## Key Takeaways

**Technical Skills:**
- Inspected HTML source code using browser DevTools
- Identified sensitive data in HTML comments
- Understood client-side vs server-side validation

**Security Concepts:**
- Client-side code is always visible and modifiable
- Authentication must happen on the server, not the browser
- HTML comments and JavaScript are not security mechanisms
- Never hardcode credentials in source code

---

## References

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [OWASP: Client-Side Security](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html)
- [OWASP Top 10 A01:2021 - Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [Mozilla: View Source](https://developer.mozilla.org/en-US/docs/Tools/View_source)