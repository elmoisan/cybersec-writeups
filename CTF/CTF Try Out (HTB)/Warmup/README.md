# HTB CTF Platform — "Welcome to CTF" (Warmup)

**Category:** Warmup  
**Difficulty:** Very Easy

---

## Challenge Description

> Welcome to your first HTB Challenge on the CTF Platform! Click the Spawn Docker button to launch your challenge, and grab the provided IP to start your hacking journey.

The challenge gives no files, only a Docker instance that is spawned from the platform and exposed as an `IP:PORT` pair:

```text
154.57.164.69:43679
```

> The IP and port change every time the instance is respawned, so yours will differ.

---

## Tooling

Nothing special is needed. Any tool that can talk to a TCP port or an HTTP server works:

- `curl` — to send an HTTP request and read the raw response
- `nc` (netcat) — to check what a service answers on a raw TCP connection
- a web browser — to view the page rendered

Docker challenges on the CTF platform are reachable directly over the Internet, so **no VPN is required**.

---

## Connecting to the Instance

When the service type is unknown, the first step is to find out what is listening. A raw TCP connection is a quick test:

```bash
nc 154.57.164.69 43679
```

Since this is a warmup, a web server is the most likely candidate, so a plain HTTP request is the natural next try. Using `curl -i` also prints the response headers, which reveal the technology behind the service:

```bash
curl -i http://154.57.164.69:43679
```

```text
HTTP/1.1 200 OK
Server: Werkzeug/3.0.2 Python/3.12.3
Date: Thu, 22 Oct 2026 20:58:31 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 2451
Connection: close
```

The `Server` header shows a **Flask** application (Werkzeug is the WSGI toolkit behind Flask) running on Python 3.12. The response is `200 OK`, so the page can be read straight away.

---

## Finding the Flag

The body of the response is a short HTML page titled **Onboarding**, styled with Bootstrap and a cyberpunk theme. The interesting part is the content section at the bottom:

```html
<div class="profile-details">
    <h3>Well Done!</h3>
    <p>Congratulations, you've got your first flag. Please copy and paste your flag onto the platform: HTB{onboard1ng_fl4g}.</p>
</div>
```

The flag is printed in clear text in the page, no exploitation, parsing or decoding required. Opening the URL in a browser shows the same message under the "Well Done!" heading.

---

## Flag

```text
HTB{REDACTED}
```

Copy it into the challenge page on the platform to validate the challenge.

---

## Troubleshooting

- **No response or connection refused:** the instance has probably expired. Docker instances are shut down after a while, so respawn it from the challenge page and use the **new** IP and port.
- **No `nc` on Windows:** use WSL, `ncat` (installed with Nmap), or PowerShell with `Test-NetConnection 154.57.164.69 -Port 43679`.
- **Port blocked:** some corporate or school networks filter high ports. Try from another network, for example a mobile hotspot.

---

## Takeaways

- The first step on any Docker challenge is **service discovery**: find out whether the port speaks raw TCP or HTTP before doing anything else.
- `curl -i` is a quick way to get both the headers and the body. Response headers such as `Server: Werkzeug/... Python/...` tell you the stack (here Flask), which is useful context for harder web challenges.
- Always read the page itself, including the source code, comments and any hidden elements. In this warmup the flag is on the page, but in harder challenges the same habit leads to hidden endpoints, comments and leaked information.
- Flags on HTB follow the `HTB{...}` format and are submitted on the challenge page of the platform.
