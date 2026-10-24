# HTB Starting Point — "Meow" (Linux)

**Category:** Starting Point (Tier 0)  
**Difficulty:** Very Easy  
**OS:** Linux  
**XP reward:** 150

---

## Challenge Description

Meow is the first machine of the Hack The Box Starting Point track. It introduces the basic vocabulary and workflow of a pentest: connecting to the lab through a VPN, checking connectivity, scanning for open ports, identifying a service, and logging in to it.

The machine is spawned as a target reachable through the VPN:

```text
<TARGET_IP>
```

> The IP changes every time the machine is respawned.

---

## Tooling

- `openvpn` — to connect to the HTB lab network
- `ping` — to test connectivity with the target (ICMP echo request)
- `nmap` — to discover open ports and identify services
- `telnet` — to connect to the exposed remote service

---

## Guided Questions (Tasks 1–7)

| Task | Question | Answer |
|------|----------|--------|
| 1 | What does **VM** stand for? | `Virtual Machine` |
| 2 | Tool used to interact with the OS through the command line (console / shell)? | `terminal` |
| 3 | Service used to form the VPN connection into HTB labs? | `openvpn` |
| 4 | Tool used to test the connection with an ICMP echo request? | `ping` |
| 5 | Most common tool for finding open ports on a target? | `nmap` |
| 6 | Service identified on port 23/tcp? | `telnet` |
| 7 | Username able to log in over telnet with a blank password? | `root` |

---

## Recon: Connecting to the Lab

First, connect to the HTB network with the VPN configuration file downloaded from the platform (here, the *EU StartingPoint 2* server):

```bash
sudo openvpn starting_point_<username>.ovpn
```

Once the tunnel is up, check that the target is reachable:

```bash
ping -c 4 <TARGET_IP>
```

```text
64 bytes from <TARGET_IP>: icmp_seq=1 ttl=63 time=...
```

Replies come back, so the target is alive and reachable.

---

## Port Scanning

Next, scan the target with `nmap` to find open ports and identify the services behind them:

```bash
nmap -sC -sV <TARGET_IP>
```

```text
PORT   STATE SERVICE VERSION
23/tcp open  telnet  Linux telnetd
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Only one port is open: **23/tcp**, running **Telnet**.

Telnet is an old protocol used to get a remote command-line session on a machine. It is **unencrypted** (credentials and commands travel in clear text), and it has been replaced by SSH in practice.

---

## Gaining Access

Connect to the service with the `telnet` client:

```bash
telnet <TARGET_IP>
```

```text
Trying <TARGET_IP>...
Connected to <TARGET_IP>.
Escape character is '^]'.

  █  █         ▐▌     ▄█▄ █          ▄▄▄▄
  █▄▄█ ▀▀█ █▀▀ ▐▌▄▀    █  █▀█ █▀█    █▌▄█ ▄▀▀▄ ▀▄▀
  █  █ █▄█ █▄▄ ▐█▀▄    █  █ █ █▄▄    █▌▄█ ▀▄▄▀ █▀█

Meow login:
```

The login prompt is waiting for credentials. Since Task 7 hints that a user can log in with a blank password, try the most obvious privileged account, `root`, and just press **Enter** at the password prompt:

```text
Meow login: root
```

The login succeeds without any password, and we land in a root shell:

```text
root@Meow:~#
```

---

## Getting the Flag

List the content of root's home directory and read the flag:

```bash
ls
cat flag.txt
```

```text
flag.txt  snap
```

```text
HTB{REDACTED}
```

Submit it in the **Submit Flag** field on the platform to own the machine.

---

## Takeaways

- **Telnet is insecure by design.** It sends everything, including usernames and passwords, in clear text. It should be replaced with SSH, and never be exposed to untrusted networks.
- **Blank passwords on privileged accounts are a critical misconfiguration.** Here, `root` had no password at all, so reaching full control of the machine required no exploit, only a login attempt.
- **Always enumerate before attacking.** A simple `nmap` scan was enough to find the only exposed service and understand the attack surface.
- **Default / weak credentials should be the first thing tested** on any exposed login service (`root`, `admin`, `administrator`, blank password, etc.).
- **Hardening checklist:** disable unused services (Telnet), enforce strong passwords on all accounts, disable direct `root` remote login, and restrict exposed ports with a firewall.
