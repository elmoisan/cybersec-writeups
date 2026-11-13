# HTB Sherlock — "PhantomRing" (Malware Analysis)

**Category:** Malware Analysis
**Difficulty:** Very Easy

---

## Scenario

> A suspicious ELF binary was recovered from `/var/tmp` during a routine threat hunting operation. It is attempting to establish outbound network connections and appears consistent with a post-exploitation agent. The goal is to perform static analysis, extract indicators of compromise, and determine how the malware operates and what it is trying to hide.

The evidence is a single archive, `PhantomRing.zip`, containing the malicious ELF 64-bit binary `agent`.

```bash
unzip PhantomRing.zip
```

No execution is required for this analysis; the artifact is investigated safely by reading its strings and disassembly.

---

## Tooling

- `strings` — to extract readable strings and identify capabilities
- `sha256sum` — to generate a unique file fingerprint for the IOC set
- `Ghidra` — to inspect the decompiled code and recover hardcoded values such as ports, sleep delays, and command handlers
- MITRE ATT&CK — to map the observed behaviour to known techniques

---

## Recon: A Different Kind of Evidence

Unlike log-based Sherlocks, this challenge is based on a **static malware triage**. The binary itself is the evidence, and the first step is to answer a simple question:

> what does the malware do before it ever touches a network?

Running `strings agent` yields the first map of capabilities:

```text
Networking: socket, connect, htons, inet_pton, 192.168.56.1

Discovery: /var/run/utmp, /proc/net/tcp, /proc, /dev/pts, /usr/bin

Evasion: io_uring_*, /sys/fs/bpf, /sys/kernel/debug/tracing/*

Commands: get, recv, users, netstat, kick, privesc, sdestruct, killbpf, exit
```

Several things stand out immediately:

- the malware hardcodes a C2 IP address;
- it interacts with Linux system directories such as `/var/run`, `/proc`, and `/usr/bin`;
- it contains references to `io_uring` and kernel tracing paths, which strongly suggests defense evasion and stealth behavior.

This is enough to orient the investigation before we even open the decompiler.

---

## Task 1 — SHA256 hash of the malicious binary

The first IOC is the binary hash itself. A stable file fingerprint is useful for enriching threat intel, feeding EDR detections, and comparing the sample with known malware families.

```bash
sha256sum agent
```

**Answer:** `2d7b1b2178f76c26893b2a56cbf9b36700235259e76b893d53817d5b66b634a5`

---

## Task 2 — IP address hardcoded for C2

The easiest IOC to read is the hardcoded command-and-control IP. It appears directly in the binary as a readable string.

```text
192.168.56.1
```

**Answer:** `192.168.56.1`

---

## Task 3 — Port used for C2 communication

The port is not stored as a string, so it is not visible in `strings` output. It appears in the networking setup in the decompiled code.

```c
uStack_10106 = htons(0x115d);
inet_pton(2, "192.168.56.1", auStack_10104);
```

The value passed to `htons()` is `0x115d`. Converting that to decimal gives:

```text
0x115d = 4445
```

**Answer:** `4445`

---

## Task 4 — Reconnect delay

The malware is designed to keep retrying after failed C2 connections. Ghidra reveals a `sleep()` call near the failure handling code.

```c
sleep(0x78);
```

The value `0x78` is decimal `120`, so the malware waits 120 seconds before reconnecting.

**Answer:** `120`

---

## Task 5 — Number of supported commands

The static analysis reveals the command parser in `process_cmd`. This is the heart of the agent’s C2 interface. Although `strings` shows a subset of the command names, the full set is larger than the obvious ones.

The valid handlers include:

- `get`
- `recv`
- `users`
- `ss` / `netstat` (same handler)
- `ps` (hidden in `strings` because of the name length)
- `me` (also hidden)
- `kick`
- `privesc`
- `sdestruct`
- `killbpf`
- `exit`

The fallback message is not a real command, so it is excluded from the count.

**Answer:** `11`

---

## Task 6 — Abused Linux kernel interface

The most striking implementation detail is the use of `io_uring_*` symbols. The runtime uses `liburing.so.2`, which points to a user-space interface to the kernel’s asynchronous I/O subsystem.

`io_uring` is a valuable red flag because it can be abused to perform I/O in ways that bypass some traditional syscall-based EDR hooks. It is a classic stealth mechanism in Linux malware.

**Answer:** `io_uring`

---

## Task 7 — Enumerating logged-in users

The malware references `/var/run/utmp`, which is the Linux file used to track active user sessions. This is a common discovery primitive for determining who is logged in to the host.

**Answer:** `/var/run/utmp`

---

## Task 8 — Directory scanned for SUID binaries

The malware is looking for privilege-escalation opportunities. One of the obvious strings is the directory it scans for SUID-capable binaries.

```text
/usr/bin
```

This is the standard location used for userland binaries, and SUID files in that directory are a classic target for local privilege escalation.

**Answer:** `/usr/bin`

---

## Task 9 — Identifying eBPF security tools

The binary is also trying to evade modern endpoint controls that rely on eBPF. The strings show a marker that is specifically associated with BPF maps:

```text
anon_inode:bpf-map
```

That is a strong clue that the malware is scanning for eBPF-backed processes or security tooling in memory, then trying to suppress or neutralise them.

**Answer:** `anon_inode:bpf-map`

---

## Task 10 — Disabling tracing

The final evasion step in the challenge is the attempt to disable tracing on the host. The binary references the tracing control file in `/sys/kernel/debug/tracing/`.

```text
/sys/kernel/debug/tracing/tracing_on
```

This is the first switch used to disable ftrace, which is a common kernel tracing facility used by defenders.

**Answer:** `/sys/kernel/debug/tracing/tracing_on`

---

## Task 11 — Path for self-destruction

To delete itself, the agent needs to find its own executable on disk. The binary uses the standard procfs symlink that points to the running process image:

```text
/proc/self/exe
```

This is a common anti-forensics technique used by malware to remove its own footprint from the system.

**Answer:** `/proc/self/exe`

---

## Task 12 — Command triggering self-destruction

The command parser includes a special destructive routine. In Ghidra, the comparison is explicit:

```c
iVar1 = strcmp(param_3, "sdestruct");
```

The malware triggers its self-deletion path when it receives this command.

**Answer:** `sdestruct`

---

## Mapping to MITRE ATT&CK

| Observed behaviour | Technique |
|---|---|
| Abuse of `io_uring` and killing eBPF processes | T1562.001 — Impair Defenses: Disable or Modify Tools |
| Reading `/usr/bin` for SUID binaries | T1548.001 — Abuse Elevation Control Mechanism: Setuid and Setgid |
| Reading `/var/run/utmp` | T1033 — System Owner/User Discovery |
| Reading `/proc/net/tcp` | T1049 — System Network Connections Discovery |
| Using `io_uring` for network/file operations | T1055 — Process Injection (or T1562.001 for evasion) |
| Self-deletion via `/proc/self/exe` | T1070.004 — Indicator Removal: File Deletion |

---

## Final Answers

| Task | Answer |
|---|---|
| 1 | `2d7b1b2178f76c26893b2a56cbf9b36700235259e76b893d53817d5b66b634a5` |
| 2 | `192.168.56.1` |
| 3 | `4445` |
| 4 | `120` |
| 5 | `11` |
| 6 | `io_uring` |
| 7 | `/var/run/utmp` |
| 8 | `/usr/bin` |
| 9 | `anon_inode:bpf-map` |
| 10 | `/sys/kernel/debug/tracing/tracing_on` |
| 11 | `/proc/self/exe` |
| 12 | `sdestruct` |

---

## Takeaways

- `strings` is a useful starting point, but it is not sufficient on its own. In Task 5, the command set is larger than the apparent subset visible in the raw strings output.
- Ghidra is essential for hardcoded values. Ports, sleep timers, and addresses are often hidden in the decompiled logic rather than presented as plain strings.
- `io_uring` is a major warning sign. If a Linux binary imports `liburing`, it is likely using a stealthier I/O path that may bypass traditional syscall monitoring.
- Defense evasion is layered. The malware does more than hide; it looks for eBPF tooling and disables tracing to reduce visibility.
- Anti-forensics is intentional. The agent is built to delete itself (`/proc/self/exe` + `sdestruct`) and reduce the amount of evidence available to responders.

---

## References

- Hack The Box — Sherlock "PhantomRing": https://app.hackthebox.com/sherlocks/PhantomRing
- MITRE ATT&CK T1562.001 — Impair Defenses: Disable or Modify Tools: https://attack.mitre.org/techniques/T1562/001/
- MITRE ATT&CK T1548.001 — Abuse Elevation Control Mechanism: Setuid and Setgid: https://attack.mitre.org/techniques/T1548/001/
- MITRE ATT&CK T1033 — System Owner/User Discovery: https://attack.mitre.org/techniques/T1033/
- MITRE ATT&CK T1049 — System Network Connections Discovery: https://attack.mitre.org/techniques/T1049/
- MITRE ATT&CK T1055 — Process Injection: https://attack.mitre.org/techniques/T1055/
- MITRE ATT&CK T1070.004 — Indicator Removal: File Deletion: https://attack.mitre.org/techniques/T1070/004/
- Linux `io_uring` overview: https://github.com/axboe/liburing
- Linux procfs documentation: https://man7.org/linux/man-pages/man5/proc.5.html
