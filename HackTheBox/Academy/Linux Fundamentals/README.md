# Linux Fundamentals

HTB Academy • Linux • Module

---

## TL;DR

Completed HTB Academy's **Linux Fundamentals** module: Linux structure, shell usage, filesystem navigation, working with files and directories, Linux administration, service management, and permissions management. Practiced on an Ubuntu target (`ACADEMY-NIXFUND`) over SSH, reached through the HTB Academy VPN from a Pwnbox and from a local Ubuntu VM.

**Status:** module completed ✅ — answers and flags are not published here, per HTB's rules. This write-up documents methodology, not solutions.

---

## Module Description

> This module covers the fundamentals required to work comfortably with the Linux operating system and shell.

**Module Summary**

Linux is an indispensable tool and system in the field of cybersecurity. Many servers run on Linux and offer a wide range of possibilities for offensive security practitioners, network defenders, and systems administrators. This module covers the essentials for starting with the Linux operating system and terminal.

In this module, the following was covered:

- Linux structure
- Using the shell
- Navigating the Linux operating system
- Working with files and directories
- Linux administration
- Service management
- Permissions management

`CREST CPSA/CRT`-related Sections: all sections

---

**Target:** `ACADEMY-NIXFUND` (Ubuntu), accessed via SSH over the HTB Academy VPN
**Attacking hosts:** HTB Pwnbox and a local Ubuntu 24.04 VM (`Trinity`)

---

## Linux Structure

Reviewed the standard Linux directory hierarchy (`/etc`, `/var`, `/home`, `/usr`, ...) and what inode numbers represent — a file's unique identifier on the filesystem, independent of its name or path.

```bash
ls -i /etc/sudoers        # inode number of a specific file
lsblk                     # disks, partitions, and loop devices
```

---

## Using the Shell

Worked hands-on in bash: command history, redirections, and piping output between tools.

```bash
echo $SHELL                      # confirm the active shell
ls -la ~ | grep -i history       # locate the shell's history file
```

Redirecting `stderr` (`2>/dev/null`) came up constantly once searches moved to the whole filesystem — most of the noise from an unprivileged search is permission errors, not useful output.

---

## Navigating the Linux Operating System

Combined directory listing, sorting, and filtering to answer questions about specific files without browsing manually.

```bash
ls -la ~                  # hidden files (dotfiles)
ls -lat /var/backups      # sort by modification time, most recent first
find / -type f -name "*.conf" -newermt 2020-03-03 -size +25k -size -28k 2>/dev/null
```

`find`'s type/name/size/time filters are meant to be combined in one call rather than post-filtered with multiple pipes — it's both faster and less error-prone on a large filesystem.

---

## Working with Files and Directories

Used `find`, `which`, and related tools to locate files and binaries by name, extension, or metadata.

```bash
find / -type f -name "*.bak" 2>/dev/null | wc -l   # count files by extension
which xxd                                          # full path of a binary
```

---

## Linux Administration

Covered package management and basic user/account administration.

```bash
dpkg -l | grep -c '^ii'          # actually-installed packages only
dpkg --get-selections | wc -l    # also counts residual-config ("rc") entries — inflates the count

useradd -m newuser               # -m / --create-home
usermod --lock newuser           # long form of -L
su --command 'whoami' newuser    # long form of -c
```

The gap between the two package-counting commands is the useful detail: `dpkg --get-selections` includes packages that were removed but left configuration behind, so it overcounts what's truly installed.

---

## Service Management

Used `systemctl` and `ps` to inspect what's running on the system and how a given service is configured.

```bash
systemctl list-units --type=service --all | grep -i <keyword>
systemctl show <unit> --property=Type,LoadState,FragmentPath
ps aux | grep -i proftpd
```

`systemctl show` on a unit that isn't actually present on the box returns empty fields rather than an error — `LoadState=not-found` is the tell that the unit doesn't exist there, meaning the answer has to come from the service's documented/default configuration instead of the live system.

Also set up minimal local web servers as a lightweight way to serve/transfer files:

```bash
npx http-server -p 8080     # npm-based static server, short port flag
php -S 127.0.0.1:8080       # PHP's built-in server, bound to localhost only
```

Binding to `0.0.0.0` (the `http-server` default) exposes the served directory to the whole LAN/VPN; binding explicitly to `127.0.0.1` restricts it to the local machine — worth remembering any time a one-off server is spun up.

---

## Permissions Management

Reviewed file and directory permission basics (owner/group/other, read/write/execute) and how they interact with service accounts — e.g. confirming which user a running daemon operates as, and what that implies for the files it can access.

```bash
ps -eo user,pid,comm | grep -i proftpd   # user context of a running service
ls -la <path>                            # inspect owner, group, and mode bits
```

---

## Networking (supporting topic)

Basic enumeration of listening services was used throughout to connect the service-management and permissions sections to what's actually exposed on the network.

```bash
ss -tuln4 | awk '$5 ~ /^0\.0\.0\.0:/'   # listening on all interfaces, not localhost, IPv4 only
```

Filtering the local-address column directly (rather than a naive `grep 0.0.0.0`) matters because the peer-address column also prints `0.0.0.0:*` on every line, including localhost-only services.

---

## Key Takeaways

**Technical Skills**
- Reflexively checking *which host* a command runs on (`whoami`/`hostname`/prompt) before trusting its output — Pwnbox, target, and local VM gave different answers to the same command
- Combining `find`'s filters (type, name, size, time) instead of post-filtering with multiple pipes
- Distinguishing a package manager's "installed" from "ever selected/configured" states
- Reading `systemctl show`'s `LoadState` to tell a missing unit from a real one before trusting its other fields
- Confirming VPN and SSH connectivity (`tun0`, routes, `nc -vz`) before assuming a target is unreachable

**Linux/Sysadmin Concepts**
- Inode numbers identify a file independently of its name or path
- A service's running user and its permissions determine its real attack surface, not just whether it's "running"
- A tool's *default* network behavior (e.g. binding to all interfaces) is a visible, documented trade-off between convenience and exposure
