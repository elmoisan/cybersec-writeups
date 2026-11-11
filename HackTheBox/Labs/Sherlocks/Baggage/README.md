# HTB Sherlock — "Baggage" (DFIR)

**Category:** DFIR / Sherlock  
**Difficulty:** Very Easy  
**XP reward:** 292

---

## Scenario

> This Sherlock provides players with an opportunity to analyze Shellbag artifacts. Shellbags can be used to find evidence of folder access by a specific user, access to network shares, and navigation of archive file contents. This information can be leveraged during investigations to identify potential data access, data staging, and data exfiltration attempts.

The evidence is a single archive, `Baggage.zip` (about 2 MB), containing the registry artifacts of the compromised user `steve`. The investigation relies on the user's registry hives (in particular `NTUSER.DAT`), where Windows stores Shellbags.

---

## Tooling

- A Shellbags parser (for example Eric Zimmerman's *ShellBags Explorer* or `SBECmd`) to read the Shellbags tree and the timestamps of each entry
- A registry viewer (for example *Registry Explorer*) to check the last write time of the keys directly in `NTUSER.DAT`
- MITRE ATT&CK to map the observed behaviour to techniques

---

## Recon: What Shellbags Are (and Are Not)

Shellbags are registry entries created by Windows Explorer to remember the display settings (view, size, position) of a folder. A side effect is useful to a forensic analyst: **a Shellbag entry exists for every folder a user browsed with Explorer**, even if the folder has since been deleted, the removable drive unplugged, or the network share disconnected.

| Question | What Shellbags can answer |
|---|---|
| Which folders did the user open? | Yes, local folders, network shares, removable drives |
| Was the content of an archive browsed? | Yes, Windows Explorer treats a `.zip` as a folder, so it gets an entry |
| In which order? | Yes, through the tree structure and the key last write times |
| When? | Partly: key last write times, and creation/access times stored in each entry |
| Which files were read or copied? | No. Shellbags only prove navigation, not file content access |

Two limits should be kept in mind throughout the analysis:

- Shellbags prove that a folder **was opened**, not what was done with the files inside it.
- Timestamps in the registry are stored in **UTC**.

---

## Task 1 — Archive downloaded by the compromised account

Browsing the Shellbags tree of `steve`, the `Downloads` folder contains an entry for an archive that was opened **as if it were a folder**:

```text
Downloads\1.zip
```

A `.zip` appearing in the Shellbags means the user (here, the attacker using the account) navigated inside it with Explorer, rather than just downloading it.

**Answer:** `1.zip`

---

## Task 2 — Utility brought in to search for sensitive data

When a ZIP is opened in Explorer, Windows extracts the viewed content to a temporary folder. This leaves a trace under the `Temp` directory:

```text
Temp\Temp1_1.zip\1\Everything-1.4.1.1028.x64.zip
```

This is the content of `1.zip`, extracted temporarily. The file is the 64-bit build of **Everything**, a very fast file-search utility for Windows (it indexes the NTFS file table). It is a legitimate tool, but here it was brought in by the attacker to quickly locate sensitive files on the machine.

**Answer:** `Everything`

---

## Task 3 — VPN folder accessed

The attacker then browsed the file system and looked for files the victim uses day to day. A folder named **OT Station 3 internal VPN** appears in the Shellbags. The last write time of its key gives the moment it was accessed:

```text
2025-09-03 07:31:05 (UTC)
```

**Answer:** `2025-09-03 07:31:05`

---

## Task 4 — Directory containing the victim's passwords

In the `Documents` folder of the user, one directory name shows what it holds:

```text
Documents\OnePassword MasterPass
```

The name suggests the master password of a password manager. Browsing it shows what the attacker was targeting (credentials), though, as noted above, Shellbags do not prove that the files were read.

**Answer:** `OnePassword MasterPass`

---

## Task 5 — Network share accessed

The attacker also reached a network share. In the Shellbags tree it is an entry of type **Network Location**, which stores the UNC path:

```text
\\Prod-ns-2\prodshare
```

**Answer:** `\\Prod-ns-2\prodshare`

---

## Task 6 — Dam construction date

Inside the share, a folder is named after the planned year of the construction:

```text
\\Prod-ns-2\prodshare\Construction 2027
```

The year is read from the folder name. It is not confirmed by any document content, since Shellbags do not store file content.

**Answer:** `2027`

---

## Task 7 — Archive present on the network share

The same folder, `Construction 2027`, contains an archive that the attacker opened as a folder (again, a Shellbag entry for a `.zip`):

```text
prodshare\Construction 2027\Dam Construction Engineer Plans.zip
```

The name points to sensitive engineering data, which makes it a good target for data theft.

**Answer:** `Dam Construction Engineer Plans.zip`

---

## Task 8 — When the network share archive was accessed

The access time is read from the Shellbag entry (key) of that ZIP in the `NTUSER.DAT` of `steve`:

```text
2025-09-03 07:34:04 (UTC)
```

**Answer:** `2025-09-03 07:34:04`

---

## Task 9 — Staging folder

After browsing the sensitive data, the attacker created a folder to gather the files before exfiltration. A new folder appears under `Pictures`, with a creation time of `07:33:16`:

```text
C:\Users\steve\Pictures\a
```

A short, meaningless name in a rarely inspected folder (`Pictures`) is a typical way to keep a staging area discreet.

**Answer:** `C:\Users\steve\Pictures\a`

---

## Task 10 — Exfiltration archive accessed

The staging folder was then compressed to prepare the data for exfiltration. The Shellbag entry for the resulting archive shows when it was accessed:

```text
2025-09-03 07:34:30 (UTC)
```

This is 26 seconds after the network share archive (`07:34:04`), which fits the logic of the attack: the data was collected, staged and compressed within a few minutes.

**Answer:** `2025-09-03 07:34:30`

---

## Attack Timeline (UTC, 2025-09-03)

| Time | Event |
|---|---|
| — | `1.zip` downloaded to `Downloads` and opened as a folder; `Everything` extracted to `Temp` |
| 07:31:05 | Folder `OT Station 3 internal VPN` accessed |
| — | Folder `Documents\OnePassword MasterPass` browsed |
| — | Network share `\\Prod-ns-2\prodshare` opened, folder `Construction 2027` browsed |
| 07:33:16 | Staging folder `C:\Users\steve\Pictures\a` created |
| 07:34:04 | `Dam Construction Engineer Plans.zip` accessed on the share |
| 07:34:30 | Exfiltration archive accessed |

Entries marked "—" have no exact timestamp in the answers above, so only their order in the Shellbags tree is used.

---

## Indicators of Compromise

| Type | Value |
|---|---|
| Compromised account | `steve` |
| Downloaded archive | `Downloads\1.zip` |
| Search utility | `Everything-1.4.1.1028.x64` |
| Temporary extraction path | `Temp\Temp1_1.zip\1\` |
| Network share | `\\Prod-ns-2\prodshare` |
| Targeted archive | `Construction 2027\Dam Construction Engineer Plans.zip` |
| Staging folder | `C:\Users\steve\Pictures\a` |
| Sensitive folders browsed | `OT Station 3 internal VPN`, `Documents\OnePassword MasterPass` |

---

## Mapping to MITRE ATT&CK

| Observed behaviour | Technique |
|---|---|
| Use of the `steve` account | T1078 — Valid Accounts |
| Download of `1.zip` with the `Everything` utility | T1105 — Ingress Tool Transfer |
| Browsing folders and searching for files with `Everything` | T1083 — File and Directory Discovery |
| Access to the `prodshare` network share | T1039 — Data from Network Shared Drive |
| Collection of files from the local machine | T1005 — Data from Local System |
| Folder `Pictures\a` used to gather files | T1074.001 — Data Staged: Local Data Staging |
| Compression of the staging folder | T1560.001 — Archive Collected Data: Archive via Utility |

---

## Final Answers

| Task | Answer |
|---|---|
| 1 | `1.zip` |
| 2 | `Everything` |
| 3 | `2025-09-03 07:31:05` |
| 4 | `OnePassword MasterPass` |
| 5 | `\\Prod-ns-2\prodshare` |
| 6 | `2027` |
| 7 | `Dam Construction Engineer Plans.zip` |
| 8 | `2025-09-03 07:34:04` |
| 9 | `C:\Users\steve\Pictures\a` |
| 10 | `2025-09-03 07:34:30` |

---

## Takeaways

- Shellbags survive the deletion of the folder, the share or the removable drive, which makes them valuable when the attacker cleans up after themselves.
- Opening a ZIP in Explorer leaves two traces: a Shellbag entry for the archive and a temporary extraction under `Temp\Temp1_<name>.zip`.
- Shellbags prove navigation, not file reading or copying. Conclusions about data theft should be backed by other artifacts (MFT, USN journal, SMB logs, proxy or firewall logs).
- Timestamps must be read carefully: the key last write time, the creation time and the access time of an entry do not mean the same thing.
- Browsing a short sequence of sensitive folders (VPN, passwords, a network share, then a staging folder), all within a few minutes, is a strong sign of a human operator looking for data rather than normal user activity.
- Defensive takeaways: restrict access to network shares holding sensitive data, do not store password manager master passwords in plain files, alert on file-search tools such as `Everything` being run from `Temp` or `Downloads`, and monitor the creation of archives in user folders such as `Pictures`.

---

## References

- Hack The Box — Sherlock "Baggage": https://app.hackthebox.com/sherlocks/Baggage
- MITRE ATT&CK T1078 — Valid Accounts: https://attack.mitre.org/techniques/T1078/
- MITRE ATT&CK T1105 — Ingress Tool Transfer: https://attack.mitre.org/techniques/T1105/
- MITRE ATT&CK T1083 — File and Directory Discovery: https://attack.mitre.org/techniques/T1083/
- MITRE ATT&CK T1039 — Data from Network Shared Drive: https://attack.mitre.org/techniques/T1039/
- MITRE ATT&CK T1005 — Data from Local System: https://attack.mitre.org/techniques/T1005/
- MITRE ATT&CK T1074.001 — Local Data Staging: https://attack.mitre.org/techniques/T1074/001/
- MITRE ATT&CK T1560.001 — Archive via Utility: https://attack.mitre.org/techniques/T1560/001/
