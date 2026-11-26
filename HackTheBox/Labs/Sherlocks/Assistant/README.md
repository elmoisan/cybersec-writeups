# HTB Sherlock — "Assistant" (DFIR / Windows PCA Triage)

**Category:** DFIR  
**Difficulty:** Very Easy

---

## Scenario

> We have reason to believe that a QA Engineer had his credentials leaked, as his PC was accessed remotely without authorization. You are provided with PCA logs from the compromised Windows 11 system. As a junior analyst, your senior has asked you to establish a minimal timeline, which can then be filled in by detailed analysis afterwards.

The evidence is a single archive, `Assistant.zip`, containing three files from `C:\Windows\appcompat\pca\` of the compromised host.

```bash
unzip -P hacktheblue Assistant.zip
```

> `hacktheblue` is the standard password of HTB Sherlock archives.

The goal is a minimal timeline of the attacker's activity (tool download, data collection, exfiltration attempt, trace removal) built from a single artifact.

---

## Tooling

- `unzip`, `iconv` — to extract the archive and convert `PcaGeneralDb0.txt` from UTF-16 to UTF-8
- `cat` / `grep` — the files are tiny (a few KB), so reading them in full is enough
- `date` / any calculator — for the time-difference question
- MITRE ATT&CK — to map the observed behaviour to known techniques

---

## Recon: Know Your Evidence

The **Program Compatibility Assistant (PCA)** is a Windows 11 (22H2 and later) component that records executables launched on the system. It is an *evidence of execution* artifact, in the same family as Prefetch and Amcache.

```text
Assistant/C/Windows/appcompat/pca/
├── PcaAppLaunchDic.txt     # chemin|date  -> LAST launch of each executable
├── PcaGeneralDb0.txt       # detailed log (UTF-16 LE), pipe-separated
└── PcaGeneralDb1.txt       # empty
```

Reading `PcaGeneralDb0.txt` requires a conversion first:

```bash
iconv -f UTF-16 -t UTF-8 PcaGeneralDb0.txt
```

Its columns are:

```text
timestamp | status | path | product | company | version | program id | message
```

The `status` column is the key to the file:

| Status | Meaning |
|---|---|
| `0` | Installer failed |
| `2` | Abnormal process exit (the message gives the exit code) |
| `3` | PCA resolve called (compatibility check) |

The two main files answer different questions:

| File | Best used for |
|---|---|
| `PcaAppLaunchDic.txt` | Full path of an executable and its **last** launch time |
| `PcaGeneralDb0.txt` | Failures, exit codes, product name and version |

> **Caveats:** PCA gives no command line and no network information. It proves that a program ran, not what it did. Timestamps are recorded as written in the logs (believed to be UTC; do not convert them for the answers).

---

## Task 1 — Full path of the downloaded archive utility

The attacker needed a way to compress data. Searching both files for an archiver gives 7-Zip.

`PcaAppLaunchDic.txt` holds the full path:

```text
C:\Users\cyberjunkie\Downloads\7z2600-x64.exe|2026-04-08 11:30:37.758
```

`PcaGeneralDb0.txt` shows the same file, but with the path abbreviated by an environment variable:

```text
%USERPROFILE%\Downloads\7z2600-x64.exe | 7-zip | igor pavlov | 26.00
```

The compromised account is **`cyberjunkie`**, so `%USERPROFILE%` expands to `C:\Users\cyberjunkie`.

**Answer:** `C:\Users\cyberjunkie\Downloads\7z2600-x64.exe`

---

## Task 2 — When was 7-Zip successfully installed?

The setup failed on the first try. `PcaGeneralDb0.txt` shows both failure events, 33 ms apart:

```text
2026-04-08 11:30:26.117|2|...\7z2600-x64.exe|7-zip|igor pavlov|26.00|...|Abnormal process exit with code 0x1
2026-04-08 11:30:26.150|0|...\7z2600-x64.exe|7-zip|igor pavlov|26.00|...|Installer failed
```

Then the setup is run again, and the first entry that is not a failure appears:

```text
2026-04-08 11:30:39.242|3|...\7z2600-x64.exe|7-zip|igor pavlov|26.00|...|PCA resolve is called, resolver name: DetectorShim_KernelDriver, result: 0
```

> **Pitfall:** `PcaAppLaunchDic.txt` gives `11:30:37.758` for the same file, which is the time of the last *launch*. The flag expects the `PcaGeneralDb0.txt` entry, at **`11:30:39`**, without milliseconds.

`7zFM.exe` (the 7-Zip graphical interface) appears later in `Program Files`, which confirms that the installation finally worked.

**Answer:** `2026-04-08 11:30:39`

---

## Task 3 — Command-line tool for potential exfiltration

Two minutes after 7-Zip, a second tool is downloaded and run from the `Downloads` folder. `PcaGeneralDb0.txt` provides the product name and the version:

```text
%USERPROFILE%\Downloads\rclone-v1.73.3-windows-amd64\rclone.exe | rclone | https://rclone.org | 1.73.3
```

`PcaAppLaunchDic.txt` gives the full path and the launch time:

```text
C:\Users\cyberjunkie\Downloads\rclone-v1.73.3-windows-amd64\rclone.exe|2026-04-08 11:32:00.303
```

**rclone** is a command-line tool that syncs files with cloud storage providers (Google Drive, S3, Mega, and so on). It is commonly used for exfiltration (MITRE ATT&CK T1567.002).

**Answer:** `rclone v1.73.3`

---

## Task 4 — When was the rclone process killed?

rclone is a CLI tool with no graphical interface. Launching it by double-click opens a console that waits for arguments and does nothing. The attacker realised it, and killed the process.

`PcaGeneralDb0.txt` records the abnormal termination:

```text
2026-04-08 11:32:08.187|2|%USERPROFILE%\Downloads\rclone-v1.73.3-windows-amd64\rclone.exe|rclone|https://rclone.org|1.73.3|...|Abnormal process exit with code 0x1
```

Launch at `11:32:00` (`PcaAppLaunchDic.txt`), exit at `11:32:08`: the process lived about 8 seconds. The following entry (`11:32:08.517`, status `3`) is a PCA resolve event, not the termination.

**Answer:** `2026-04-08 11:32:08`

---

## Task 5 — Start of the data collection

7-Zip is installed, so the next step is to gather and compress files. The 7-Zip graphical file manager is `7zFM.exe`. `PcaAppLaunchDic.txt` gives its launch time:

```text
C:\Program Files\7-Zip\7zFM.exe|2026-04-08 11:37:07.600
```

This is the best available evidence of the start of the collection phase, which matches the wording of the question ("based on the limited evidence we have").

> **False lead:** `C:\Users\cyberjunkie\Desktop\KAPE\gkape.exe` (`12:00:25`) is a data-collection tool too, but it comes **after** the trace-removal phase and it is not the answer for this task.

**Answer:** `2026-04-08 11:37:07`

---

## Task 6 — Duration of the collection before the exfiltration

The question asks for the time between the start of the collection and its conclusion, in the format `***.***` (seconds, three decimals).

- Start of the collection: `11:37:07.600` (`PcaAppLaunchDic.txt`)
- Conclusion of the collection: `11:40:03.043`, the `7zFM.exe` entry in `PcaGeneralDb0.txt`

```text
2026-04-08 11:40:03.043|3|%programfiles%\7-Zip\7zFM.exe|7-zip|igor pavlov|26.00|...|PCA resolve is called, resolver name: DetectorShim_KernelDriver, result: 0
```

The difference:

```text
11:40:03.043 - 11:37:07.600 = 175.443 s
```

Thirteen seconds later, at `11:40:16`, a Windows Terminal is opened (see Task 7), which is consistent with an exfiltration attempt right after the collection.

> **Pitfall:** the flag format requires milliseconds. Rounding to `176` does not fit `***.***`.

**Answer:** `175.443`

---

## Task 7 — Full path of the utility used to delete files

After the Windows Terminal session (`WindowsTerminal.exe`, `11:40:16`), the attacker installs and runs a secure-deletion tool:

```text
C:\Users\cyberjunkie\Downloads\Eraser 6.2.0.2996.exe|2026-04-08 11:42:11.726
C:\Program Files\Eraser\Eraser.exe|2026-04-08 11:43:38.671
```

The first line is the installer. The second is the utility that does the deletion, and it is the one the question asks for.

**Eraser** overwrites files so they cannot be recovered, which removes the traces of the unauthorized tools (MITRE ATT&CK T1070.004).

**Answer:** `C:\Program Files\Eraser\Eraser.exe`

---

## Incident Timeline (2026-04-08, as recorded in the logs)

| Time | Event | Source |
|---|---|---|
| 10:12:30 | `WindowsTerminal.exe` launched | `PcaAppLaunchDic` |
| 11:30:26 | First 7-Zip installer attempt fails (exit code `0x1`) | `PcaGeneralDb0` |
| 11:30:39 | 7-Zip installed (second attempt) | `PcaGeneralDb0` |
| 11:32:00 | `rclone.exe` launched by double-click | `PcaAppLaunchDic` |
| 11:32:08 | rclone killed (abnormal exit, code `0x1`) | `PcaGeneralDb0` |
| 11:37:07 | `7zFM.exe` launched: start of the data collection | `PcaAppLaunchDic` |
| 11:40:03 | End of the collection (175.443 s later) | `PcaGeneralDb0` |
| 11:40:16 | `WindowsTerminal.exe`: probable rclone use via CLI | `PcaAppLaunchDic` |
| 11:42:11 | Eraser installer launched | `PcaAppLaunchDic` |
| 11:43:38 | `Eraser.exe` launched: trace removal | `PcaAppLaunchDic` |
| 12:00:25 | `KAPE\gkape.exe` launched from the Desktop | `PcaAppLaunchDic` |

---

## Mapping to MITRE ATT&CK

| Observed behaviour | Technique |
|---|---|
| Unauthorized RDP access with leaked credentials | T1021.001 — Remote Services: Remote Desktop Protocol, T1078 — Valid Accounts |
| Downloading 7-Zip, rclone and Eraser | T1105 — Ingress Tool Transfer |
| Compressing data with 7-Zip | T1560.001 — Archive Collected Data: Archive via Utility |
| Using rclone to send data to cloud storage | T1567.002 — Exfiltration Over Web Service: Exfiltration to Cloud Storage |
| Running commands in Windows Terminal | T1059 — Command and Scripting Interpreter |
| Securely deleting files with Eraser | T1070.004 — Indicator Removal: File Deletion |

---

## Final Answers

| Task | Answer |
|---|---|
| 1 | `C:\Users\cyberjunkie\Downloads\7z2600-x64.exe` |
| 2 | `2026-04-08 11:30:39` |
| 3 | `rclone v1.73.3` |
| 4 | `2026-04-08 11:32:08` |
| 5 | `2026-04-08 11:37:07` |
| 6 | `175.443` |
| 7 | `C:\Program Files\Eraser\Eraser.exe` |

---

## Initial Assessment and Recommended Next Steps

**Assessment:** the host is **compromised**. Using the leaked credentials of `cyberjunkie`, the attacker installed an archiver, tried to run rclone (first by mistake in graphical mode), collected data with 7-Zip, opened a terminal that probably served to run rclone, and then removed traces with Eraser. Whether data actually left the host cannot be proven from PCA alone.

**Recommended next steps:**

1. **Contain:** isolate the host from the network and disable the compromised account.
2. **Rotate secrets:** reset the QA Engineer's credentials and every secret reachable from this account.
3. **Reduce exposure:** do not expose RDP directly to the Internet; require a VPN and multi-factor authentication.
4. **Find the exfiltration:** analyse network and firewall logs around `11:40`–`11:45`, and look for rclone configuration files (`rclone.conf`) and destination cloud accounts.
5. **Corroborate the timeline:** cross-check with Prefetch, Amcache, Shimcache, UserAssist, RDP logs (Security events 4624/4625, TerminalServices) and the Windows Terminal / PowerShell history.
6. **Recover deleted traces:** Eraser leaves its own artifacts (task list, logs, registry keys) that may show what was overwritten.
7. **Clarify the KAPE run:** `gkape.exe` on the Desktop at `12:00:25` is either the attacker's or an earlier response action, and it should be attributed with the administrators.

---

## Takeaways

- **Two files, two questions.** `PcaAppLaunchDic.txt` gives full paths and the last launch time; `PcaGeneralDb0.txt` gives failures, exit codes, product and version.
- **Read the status column.** `0`, `2` and `3` tell a failed installer, a killed process and a compatibility check apart, which is what let us find the failed 7-Zip attempt and the killed rclone.
- **Match the expected source.** For the same program, the two files give different timestamps (`11:30:37` vs `11:30:39`). When a flag is rejected, try the other file.
- **Expand environment variables.** `%USERPROFILE%` and `%programfiles%` in `PcaGeneralDb0.txt` are not full paths.
- **Mind the format.** `***.***` needs milliseconds: `175.443`, not `176`.
- **Execution is not proof of impact.** PCA shows that rclone ran, not what it sent. A minimal timeline must say so.
- **Order tells the story.** Archiver → exfiltration tool → collection → terminal → eraser is a textbook staging and cleanup sequence.

---

## References

- Hack The Box — Sherlock "Assistant": https://app.hackthebox.com/sherlocks/Assistant
- rclone: https://rclone.org
- Eraser: https://eraser.heidi.ie
- MITRE ATT&CK T1560.001 — Archive via Utility: https://attack.mitre.org/techniques/T1560/001/
- MITRE ATT&CK T1567.002 — Exfiltration to Cloud Storage: https://attack.mitre.org/techniques/T1567/002/
- MITRE ATT&CK T1070.004 — Indicator Removal: File Deletion: https://attack.mitre.org/techniques/T1070/004/
