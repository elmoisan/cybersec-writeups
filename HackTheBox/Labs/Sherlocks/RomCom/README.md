# HTB Sherlock — "RomCom" (DFIR / NTFS Triage)

**Category:** DFIR / Threat Intelligence  
**Difficulty:** Very Easy

---

## Scenario

> Susan works at the Research Lab in Forela International Hospital. A Microsoft Defender alert was received from her computer, and she also mentioned that while extracting a document from the received file, she received tons of errors, but the document opened just fine. According to the latest threat intel feeds, WinRAR is being exploited in the wild to gain initial access into networks, and WinRAR is one of the software programs the staff uses. You are a threat intelligence analyst with some background in DFIR. You have been provided a lightweight triage image to kick off the investigation while the SOC team sweeps the environment to find other attack indicators.

The evidence is a single archive, `RomCom.zip`, containing one file: a KAPE-style triage image in VHDX format.

```bash
unzip -P hacktheblue RomCom.zip
# -> 2025-09-02T083211_pathology_department_incidentalert.vhdx  (~306 MB)
```

> `hacktheblue` is the standard password of HTB Sherlock archives.

The goal is to rebuild, from file-system metadata only, how a booby-trapped RAR archive dropped a decoy document, a backdoor and a persistence shortcut on Susan's machine.

---

## Tooling

- `unzip` — to extract the archive
- Python with `dissect.target` / `dissect.ntfs` — to open the VHDX and read the NTFS volume without mounting it
- A small custom parser for `$MFT` and for the USN journal (`$UsnJrnl:$J`, USN_RECORD_V2)
- (Alternative) `MFTECmd` + Timeline Explorer for the same parsing on a Windows analysis box
- MITRE ATT&CK — to map the observed behaviour to known techniques

```bash
pip install dissect.target
target-info 2025-09-02T083211_pathology_department_incidentalert.vhdx
```

---

## Recon: Know Your Evidence

The VHDX holds a single NTFS volume with a very light triage: only the file-system metadata was collected, not the file contents.

```text
/
├── 2025-09-02T08_32_11_5202830_CopyLog.csv   # KAPE copy log (what was collected, SHA1, timestamps)
└── C/
    ├── $MFT                                  # Master File Table (~143 MB)
    └── $Extend/
        ├── $J                                # USN change journal (~35 MB)
        └── $Max
```

`CopyLog.csv` confirms the collection ran at `2025-09-02 08:32:16 UTC` and that the journal covers about 24 hours (2025-09-01 08:47 -> 2025-09-02 08:32).

The two artifacts answer different questions:

| Artifact | Best used for |
|---|---|
| `$MFT` | Full path of a file, `$STANDARD_INFORMATION` timestamps (created / modified / MFT change / last access) |
| `$UsnJrnl:$J` | Ordered sequence of events (`FILE_CREATE`, `DATA_EXTEND`, `OBJECT_ID_CHANGE`, `RENAME_NEW`, `CLOSE`...) with a precise timestamp |

Useful USN reasons for this case:

| Reason | What it tells us |
|---|---|
| `FILE_CREATE` | The file appeared on disk (copy, download or extraction) |
| `DATA_EXTEND` | Content was written |
| `OBJECT_ID_CHANGE` | Typical side effect of a file being **opened** through the shell (link tracking) |
| `FILE_CREATE` on a `.lnk` in `...\Windows\Recent\` | Windows records that the user opened a file |

> **Caveats:**
> - A standalone `$MFT` has no parent volume, so full paths must be rebuilt by hand from each record's `$FILE_NAME` parent reference.
> - Timestamps are UTC. Do not convert them for the answers.
> - File contents are not in the triage: the `.lnk` target and the backdoor itself cannot be inspected.
> - The `$STANDARD_INFORMATION` *modified* time of the RAR (`14:54:54`) is the archive's original mtime preserved by the copy, **not** an event on this host. Do not use it.

---

## Task 1 — CVE exploited by RomCom in 2025

The scenario points to WinRAR being exploited in the wild for initial access. The vulnerability exploited by the RomCom group (discovered by ESET in August 2025) is **CVE-2025-8088**, fixed in WinRAR 7.13.

**Answer:** `CVE-2025-8088`

---

## Task 2 — Nature of the vulnerability

CVE-2025-8088 is a **path traversal** flaw in the Windows versions of WinRAR. A crafted archive hides payloads in NTFS **Alternate Data Streams** whose names contain `..\` sequences. When the archive is opened or extracted, WinRAR writes those payloads outside the destination folder, for example in `AppData\Local` or in the `Startup` folder.

It also explains Susan's symptoms: WinRAR throws many errors on the malicious stream entries, while the legitimate decoy document extracts and opens normally.

**Answer:** `Path Traversal`

---

## Task 3 — Name of the malicious archive

Searching the rebuilt MFT paths for `.rar` returns two records:

```text
117118  Users\susan\AppData\Local\Temp\vmware-susan\VMwareDnD\9775f068\Pathology-Department-Research-Records.rar
117119  Users\susan\Documents\Pathology-Department-Research-Records.rar
```

The `VMwareDnD` folder is VMware's drag-and-drop staging area: the file was dragged from the host into the VM, then ended up in Susan's `Documents` folder.

**Answer:** `Pathology-Department-Research-Records.rar`

---

## Task 4 — When was the archive created on disk?

The USN journal shows the creation of both copies within 80 ms:

```text
2025-09-02 08:13:50.440310  117118  Pathology-Department-Research-Records.rar  FILE_CREATE   (VMwareDnD temp)
2025-09-02 08:13:50.519082  117119  Pathology-Department-Research-Records.rar  FILE_CREATE   (Documents)
```

The `$STANDARD_INFORMATION` creation time of the file in `Documents` matches: `08:13:50.519082`.

**Answer:** `2025-09-02 08:13:50`

---

## Task 5 — When was the archive opened?

About 14 seconds after the copy, two things happen in the same instant:

```text
2025-09-02 08:14:04.980743  117119  Pathology-Department-Research-Records.rar  OBJECT_ID_CHANGE
2025-09-02 08:14:04.996427  117123  Pathology-Department-Research-Records.lnk  FILE_CREATE   (Recent)
```

The `.lnk` file created in `Recent` is the Windows record of "the user opened this file". It is immediately followed by WinRAR starting up for the first time for this profile (`AppData\Roaming\WinRAR\version.dat` at `08:14:05.027`) and a burst of `WinRAR.exe.WebView2` files in `AppData\Local\Temp`.

**Answer:** `2025-09-02 08:14:04`

---

## Task 6 — Name of the decoy document

Right after the archive opens, a PDF appears in Susan's `Documents` folder:

```text
2025-09-02 08:14:18.793693  117403  Users\susan\Documents\Genotyping_Results_B57_Positive.pdf  FILE_CREATE
```

The name looks like a legitimate research result for a hospital lab, which is the point: it is meant to keep Susan busy while the real payload is dropped.

**Answer:** `Genotyping_Results_B57_Positive.pdf`

---

## Task 7 — The actual backdoor

Within the same 100 ms window as the decoy, an executable is written one level above `Documents`, in `AppData\Local`, which is an out-of-tree location typical of the path traversal:

```text
2025-09-02 08:14:18.856898  117405  Users\susan\AppData\Local\ApbxHelper.exe  FILE_CREATE
2025-09-02 08:14:18.873029  117405  Users\susan\AppData\Local\ApbxHelper.exe  DATA_EXTEND|FILE_CREATE|CLOSE
```

About 10 seconds later the file gets an `OBJECT_ID_CHANGE` (`08:14:28.784`), which is consistent with it being touched or launched, although USN alone does not prove execution.

**Answer:** `C:\Users\susan\AppData\Local\ApbxHelper.exe`

---

## Task 8 — File dropped for persistence

At the same millisecond as the backdoor, a shortcut is created in Susan's Startup folder:

```text
2025-09-02 08:14:18.856898  117404  Users\susan\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Display Settings.lnk  FILE_CREATE
```

Anything in this folder runs at logon. The harmless-looking name (`Display Settings`) is a masquerading trick, and the shortcut very likely points to `ApbxHelper.exe`. The triage holds no file contents, so this link is inferred from the matching timestamps, not read from the `.lnk`.

**Answer:** `C:\Users\susan\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Display Settings.lnk`

---

## Task 9 — Associated MITRE technique

Persistence here is carried by a **shortcut (`.lnk`)** that launches the backdoor at logon, which maps to **T1547.009 — Boot or Logon Autostart Execution: Shortcut Modification**.

> **Pitfall:** `T1547.001` (Registry Run Keys / Startup Folder) looks like the natural choice because the file sits in the Startup folder, but it is **rejected** by the platform. The question is about the shortcut file itself, which is what T1547.009 describes.

**Answer:** `T1547.009`

---

## Task 10 — When was the decoy document opened?

About 47 seconds after the decoy was created, Susan opens it:

```text
2025-09-02 08:15:05.356670  117403  Genotyping_Results_B57_Positive.pdf          OBJECT_ID_CHANGE
2025-09-02 08:15:05.612445  117410  Genotyping_Results_B57_Positive.lnk          FILE_CREATE   (Recent)
```

Same signal as for the archive: an `OBJECT_ID_CHANGE` followed by the `.lnk` in `Recent`. By then the backdoor and its persistence were already in place.

**Answer:** `2025-09-02 08:15:05`

---

## Incident Timeline (2025-09-02 UTC)

| Time | Event | Source |
|---|---|---|
| 08:13:50.440 | RAR staged in `VMwareDnD` temp (drag-and-drop from the host) | USN |
| 08:13:50.519 | RAR copied to `Documents` | USN / MFT |
| 08:14:04.980 | RAR opened (`OBJECT_ID_CHANGE`) | USN |
| 08:14:04.996 | `Pathology-Department-Research-Records.lnk` created in `Recent` | USN |
| 08:14:05.027 | WinRAR profile and WebView2 artifacts created | USN |
| 08:14:18.793 | Decoy `Genotyping_Results_B57_Positive.pdf` dropped | USN |
| 08:14:18.856 | `Display Settings.lnk` dropped in `Startup` | USN |
| 08:14:18.856 | `ApbxHelper.exe` dropped in `AppData\Local` | USN |
| 08:14:28.784 | `OBJECT_ID_CHANGE` on `ApbxHelper.exe` | USN |
| 08:15:05.356 | Decoy PDF opened | USN |
| 08:15:05.612 | `Genotyping_Results_B57_Positive.lnk` created in `Recent` | USN |
| 08:32:16 | Triage collection by the SOC (`CopyLog.csv`) | KAPE log |

---

## Mapping to MITRE ATT&CK

| Observed behaviour | Technique |
|---|---|
| Malicious RAR exploiting WinRAR when opened | T1203 — Exploitation for Client Execution |
| User opens the received archive and decoy | T1204.002 — User Execution: Malicious File |
| Payloads hidden in NTFS Alternate Data Streams | T1564.004 — Hide Artifacts: NTFS File Attributes |
| Shortcut in the Startup folder launching the backdoor | T1547.009 — Boot or Logon Autostart Execution: Shortcut Modification |
| Backdoor and shortcut with innocuous names (`ApbxHelper.exe`, `Display Settings.lnk`) | T1036 — Masquerading |

---

## Final Answers

| Task | Answer |
|---|---|
| 1 | `CVE-2025-8088` |
| 2 | `Path Traversal` |
| 3 | `Pathology-Department-Research-Records.rar` |
| 4 | `2025-09-02 08:13:50` |
| 5 | `2025-09-02 08:14:04` |
| 6 | `Genotyping_Results_B57_Positive.pdf` |
| 7 | `C:\Users\susan\AppData\Local\ApbxHelper.exe` |
| 8 | `C:\Users\susan\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Display Settings.lnk` |
| 9 | `T1547.009` |
| 10 | `2025-09-02 08:15:05` |

---

## Initial Assessment and Recommended Next Steps

**Assessment:** Susan's workstation is **compromised**. Opening `Pathology-Department-Research-Records.rar` triggered CVE-2025-8088: a decoy PDF was extracted as expected, while a backdoor (`ApbxHelper.exe`) and a Startup shortcut (`Display Settings.lnk`) were silently written outside the extraction folder. The backdoor survives reboots through the shortcut. The triage contains metadata only, so what the backdoor did afterwards is unknown.

**Recommended next steps:**

1. **Contain:** isolate the host from the network and disable or reset Susan's account.
2. **Collect and analyse:** recover `ApbxHelper.exe`, `Display Settings.lnk` and the original RAR (hash them, detonate in a sandbox, reverse the backdoor, read the `.lnk` target and the RAR's alternate streams).
3. **Eradicate:** remove the Startup shortcut and the backdoor; check other persistence locations (Run keys, scheduled tasks, services).
4. **Hunt across the fleet:** search for `ApbxHelper.exe`, `Display Settings.lnk` in Startup folders, and the RAR's hash on all endpoints.
5. **Check network activity:** review proxy, DNS and firewall logs after `08:14:18` for beaconing from this host.
6. **Corroborate the timeline:** cross-check with Defender alerts and logs, Prefetch, Amcache, Shimcache and the Recent / Jump Lists.
7. **Patch:** update WinRAR to 7.13 or later everywhere, and consider restricting archive handling from untrusted sources.
8. **Find the origin:** establish how the archive reached the VM (the `VMwareDnD` path points to drag-and-drop from the host) and who sent it.

---

## Takeaways

- **Two artifacts, two questions.** `$MFT` gives paths and timestamps; the USN journal gives the ordered sequence of events. Together they rebuild a full story without a single file content.
- **Open events leave marks.** An `OBJECT_ID_CHANGE` followed by a `.lnk` created in `Recent` is a reliable "the user opened this file" signal.
- **Look for drops in the same instant.** The decoy, the backdoor and the shortcut share the same 100 ms window: the signature of a single extraction.
- **Out-of-tree writes betray path traversal.** A payload in `AppData\Local` and a shortcut in `Startup`, from an archive in `Documents`, cannot come from a normal extraction.
- **Filter the noise.** Browser-like components (WebView2) create thousands of USN records; focus on `FILE_CREATE` outside cache folders.
- **Match the technique to the artifact.** A `.lnk` in `Startup` is T1547.009 here, not T1547.001: read what the question designates (the shortcut file).
- **Metadata is not content.** Without the files, the `.lnk` target and the backdoor's behaviour remain inferences.

---

## References

- Hack The Box — Sherlock "RomCom": https://app.hackthebox.com/sherlocks/RomCom
- NVD — CVE-2025-8088: https://nvd.nist.gov/vuln/detail/CVE-2025-8088
- MITRE ATT&CK T1547.009 — Shortcut Modification: https://attack.mitre.org/techniques/T1547/009/
- MITRE ATT&CK T1564.004 — NTFS File Attributes: https://attack.mitre.org/techniques/T1564/004/
- MITRE ATT&CK T1203 — Exploitation for Client Execution: https://attack.mitre.org/techniques/T1203/
- dissect.target: https://github.com/fox-it/dissect.target
