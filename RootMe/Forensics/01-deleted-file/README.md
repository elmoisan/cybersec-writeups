# Deleted File

`Forensic` • `Easy` • `5 pts`

## TL;DR

Recover a deleted PNG from a FAT16 USB image with The Sleuth Kit, then read the author's name in its XMP metadata.

**Flag:** `REDACTED`

---

## Challenge Description

> You can look at whatever you want, but this USB stick is empty... Your cousin found a USB stick at the library this morning. He is not very good with computers, so he is counting on you to find the owner of this stick! The flag is the owner's identity in the form `firstname_lastname`.

**File:** `ch39.gz`

**SHA-256 (from the statement):** `cd9f4ada5e2a97ec6def6555476524712760e3d8ee99c26ec2f11682a1194778`

**Context:** The stick looks empty, but "deleted" rarely means "erased". The goal is to find who owns it.

---

## Recon

**Step 1 — Verify the download and peel the layers:**

```bash
$ sha256sum ch39.gz
cd9f4ada5e2a97ec6def6555476524712760e3d8ee99c26ec2f11682a1194778  ch39.gz

$ gunzip -k ch39.gz
$ file ch39
ch39: POSIX tar archive (GNU)

$ tar -tvf ch39
-rw-rw---- manah/root 32505856 2021-09-12 13:16 usb.image

$ mkdir ex && tar -xf ch39 -C ex && cd ex
$ file usb.image
usb.image: DOS/MBR boot sector, ... OEM-ID "mkfs.fat", ... label: "USB        ", FAT (16 bit)
```

**Observations:**
- The hash matches the one in the statement → the file is intact
- The `.gz` hides a `tar`, which hides the real disk image: always run `file` at each layer
- `usb.image` is a **FAT16** filesystem labeled `USB`

**Hypothesis:** The user "emptied" the stick by deleting files. On FAT, deletion only flags the directory entry, so the data should still be on the disk.

---

## Exploitation

### Step 1 — List files, including deleted ones

```bash
$ sudo apt install sleuthkit libimage-exiftool-perl

$ fls -r usb.image
r/r 3:	USB         (Volume Label Entry)
r/r * 5:	anonyme.png
v/v 1013699:	$MBR
v/v 1013700:	$FAT1
v/v 1013701:	$FAT2
V/V 1013702:	$OrphanFiles
```

The `*` marks a **deleted** entry. The file `anonyme.png` is still referenced at **inode 5**.

---

### Step 2 — Recover the deleted file

```bash
$ icat usb.image 5 > anonyme.png
$ file anonyme.png
anonyme.png: PNG image data, 400 x 300, 8-bit/color RGB, non-interlaced
```

✅ The PNG is fully recovered: its clusters were never overwritten.

---

### Step 3 — Read the metadata

The file is named "anonymous", but the metadata tells another story:

```bash
$ exiftool anonyme.png | grep -iE "creator|author|artist"
Creator                         : [REDACTED]
```

The `Creator` field (XMP `dc:creator`) contains the owner's full name.

> 💡 Quick and dirty alternative: `strings usb.image | grep -i -A2 creator` prints the raw XMP block straight from the image, because the deleted data is still there. It works, but it does not tell you which file the data belongs to.

---

### Step 4 — Build the flag

Format `firstname_lastname`, lowercase:

```
REDACTED
```

---

## Impact & Mitigation

### Real-World Implications

| Weakness | Impact |
|----------|--------|
| **CWE-212** | Improper Removal of Sensitive Information Before Storage or Transfer |
| **CWE-226** | Sensitive Information in Resource Not Removed Before Reuse |
| **CWE-200** | Exposure of Sensitive Information (metadata leak) |

**Attack Scenarios:**
1. **Lost or resold media**: A "formatted" or "emptied" drive still holds recoverable documents, photos and credentials
2. **Deanonymization**: Metadata (author, GPS, device, software) identifies the person behind an "anonymous" file
3. **Investigations and OSINT**: Deleted files and EXIF/XMP data are routine evidence for forensic analysts and attackers alike
4. **Data leaks by publication**: Documents published online with intact metadata expose usernames, internal paths and software versions

**Why this matters:**
- A normal delete only removes a pointer, not the content
- Quick formats do not overwrite data either
- Metadata is invisible to the user in most viewers, so people forget it exists

---

### Secure Practices

**❌ NEVER rely on this (data remains recoverable):**

```bash
# Plain delete or quick format: only the directory entry / allocation table changes
rm secret.png
mkfs.fat -F 16 /dev/sdX1
```

**✅ DO this instead:**

**Option 1 — Overwrite files before removing them:**
```bash
# Overwrite then delete (works best on magnetic disks)
shred -vzu -n 3 secret.png
```

**Option 2 — Wipe the whole device before giving it away:**
```bash
# Overwrite the entire device with zeros (double-check the device name!)
sudo dd if=/dev/zero of=/dev/sdX bs=1M status=progress

# On SSDs / flash: prefer the hardware discard or secure erase
sudo blkdiscard -s /dev/sdX
```

**Option 3 — Strip metadata before sharing a file:**
```bash
exiftool -all= -overwrite_original photo.png
# or, for many formats:
mat2 photo.png
```

**Best Practices:**
1. **Treat "delete" and "quick format" as non-destructive** operations
2. **Wipe or destroy media** following NIST SP 800-88 before disposal or resale
3. **Use full-disk encryption** from the start: discarded media is then unreadable without the key
4. **Remember flash storage limits**: wear leveling means overwriting a single file may not reach every copy, so rely on encryption or device-level erase
5. **Strip metadata** from every file you publish or send outside your organization

---

## Key Takeaways

**Technical Skills:**
- Peeled nested containers (`gz` → `tar` → disk image) and identified each layer with `file`
- Recognized a FAT16 image and used The Sleuth Kit (`fsstat`, `fls`, `icat`)
- Spotted deleted entries by the `*` marker and recovered one by inode number
- Extracted author information from XMP metadata with `exiftool`

**Forensic Concepts:**
- On FAT, deleting a file flags its directory entry; the data stays until overwritten
- `fls` + `icat` recover files **through the filesystem** (name and size preserved); carving tools such as `foremost` or `photorec` recover them **by signature** when the directory entry is gone
- File names lie, **metadata often does not**
- Always verify the integrity of evidence with a hash before working on it

---

## References

- [CWE-212: Improper Removal of Sensitive Information Before Storage or Transfer](https://cwe.mitre.org/data/definitions/212.html)
- [CWE-226: Sensitive Information in Resource Not Removed Before Reuse](https://cwe.mitre.org/data/definitions/226.html)
- [The Sleuth Kit documentation](https://www.sleuthkit.org/sleuthkit/docs.php)
- [NIST SP 800-88 Rev. 1: Guidelines for Media Sanitization](https://csrc.nist.gov/publications/detail/sp/800-88/rev-1/final)
- [ExifTool by Phil Harvey](https://exiftool.org/)
