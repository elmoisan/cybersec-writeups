# SMB - FTP - NFS

`Network` • `Medium` • `20 pts`

## TL;DR

Analyze one network capture containing `SMB`, `FTP`, and `NFS` traffic. Rebuild transferred files from each protocol, identify decoys, and extract the 3 partial flags to reconstruct the final flag.

**Flag:** `[REDACTED]`

---

## Challenge Description

> Votre professeur de réseau vous fournit cette capture en vous demandant d’essayer de retrouver les fichiers qu’il a fait transiter sur votre lab de test.
>
> Le flag est la concatenation des trois flags présents dans les fichiers.
>
> Bonne chance ! :)

**SHA256 checksum:** `66adb6a6a6c96c486e9f1856bf5039ab3b7a713b2a94e834ed281e7444f8aea7`

---

## Recon

From traffic inspection, three protocol families stand out:

- `SMB` on port `445`
- `FTP` control on port `21` + passive data ports (`PASV`)
- `NFS` over `ONC RPC` on port `2049`

Main TCP conversations:

| Flow | Purpose |
|------|---------|
| `445 <-> 55270` | SMB file transfer |
| `21 <-> 60386` | FTP control channel |
| `48553 <-> 42488` | FTP data (`cat.jpg`) |
| `23673 <-> 59890` | FTP data (`cat2.png`) |
| `15864 <-> 48142` | FTP data (`cookie.txt`) |
| `2049 <-> 943` | NFS / RPC traffic |

---

## Exploitation

### 1) SMB: extract and decode `books.pdf`

Server-side SMB payloads are reassembled in sequence order, then scanned for `%PDF ... %%EOF` boundaries.

Three files appear:

- `congradulation.odt` → decoy
- `books.pdf` → contains flag material
- `maybe.tar.gz` → decoy

`books.pdf` uses a custom `ToUnicode CMap` in a CID font. Standard extraction (`strings`, `pdftotext`) misses the real text. After inflating PDF streams and reading `beginbfchar` mappings, the hidden text resolves to the first flag segment.

---

### 2) FTP: follow PASV data channels

The FTP control channel (`227 Entering Passive Mode`) reveals per-file data ports using:

$$\text{port} = P1 \times 256 + P2$$

- `cat.jpg` (`48553`) → decoy
- `cat2.png` (`23673`) → second flag segment
- `cookie.txt` (`15864`) → decoy

Reassembling server payload on `23673` and carving from PNG magic bytes (`\x89PNG`) to `IEND` gives a valid image containing the second part.

---

### 3) NFS: parse RPC `READ` replies to rebuild `holidays.mp4`

Naively concatenating TCP payloads fails because NFSv4 data is wrapped in `ONC RPC` records.

Correct method:

1. Parse RPC record markers
2. Locate NFS `READ` operation (`opcode 0x19`)
3. Extract exactly `data_len` bytes from each reply
4. Concatenate chunks in order

Recovered file: `holidays.mp4`.

Video analysis shows two keyframes (`IDR`), and the second one contains different visual content. Decoding that frame reveals the third flag segment.

---

## Final Reconstruction

| Protocol | File | Result |
|----------|------|--------|
| SMB | `books.pdf` | Flag part #1 |
| FTP | `cat2.png` | Flag part #2 |
| NFS | `holidays.mp4` | Flag part #3 |

Concatenating the three parts gives the final challenge flag.

---

## Key Takeaways

- **SMB / PDF forensics:** custom font CMaps can hide text from naive extractors.
- **FTP analysis:** always inspect every `PASV` data port, not only the first transferred file.
- **NFS reconstruction:** parse RPC framing and NFS `READ` semantics; raw TCP carving can corrupt artifacts.
- **Video forensics:** check all keyframes (`IDR`), not only frame 0.

---

## References

- [RFC 959 - File Transfer Protocol](https://datatracker.ietf.org/doc/html/rfc959)
- [RFC 5531 - ONC RPC Version 2](https://datatracker.ietf.org/doc/html/rfc5531)
- [RFC 7530 - Network File System (NFS) Version 4](https://datatracker.ietf.org/doc/html/rfc7530)
- [ISO/IEC 14496-12 - ISO Base Media File Format (MP4)](https://www.iso.org/standard/74428.html)