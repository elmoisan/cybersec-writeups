# Godot - 0 protection

`Reverse Engineering` • `Easy` • `10 pts`

## TL;DR

A Godot 3.2 game exported as a self-contained Windows PE64 executable.
The flag is displayed on a sign atop an unreachable floating island — no need to play.
The Godot PCK archive is embedded at the end of the exe; unpacking it exposes
a GDScript file that XORs two hardcoded arrays to produce the flag.

**Flag:** `[REDACTED]`

---

## Challenge Description

> Votre ami développeur a conçu un nouveau jeu qu'il veut vous faire tester.
> Il vous explique que le but est d'atteindre l'île lumineuse dans le ciel.
> Il vous dit également que si jamais vous y arrivez, vous devrez lui dire
> ce qui est écrit sur le panneau présent sur l'île en guise de preuve,
> car c'est impossible que vous y arriviez. Montrez-lui qu'il se trompe.

The provided file `0_protection.exe` is a 64-bit Windows console executable
— a Godot 3.2 export — that bundles the entire game inside itself.
The flag is rendered at runtime on a 3D `Label` node visible only if the player
reaches an inaccessible sky island.

---

## Recon

### File identification

```bash
$ file 0_protection.exe
0_protection.exe: PE32+ executable (GUI) x86-64 (stripped to external PDB),
                  for MS Windows, 14 sections
$ wc -c 0_protection.exe
44404656 bytes
```

A 44 MB PE64 binary. The abnormal size immediately suggests a self-contained
game bundle rather than a plain executable. No UPX, no custom packer.

### Godot PCK structure

Godot exports can embed their resource package (`.pck`) directly into the
executable. The embedded PCK is identified by its `GDPC` magic signature.
Scanning for all occurrences reveals the layout:

| Offset | Content |
|--------|---------|
| `0x1FD4400` | `GDPC` — start of embedded PCK |
| `0x2A58FAC` | `GDPC` — end-of-file footer (4 bytes before EOF) |

The footer pattern is a Godot convention: the last 12 bytes of the exe are
`<int64 offset-from-end-to-PCK-start>` + `GDPC`, allowing the runtime to
locate the embedded package without scanning the whole file.

```python
end_magic_pos = len(data) - 4           # b'GDPC' at EOF
offset_from_end = struct.unpack_from('<q', data, end_magic_pos - 8)[0]
pck_start = len(data) - offset_from_end  # → 0x1FD4400
```

### PCK header

The PCK uses format version 1 (Godot 3.x):

```
magic        : GDPC
pack_version : 1
game_version : 3.2.0
reserved     : 16 × uint32 (zeroed)
file_count   : 27
```

### File inventory

The archive contains 27 entries. The relevant ones:

| Path | Size | Role |
|------|------|------|
| `res://src/FlagLabel.gd` | 362 B | **Generates the flag at runtime** |
| `res://src/Player.gd` | 1 466 B | Player movement and camera |
| `res://res/scenes/island.tscn` | 2 050 B | Sky island scene — hosts the flag label |
| `res://res/scenes/Main.tscn` | 6 753 B | Root scene |
| `res://project.binary` | 3 135 B | Compiled project settings |

---

## Exploitation

### Step 1 — Locate the PCK in the exe

```python
import struct

data = open('0_protection.exe', 'rb').read()

end_magic_pos = len(data) - 4
offset_from_end = struct.unpack_from('<q', data, end_magic_pos - 8)[0]
pck_start = len(data) - offset_from_end
# → pck_start = 33375232 (0x1FD4400)
# → data[pck_start:pck_start+4] == b'GDPC' ✓
```

### Step 2 — Parse the PCK file table

Each file entry in a Godot 3 PCK has the following layout:

```
path_len  : uint32
path      : path_len bytes (null-padded UTF-8)
offset    : uint64  (absolute offset in the exe)
size      : uint64
md5       : 16 bytes
```

```python
header_size = 4 + 4 + 4 + 4 + 4 + 64   # magic + versions + reserved
file_count_pos = pck_start + header_size
file_count = struct.unpack_from('<I', data, file_count_pos)[0]   # 27

pos = file_count_pos + 4
files = {}
for _ in range(file_count):
    path_len = struct.unpack_from('<I', data, pos)[0]; pos += 4
    path     = data[pos:pos+path_len].rstrip(b'\x00').decode(); pos += path_len
    offset   = struct.unpack_from('<Q', data, pos)[0]; pos += 8
    size     = struct.unpack_from('<Q', data, pos)[0]; pos += 8
    pos += 16   # skip md5
    files[path] = (offset, size)
```

### Step 3 — Extract and read `FlagLabel.gd`

```python
offset, size = files['res://src/FlagLabel.gd']
script = data[offset:offset+size].decode('utf-8')
print(script)
```

```gdscript
extends Label

func _ready():
    var key = [119, 104, 52, 116, 52, 114, 51, 121, 48, 117, 100, 48, 49, 110, 103, 63]
    var enc = [32, 13, 88, 24, 20, 22, 92, 23, 85, 89, 68, 68, 89, 11, 71, 89,
               27, 9, 83, 84, 93, 1, 57, 42, 83, 7, 13, 96, 69, 29, 86, 81, 52, 4, 7, 64, 70]

    text = ""
    for i in range(len(enc)):
        text += char(enc[i] ^ key[i % len(key)])
```

The algorithm is an identical repeating-key XOR to the one seen in *ELF C++ - 0 protection*:

```
plaintext[i] = enc[i] XOR key[i % len(key)]
```

### Step 4 — Replay the XOR offline

```python
key = [119, 104, 52, 116, 52, 114, 51, 121, 48, 117, 100, 48, 49, 110, 103, 63]
enc = [32, 13, 88, 24, 20, 22, 92, 23, 85, 89, 68, 68, 89, 11, 71, 89,
       27, 9, 83, 84, 93, 1, 57, 42, 83, 7, 13, 96, 69, 29, 86, 81, 52, 4, 7, 64, 70]

flag = ''.join(chr(enc[i] ^ key[i % len(key)]) for i in range(len(enc)))
print(flag)
# Well done, the flag is
# ScriPts1nCl34r
```

---

## Why does this work?

Godot's export format is not an obfuscation mechanism. The `.pck` archive stores
all game assets — including GDScript source files — in plaintext, with no encryption
and no compilation to bytecode by default. The `GDPC` magic and the file table are
fully documented in the Godot source code.

The XOR transform in `FlagLabel.gd` looks like protection but provides none:
key and ciphertext are both hardcoded in the same script, making the cipher
trivially reversible without running the game.

Reaching the island in-game would be the intended path — but static analysis
bypasses the entire game engine in seconds.

---

## Key Takeaways

- **Godot self-contained exports** embed a standard `.pck` archive at the end of
the executable, locatable via the `GDPC` end-of-file footer.
- **GDScript is stored as source** in default exports — no compilation, no
bytecode. Every script is directly readable after unpacking.
- **Repeating-key XOR** is not encryption when both operands live in the same file.
  The cipher is irrelevant; the key is the real secret, and it is not secret.
- **Never trust game-enforced constraints** in a reversing challenge. Walls,
gravity, and unreachable areas only matter at runtime.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `file` | Identify binary format and architecture |
| Python `struct` | Parse PE, PCK header and file table |
| Manual byte scanning | Locate `GDPC` magic and compute PCK bounds |

---

## References

- [Godot PCK format — Godot source code](https://github.com/godotengine/godot/blob/3.x/core/io/pck_packer.cpp)
- [Godot export documentation](https://docs.godotengine.org/en/3.5/tutorials/export/exporting_projects.html)
- [GDScript reference](https://docs.godotengine.org/en/3.5/tutorials/scripting/gdscript/gdscript_basics.html)
- [Root-Me — Godot - 0 protection](https://www.root-me.org/en/Challenges/Cracking/Godot-0-protection)
