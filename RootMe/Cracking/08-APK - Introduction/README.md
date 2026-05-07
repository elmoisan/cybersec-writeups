# APK - Introduction

`Reverse Engineering` • `Easy` • `15 pts`

---

## TL;DR

A basic Android crackme with zero obfuscation. The seed string is stored as a
plain resource in `resources.arsc` and the password-generation logic lives in
an unprotected `classes3.dex`. Reimplementing `makeFlag()` in Python yields
the password in seconds.

**Flag:** `[REDACTED]`

---

## Challenge Description

> Find the valid password for this application!

The provided file `ch68.zip` contains `basic_rev.apk`, a standard Android
package. It displays a text field and a validation button; the correct password
must be entered to get the success toast message.

---

## Recon

### File identification

```bash
$ unzip -l ch68.zip
Archive:  ch68.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
  3868913  2022-05-09 17:31   basic_rev.apk

$ file basic_rev.apk
basic_rev.apk: Zip archive data
```

An APK is just a ZIP archive. Unpacking it reveals the standard Android layout:

```bash
$ unzip -q basic_rev.apk -d apk_contents && ls apk_contents/
AndroidManifest.xml  META-INF  classes.dex  classes2.dex  classes3.dex
res/  resources.arsc
```

Three DEX files are present. All application logic, including the password
check, lives in `classes3.dex`.

---

## Static Analysis

### Finding the success string

A quick scan for interesting strings across all DEX files reveals the goal
immediately:

```bash
$ python3 -c "
import re
for fname in ['classes.dex', 'classes2.dex', 'classes3.dex']:
    data = open(f'apk_contents/{fname}', 'rb').read()
    for s in re.findall(b'[\x20-\x7e]{6,}', data):
        if any(k in s.lower() for k in [b'well played', b'password', b'try again']):
            print(fname, s.decode())
"
classes3.dex  Well played! You can validate now with this password :)
classes3.dex  Try again ;)
```

The surrounding bytes also reveal the package name and key identifiers:
`com.example.basic_rev`, `MainActivity`, `makeFlag`, `ed1`, `seed`.

### Extracting the seed from resources

The `onCreate` method loads a string resource at ID `0x7F0F007A`
(`2131689594` decimal) and passes it as the seed to `makeFlag()`.
Parsing `resources.arsc` with androguard exposes it:

```bash
$ python3 -c "
from androguard.misc import AnalyzeAPK
import logging; logging.disable(logging.CRITICAL)
a, d, dx = AnalyzeAPK('basic_rev.apk')
arsc = a.get_android_resources()
strings = arsc.get_resolved_strings()
pkg = strings['com.example.basic_rev']['DEFAULT']
print(pkg[2131689594])
"
1dndr@
```

The seed is **`1dndr@`**, stored as a plain string resource — no encryption.

### Reversing `makeFlag()` with androguard

Disassembling `classes3.dex` gives the full Dalvik bytecode for both
`MainActivity` classes:

```bash
$ python3 -c "
from androguard.misc import AnalyzeAPK
import logging; logging.disable(logging.CRITICAL)
a, d, dx = AnalyzeAPK('basic_rev.apk')
for dex in d:
    for cls in dex.get_classes():
        if 'basic_rev/MainActivity' in str(cls.get_name()):
            for m in cls.get_methods():
                if m.get_code():
                    print('Method:', m.get_name())
                    for i in m.get_code().get_bc().get_instructions():
                        print('  ', i)
"
```

#### `onClick` — the comparison

```
iget-object  ed1 (EditText)
invoke-virtual  getText → toString  → input string
invoke-virtual  makeFlag(seed)      → expected string
invoke-virtual  equals              → compare
if-eqz → "Try again ;)"
         "Well played! You can validate now with this password :)"
```

The check is a plain `String.equals()` call. No hash, no encoding.

#### `makeFlag(seed)` — the algorithm

Reading the Dalvik bytecode, the function:

1. Initialises `result` with `seed[5]` and `rotated` with `seed[2]`.
2. Loops over each index `i` from `0` to `seed.length - 1`:
   - Builds a **rotated** variant of the accumulator string.
   - Appends a character from `seed` (wrapping logic differs for `i < 3` vs `i >= 3`).
   - Pads the accumulator to match `seed.length` by mirroring characters.
   - Picks one character from the rotated string using the formula:
     `index = (seed.length + acc.length) * i + acc.length) % rotated.length`
   - Appends it to `result`.
3. Assembles the final password:
   `result[0:2] + seed[3] + result[3] + chr(48) + result[5:7]`

---

## Exploitation

### Reimplementing `makeFlag()` in Python

```python
def makeFlag(seed):
    result  = seed[5]          # '@'
    acc     = seed[2]          # 'n'
    empty   = ""

    for i in range(len(seed)):
        # Build rotated view of acc
        rotated = acc[len(acc) - i:] + acc[i:]

        # Extend acc with a character from seed
        if i >= 3:
            acc = acc + seed[i - 3]
        else:
            acc = acc + seed[len(seed) - (3 - i)]

        # Pad acc to match seed length
        if i < len(acc):
            gap = len(acc) - i
            if len(seed) >= gap:
                acc = acc + seed[len(seed) - gap]
            else:
                acc = acc + seed[len(seed) - (gap - len(seed))]

        # Pick one character from rotated and append to result
        idx     = ((len(seed) + len(acc)) * i + len(acc)) % len(rotated)
        result  = result + rotated[idx]

    # Final assembly
    return result[0:2] + seed[3] + result[3] + chr(48) + result[5:7]


seed     = "1dndr@"
password = makeFlag(seed)
print(password)   # @ndr01d
```

```
$ python3 solve.py
@ndr01d
```

The password is **`@ndr01d`** — a leet-speak spelling of *Android*.

---

## Why does this work?

The developer stored the seed as a **plain string resource** and implemented
the password check as a direct `String.equals()` comparison against the output
of `makeFlag()`. Because the algorithm is fully deterministic and operates on a
publicly readable seed, reversing it is trivial:

```java
// Pseudocode reconstructed from bytecode
String seed = getString(R.string.seed);          // "1dndr@"  — visible in resources.arsc
Button b1 = findViewById(R.id.b1);
b1.setOnClickListener(v -> {
    String input    = ed1.getText().toString();
    String expected = makeFlag(seed);            // "@ndr01d"
    if (input.equals(expected)) {
        Toast.makeText(ctx, "Well played! ...", 0).show();
    } else {
        Toast.makeText(ctx, "Try again ;)",    0).show();
    }
});
```

A proper implementation would hash the input (e.g. SHA-256) and compare
digests, keeping both the seed and the expected value out of the binary.

---

## Key Takeaways

- **APKs are ZIP archives** — unzip first, inspect the DEX files directly.
- **`resources.arsc`** stores all string resources in plaintext; seeds and
  constants hidden there are trivially recoverable with androguard or
  `aapt dump resources`.
- **Plain `String.equals()` checks** in Android are just as exposed as in any
  other managed runtime: the expected value (or the seed used to derive it) is
  always reachable through static analysis.
- **Androguard** provides full Dalvik disassembly without needing a device,
  making it the go-to tool for Android static analysis on any platform.
- **Algorithm reversal**: when the password is derived from a seed rather than
  stored directly, reimplementing the derivation function in Python is
  usually faster than patching or running the app.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `unzip` | Unpack the APK (ZIP archive) |
| Python `re` / raw bytes | Quick scan for interesting strings in DEX files |
| androguard `AnalyzeAPK` | Parse `resources.arsc` and disassemble Dalvik bytecode |
| Python | Reimplement `makeFlag()` and compute the password |

---

## References

- [Android APK format](https://developer.android.com/guide/components/fundamentals)
- [Dalvik bytecode reference](https://source.android.com/docs/core/runtime/dalvik-bytecode)
- [androguard — Android reverse engineering framework](https://github.com/androguard/androguard)
- [Root-Me — APK - Introduction](https://www.root-me.org/en/Challenges/Cracking/APK-Introduction)