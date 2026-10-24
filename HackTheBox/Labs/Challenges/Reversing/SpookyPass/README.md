# HTB Challenge — "SpookyPass" (Reversing)

**Category:** Reversing  
**Difficulty:** Very Easy

---

## Challenge Scenario

> All the coolest ghosts in town are going to a Haunted Houseparty - can you prove you deserve to get in?

The challenge provides a single ZIP archive containing one file:

```text
rev_spookypass/pass
```

---

## Tooling

- `file` — to identify the file type
- `strings` — to look for readable text embedded in the binary
- `objdump` — to disassemble the binary and read its `.rodata` section
- A Linux shell — to run the binary directly

---

## Recon: Identifying the Binary

First, check what kind of file `pass` is:

```bash
file pass
```

```text
pass: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=..., for GNU/Linux 4.4.0, not stripped
```

It's a 64-bit Linux executable, and importantly **not stripped** — the symbol table (function and variable names like `main` and `parts`) is still present, which makes static analysis much easier.

Running it directly confirms it's an interactive password prompt:

```bash
echo "test" | ./pass
```

```text
Welcome to the SPOOKIEST party of the year.
Before we let you in, you'll need to give us the password: You're not a real ghost; clear off!
```

---

## Step 1: Looking for Strings

A quick pass with `strings` is always worth trying first, since many easy reversing challenges leave sensitive data in plain text:

```bash
strings pass
```

Among the standard libc symbols, a few interesting lines stand out:

```text
Welcome to the 
[1;3mSPOOKIEST
[0m party of the year.
Before we let you in, you'll need to give us the password: 
s3cr3t_p455_f0r_gh05t5_4nd_gh0ul5
Welcome inside!
You're not a real ghost; clear off!
...
parts
main
```

The string `s3cr3t_p455_f0r_gh05t5_4nd_gh0ul5` looks exactly like the password the program is waiting for, and the symbol name `parts` hints at some kind of array used after a successful check — likely how the flag is built.

---

## Step 2: Disassembling `main`

To confirm what the password is actually checked against, and to understand what `parts` does, disassemble the binary:

```bash
objdump -d -M intel pass
```

The relevant logic inside `<main>` is:

```asm
lea    rax,[rbp-0x90]
mov    esi,0x80
mov    rdi,rax
call   fgets@plt              ; read user input

lea    rax,[rbp-0x90]
mov    esi,0xa
mov    rdi,rax
call   strchr@plt             ; find '\n'
...
mov    BYTE PTR [rax],0x0     ; strip the newline

lea    rax,[rbp-0x90]
lea    rdx,[rip+0xe36]        # 2080 <_IO_stdin_used+0x80>
mov    rsi,rdx
mov    rdi,rax
call   strcmp@plt             ; compare input vs. the string at 0x2080
test   eax,eax
jne    12c2 <main+0x139>      ; if different -> print "You're not a real ghost..."

; --- if the password matches ---
puts   "Welcome inside!"
mov    DWORD PTR [rbp-0xbc],0x0
; loop 0x1A (26) times:
;   edx = parts[i]   (4-byte int, taken from the global array `parts`)
;   buffer[i] = dl   (only the low byte is kept)
;   i++
call   puts                   ; print the reconstructed 26-byte buffer
```

So the program does two things:

1. Compares the user's input with a **hardcoded string** using `strcmp`.
2. On success, it does **not** print a static string directly — instead it rebuilds a 26-character buffer **byte by byte**, one `int` at a time, from a global array called `parts`, and only then prints it.

This byte-by-byte reconstruction is a simple anti-`strings` trick: the final message (the flag) isn't stored as one contiguous readable string in the binary, so a plain `strings pass` wouldn't show it directly — only the *password* was visible that way, not the flag.

---

## Step 3: Extracting the Hardcoded Password

The comparison string lives at offset `0x2080`, referenced via `lea rdx,[rip+0xe36]`. Dumping the `.rodata` section confirms it:

```bash
objdump -s -j .rodata pass
```

```text
 2080 73336372 33745f70 3435355f 6630725f  s3cr3t_p455_f0r_
 2090 67683035 74355f34 6e645f67 6830756c  gh05t5_4nd_gh0ul
 20a0 35005765 6c636f6d 6520696e 73696465  5.Welcome inside
 20b0 21000000 00000000 596f7527 7265206e  !.......You're n
 20c0 6f742061 20726561 6c206768 6f73743b  ot a real ghost;
 20d0 20636c65 6172206f 66662100            clear off!.
```

Reading the bytes as ASCII gives the expected password:

```text
s3cr3t_p455_f0r_gh05t5_4nd_gh0ul5
```

---

## Step 4: Triggering the Flag

Running the binary and supplying that exact password unlocks the success branch, which reconstructs and prints the `parts` array — the actual flag:

```bash
echo "s3cr3t_p455_f0r_gh05t5_4nd_gh0ul5" | ./pass
```

```text
Welcome to the SPOOKIEST party of the year.
Before we let you in, you'll need to give us the password: Welcome inside!
HTB{un0bfu5c4t3d_5tr1ng5}
```

---

## The Flag

```text
HTB{REDACTED}
```

---

## Takeaways

- **Unstripped binaries leak a lot of information for free.** Symbol names like `main` and `parts` immediately hint at the program's structure and where the interesting logic lives.
- **`strings` is a great first move, but not the whole story.** It revealed the password instantly, but the flag was deliberately built byte by byte at runtime from an integer array (`parts`) specifically so it wouldn't appear as a contiguous readable string — a basic form of string obfuscation.
- **Reading the disassembly confirms what a static string dump only hints at.** Following the `strcmp` call and the reconstruction loop in `main` was what revealed *how* the flag was produced, not just *that* a password existed.
- **The flag name itself is the lesson:** `un0bfu5c4t3d_5tr1ng5` ("unobfuscated strings") — the password was left in plain text in `.rodata`, which was enough to unlock the challenge even though the flag text itself was mildly obfuscated.
- As with most easy reversing challenges, the workflow is always the same: **identify the binary → dump strings → disassemble the relevant function → confirm with a dynamic run.**
