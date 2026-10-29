# HTB — "Behind the Scenes" (Reversing)

**Category:** Reversing  
**Difficulty:** Unspecified

---

## Challenge Description

> After struggling to secure our secret strings for a long time, we finally figured out the solution to our problem: Make decompilation harder. It should now be impossible to figure out how our programs work!

The challenge ships a single ELF binary, `challenge`, to analyze locally — no network target this time.

---

## Tooling

- `file`, `strings` — quick static triage
- `objdump -d` — disassembly
- A shell to just run the binary with candidate passwords

---

## Initial Triage

```bash
file challenge
```

```text
challenge: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, not stripped, for GNU/Linux 3.2.0
```

Not stripped — symbol names survive, which already works against the "impossible to figure out" claim in the scenario. A quick strings pass turns up the usage message, a cryptic hint, and the flag template:

```bash
strings -n 6 challenge
```

```text
./challenge <password>
> HTB{%s}
```

And in `.rodata`, visible directly in a hex dump:

```text
2010  3c 70 61 73 73 77 6f 72 64 3e 00 49 74 7a 00 5f   <password>.Itz._
2020  30 6e 00 4c 79 5f 00 55 44 32 00 3e 20 48 54 42   0n.Ly_.UD2.> HTB
2030  7b 25 73 7d 0a 00                                 {%s}..
```

Three suggestive strings sit between null bytes: `"Itz"`, `"_0n"`, `"Ly_"`, `"UD2"` — read together, `Itz_0nLy_UD2`, a pun on the x86 **`UD2`** instruction ("undefined instruction", opcode `0F 0B`), which raises `SIGILL` when executed. That's the challenge's real gimmick.

---

## The "Decompilation Hardening" Trick

Disassembling `main` shows a `ud2` instruction dropped after nearly every meaningful operation:

```bash
objdump -d --disassemble=main ./challenge
```

```text
12e1:  call   10e0 <sigaction@plt>
12e6:  0f 0b  ud2
12e8:  cmpl   $0x2,-0xa4(%rbp)
12ef:  je     130b <main+0xaa>
12f1:  0f 0b  ud2
...
```

Since `ud2` always raises `SIGILL`, the binary installs a custom handler for it before doing anything else:

```text
12b8: lea -0x96(%rip),%rax        # 1229 <segill_sigaction>
...
12e1: call sigaction@plt
```

Disassembling the handler itself shows exactly what it does:

```bash
objdump -d --disassemble=segill_sigaction ./challenge
```

```text
0000000000001229 <segill_sigaction>:
    1244: mov    -0x8(%rbp),%rax
    1248: mov    0xa8(%rax),%rax      ; ucontext->uc_mcontext.gregs[REG_RIP]
    124f: lea    0x2(%rax),%rdx       ; rip + 2
    1257: mov    %rdx,0xa8(%rax)      ; write it back
    125f: pop    %rbp
    1260: ret
```

It reads the saved `RIP` from the signal's `ucontext`, adds `2` (the exact length of a `ud2` instruction), and writes it back before returning — i.e. it **just steps over every `ud2` and resumes execution normally**. There is no hidden logic, no instruction substitution, no VM: the `ud2`s are pure noise meant to:

- confuse decompilers/disassemblers that choke on or misinterpret `ud2` as unreachable/invalid code,
- and discourage naive single-stepping under a debugger (an attached debugger may intercept `SIGILL` itself instead of letting the program's own handler run, unless explicitly told to pass the signal through).

None of that affects *reading* the disassembly by hand — the real instructions are still right there, in order, between the `ud2`s.

---

## Reading the Actual Password Check

Stripping out the `ud2` noise, `main`'s logic is straightforward:

```text
cmp $0x2, argc            ; require exactly one CLI argument
je  ...
...
call strlen(argv[1])
cmp $0xc, result          ; require length == 12
jne ...
...
strncmp(argv[1]+0, "Itz", 3)   ; @0x201b
jne fail
strncmp(argv[1]+3, "_0n", 3)   ; @0x201f
jne fail
strncmp(argv[1]+6, "Ly_", 3)   ; @0x2023
jne fail
strncmp(argv[1]+9, "UD2", 3)   ; @0x2027
jne fail
...
printf("> HTB{%s}\n", argv[1])
```

The 12-character password is checked in four separate 3-character chunks, each compared against its own standalone string in `.rodata` — almost certainly so that a plain `strings` dump doesn't hand over one obvious contiguous password string. Concatenating the four pieces:

```text
"Itz" + "_0n" + "Ly_" + "UD2" = "Itz_0nLy_UD2"
```

This is exactly the "hint" string noticed during initial triage — it wasn't a hint at all, it *was* the password, laid out in the binary in the same order the code checks it.

---

## Getting the Flag

```bash
./challenge Itz_0nLy_UD2
```

```text
> HTB{REDACTED}
```

---

## The Flag

```text
HTB{REDACTED}
```

---

## Takeaways

- **`ud2`-based "anti-decompilation" only works if the analyst never looks at the signal handler.** Here, `segill_sigaction` just skips 2 bytes and returns — once that's understood, every `ud2` in the disassembly can be mentally deleted and the real control flow reads perfectly normally. Static analysis fully defeats this trick; no dynamic tracing was even required.
- **An unstripped binary gives away everything.** Symbol names (`segill_sigaction`, `main`) immediately signal what's going on and where to look — a stripped binary would have made the signal handler much less obviously the point of interest.
- **Splitting a secret into several disjoint string literals doesn't meaningfully protect it.** `strings` already surfaced all four fragments; reading the comparison order in the disassembly was enough to reassemble them correctly.
- **`SIGILL`/`ud2` traps are a real (if weak) anti-debugging technique** — they rely on the fact that many debuggers stop on unhandled signals by default, and that disassemblers/decompilers can mishandle an illegal opcode mid-function. They don't, by themselves, hide or encrypt any logic; they only degrade *tooling* convenience, not a careful manual read.
- As the flag text itself says: making something *harder* to decompile is not the same as making it *impossible* — a few minutes with `objdump` and attention to the signal handler fully recovers the logic.
