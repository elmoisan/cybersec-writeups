# HTB Try-Outs — "It's Oops PM" (Hardware)

**Category:** Hardware  
**Difficulty:** Easy  
**Target:** `154.57.164.82:36075`

---

## Challenge Description

> With the location of the underground bunker secured, the crew embarks on the next phase of their plan: assessing the feasibility of creating an underground tunnel to bypass the super mutant camp. They secure samples of water, soil, and air near the area. Scouring the wasteland for salvageable equipment, they stumble upon a dilapidated research facility where they find a cache of environmental sensors. Examining these sensors, the crew discovers they communicate with a satellite and contain a crypto-processor that encrypts their transmissions. After hand-drawing the diagrams and emulating the silicon chip's logic with VHDL, they uncover what appears to be a backdoor in the embedded logic that only triggers when a specific input is given to the system. Determined to exploit this, they turn to their tech specialist. Can you connect to the satellite and activate it?

We're given a remote TCP service and a zip archive containing the VHDL source for the chip (a small "TPM"-like crypto-processor):

```text
hardware_its_oops_pm/
├── tpm.vhdl
├── key.vhdl
├── encryption.vhdl
├── backdoor.vhdl
└── schematic.png
```

---

## Source Analysis

### `tpm.vhdl` — top-level entity

This is the top module that wires everything together:

```vhdl
entity tpm is
    Port (
        Data : in STD_LOGIC_VECTOR(15 downto 0);
        Output : out STD_LOGIC_VECTOR(15 downto 0)
    );
end tpm;

architecture Behavioral of tpm is
    signal Key : STD_LOGIC_VECTOR(15 downto 0);
    signal Encrypted : STD_LOGIC_VECTOR(15 downto 0);
    signal B: STD_LOGIC;
begin
    ck : ckey port map(Key);
    enc: encryption port map (Data, Key, Encrypted);
    bd: backdoor port map (Data, B);

    process(Key, Encrypted, B)
    begin
        case B is
            when '1' =>
                for i in 0 to 15 loop
                    Output(i) <= Key(i);
                end loop;
            when others =>
                for i in 0 to 15 loop
                    Output(i) <= Encrypted(i);
                end loop;
        end case;
    end process;
end Behavioral;
```

The interesting part is the `case` statement: normally `Output` is driven by the `Encrypted` signal (the XOR-encrypted version of our input). However, if the backdoor signal `B` is `'1'`, the output multiplexer switches and drives the raw internal `Key` straight to the output instead — completely bypassing encryption.

### `backdoor.vhdl` — the trigger condition

```vhdl
entity backdoor is
    Port (
        D : in STD_LOGIC_VECTOR(15 downto 0);
        B : out STD_LOGIC
    );
end backdoor;

architecture Behavioral of backdoor is
    constant pattern : STD_LOGIC_VECTOR(15 downto 0) := "1111111111101001";
begin
    process(D)
    begin
        if D = pattern then
            B <= '1';
        else
            B <= '0';
        end if;
    end process;
end Behavioral;
```

`B` is asserted only when the 16-bit input `D` exactly equals the hardcoded pattern:

```text
1111111111101001   (binary)
= 0xFFE9            (hex)
```

### `encryption.vhdl` — normal operation (for reference)

```vhdl
process(D, K)
begin
    for i in 1 to 15 loop
        E(i) <= D(i) XOR K(i);
    end loop;

    E(0) <= NOT K(0);
    E(6) <= NOT K(6);
    E(13) <= NOT K(13);
end process;
```

Under normal conditions, each bit of the input is simply XOR'd with the corresponding key bit (with a few bits of the key additionally inverted directly onto the output, independent of the input). This is a trivial stream cipher — but we never actually need to break it, thanks to the backdoor.

### `key.vhdl` — key generation

```vhdl
architecture Behavioral of ckey is
    constant key : STD_LOGIC_VECTOR(15 downto 0) := "0110001111100001";
begin
    K <= key;
end Behavioral;
```

In this source file the key is shown as a constant for simulation purposes, but the key point for the attack is simply this: whatever the key is, the backdoor leaks it directly.

---

## The Bug

Putting it together:

- Input `Data = 1111111111101001` → `backdoor.B = '1'`
- `B = '1'` → the top-level mux routes `Key` straight to `Output`, skipping `encryption` entirely

So the "crypto-processor" has a logic bomb: feed it one specific 16-bit magic value, and instead of encrypting your data, it hands you its secret key in the clear.

---

## Exploitation

Connect to the service with `ncat`/`nc`:

```bash
ncat 154.57.164.82 36075
```

The service behaves like a simple 16-bit input/output oracle:

```text
The input must be a binary signal of 16 bits.

Input : 0000000000000000
Output: 0100001110100000
```

Sending an arbitrary value (all zeros here) confirms we're talking to the encryption path. Now send the backdoor pattern identified in `backdoor.vhdl`:

```text
Input : 1111111111101001
Output: 0110001111100001

You triggered the backdoor here is the flag: HTB{4_7yp1c41_53cu23_TPM_ch1p}
```

As predicted, the output `0110001111100001` is the raw internal key, and triggering the backdoor condition directly returns the flag.

---

## Flag

```text
HTB{4_7yp1c41_53cu23_TPM_ch1p}
```

---

## Takeaways

- Hardware/VHDL challenges can be approached exactly like a code review: trace every signal from input to output and look for conditional logic that deviates from the "intended" data path.
- A single `case`/`if` statement comparing an input against a hardcoded constant is a classic hardware backdoor pattern (sometimes called a "cheat code" or "trigger input") — always worth grepping for hardcoded `STD_LOGIC_VECTOR` constants compared directly against inputs.
- No actual cryptanalysis of the XOR cipher in `encryption.vhdl` was needed; the backdoor made the entire encryption scheme irrelevant.
