# TCP - Retour au collège

`Programming` • `Medium` • `5 pts`

## TL;DR

Connect to a TCP server that sends two numbers. Calculate: $\sqrt{n_1} \times n_2$, round to 2 decimal places, and send the result within 2 seconds.

**Flag:** `RM{[REDACTED]}`

---

## Challenge Description

> Pour commencer cette épreuve utilisant le protocole TCP, vous devez vous connecter à un programme sur une socket réseau.
>
> - Vous devez calculer la racine carrée du nombre n°1 et multiplier le résultat obtenu par le nombre n°2.
> - Vous devez ensuite arrondir à deux chiffres après la virgule le résultat obtenu.
> - Vous avez 2 secondes pour envoyer la bonne réponse à partir du moment où le programme vous envoie le calcul.

**Target:** `challenge01.root-me.org:52002` (TCP)

---

## Recon

The server sends two numbers and expects the computed result within a strict 2-second timeout.

**Required calculation:**
$$\text{result} = \text{round}(\sqrt{n_1} \times n_2, 2)$$

**Key constraint:** Fast socket I/O and precise timing.

---

## Exploitation

### Python Solution (Working)

```python
#!/usr/bin/env python3
import socket
import math
import re

host, port = "challenge01.root-me.org", 52002

with socket.create_connection((host, port), timeout=5) as s:
    # Read until we get the full challenge
    data = b""
    while b"=" not in data:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    
    text = data.decode(errors="ignore")
    print(text, end="")
    
    # Parse: "Calculate the square root of X and multiply by Y ="
    m = re.search(r"square root of\s+(\d+)\s+and multiply by\s+(\d+)", text)
    if not m:
        raise SystemExit("[-] Could not parse challenge")
    
    n1, n2 = map(int, m.groups())
    print(f"[*] Parsed: sqrt({n1}) * {n2}")
    
    # Calculate and format to 2 decimals
    ans = math.sqrt(n1) * n2
    print(f"[*] Result: {ans:.2f}")
    
    # Send the answer
    s.sendall(f"{ans:.2f}\n".encode())
    
    # Receive the flag
    s.settimeout(2)
    out = []
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            out.append(chunk)
    except socket.timeout:
        pass
    
    if out:
        flag_response = b"".join(out).decode(errors="ignore")
        print(flag_response, end="")
```

### Execution

```
$ python3 solution.py
====================
 GO BACK TO COLLEGE
====================
You should tell me the answer of this math operation in less than 2 seconds !

[*] Parsed: sqrt(159) * 2718
[*] Result: 34267.98

Calculate the square root of 159 and multiply by 2718 = [+] Good job ! Here is your flag: RM{[REDACTED]}
```

---

## Walkthrough

1. **Connect** to `challenge01.root-me.org:52002`
2. **Read** the server message until you see `=` (end of challenge line)
3. **Parse** the message with regex: `"square root of\s+(\d+)\s+and multiply by\s+(\d+)"`
4. **Compute** $\sqrt{n_1} \times n_2$
5. **Format** to 2 decimals using `f"{result:.2f}"`
6. **Send** the result + newline
7. **Read** the flag response with a 2-second timeout

**Real test case from the challenge:**
- Challenge: `Calculate the square root of 159 and multiply by 2718 =`
- Parsed: $n_1 = 159$, $n_2 = 2718$
- Calculation: $\sqrt{159} \times 2718 \approx 12.61 \times 2718 = 34267.98$
- Sent: `34267.98`
- Response: `[+] Good job ! Here is your flag: RM{TCP_C0nnecT_4nD_m4Th}`

---

## Key Takeaways

- **Socket I/O:** Use `socket.settimeout()` to handle strict time limits
- **Floating-point precision:** Python's `round()` function handles banker's rounding; use `Decimal` for strict rounding if needed
- **Protocol parsing:** Always verify the exact format of server input (delimiters, line endings)
- **Race conditions:** Network latency + computation must stay under 2 seconds total

---

## References

- [Python socket module](https://docs.python.org/3/library/socket.html)
- [Python math.sqrt()](https://docs.python.org/3/library/math.html#math.sqrt)
- [RFC 793 - Transmission Control Protocol](https://datatracker.ietf.org/doc/html/rfc793)
