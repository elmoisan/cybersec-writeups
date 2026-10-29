# HTB — "Ether Tag" (Hardware/ICS)

**Category:** Hardware / ICS  
**Difficulty:** Very Easy

---

## Challenge Description

> We've discovered an EtherNet/IP controller on the network. Your mission: connect to the device and retrieve the value of the FLAG tag. Can you extract the flag and prove your skills?

The challenge spawns a Docker instance exposed as an `IP:PORT` pair:

```text
154.57.164.76:39178
```

> The IP and port change every time the instance is respawned.

---

## Tooling

- `cpppo` — Python library implementing an EtherNet/IP (ENIP) / CIP client, including a CLI tag-reader
- `nc` — to sanity-check raw TCP connectivity to the target

---

## Recon: EtherNet/IP and CIP

**EtherNet/IP** (Ethernet Industrial Protocol) is an industrial fieldbus protocol that encapsulates **CIP** (Common Industrial Protocol) over TCP/UDP. It's what PLCs and industrial controllers use to expose named data points called **tags**. The scenario states a tag named `FLAG` exists on the controller — the goal is simply to read it over the wire, no exploitation involved.

A CIP session normally goes through:

1. **Register Session** — handshake with the device, which returns a `Session Handle`.
2. **Send RR Data / Unconnected Message** — a CIP service request (e.g. *Read Tag Service*) encoding the tag's symbolic name.
3. The device replies with the tag's data type and value.

Rather than hand-crafting these frames, `cpppo` handles the whole exchange and exposes a simple CLI:

```bash
pip install cpppo --break-system-packages
```

---

## Verifying Connectivity

Before touching the protocol layer, a raw TCP check confirms the target is reachable:

```bash
nc -vz 154.57.164.76 39178
```

```text
Connection to 154.57.164.76 39178 port [tcp/*] succeeded!
```

---

## First Read Attempt

```bash
python3 -m cpppo.server.enip.client --address 154.57.164.76:39178 FLAG -v
```

```text
10-29 20:07:57.279 MainThread enip.cli NORMAL   __init__   Connect:  Success in   0.079/  5.000s
10-29 20:07:57.317 MainThread enip.cli NORMAL   main       Client Tag I/O  Average  26.747 TPS (  0.037s ea).
```

The session connects and the tag read succeeds (`Success`, TPS reported), but the CLI prints nothing by default unless explicitly asked to. Adding `--print` makes it display the retrieved value:

```bash
python3 -m cpppo.server.enip.client --address 154.57.164.76:39178 --print FLAG
```

```text
                FLAG              == [72]: 'OK'
```

---

## Reading the Full Tag

`[72]` is the ASCII code for `'H'` — the very first byte of `HTB{...}`. This confirms `FLAG` is an **array tag**, and the bare `FLAG` read only fetched a single element (index 0). The fix is to request a full index range:

```bash
python3 -m cpppo.server.enip.client --address 154.57.164.76:39178 --print "FLAG[0-80]"
```

```text
             FLAG[0][  0-80 ]+  0 == [72, 84, 66, 123, 51, 116, 104, 51, 114, 110, 51, 116, 49, 112, 95, 112, 119, 110, 51, 100, 125, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]: 'OK'
```

The array comes back as a list of ASCII codes padded with trailing zeros. Decoding the non-zero bytes:

```text
72, 84, 66, 123, 51, 116, 104, 51, 114, 110, 51, 116, 49, 112, 95, 112, 119, 110, 51, 100, 125
 H,  T,  B,  {,  3,  t,  h,  3,  r,  n,  3,  t,  1,  p,  _,  p,  w,  n,  3,  d,  }
```

---

## The Flag

```text
HTB{REDACTED}
```

---

## Takeaways

- **EtherNet/IP tags are addressed by symbolic name**, but the underlying data type matters: a plain scalar read (`FLAG`) only returns the type's base element, while a tag backed by an array needs an explicit index range (`FLAG[0-80]`) to retrieve its full contents.
- **A "successful" read isn't necessarily a complete one.** The first attempt reported `Success` and looked fine at the protocol level, but silently returned only one byte — always sanity-check the *shape* of the data you get back, not just whether the request succeeded.
- **String data on PLCs is frequently stored as raw byte/array tags**, not a native string type, since CIP's primitive types are oriented around industrial data (integers, reals, booleans, byte arrays). Expect to manually decode ASCII codes from an integer array.
- **`cpppo`'s CLI needs `--print` to actually display tag values** — a quiet, zero-output exit can easily be mistaken for a failure when it's actually just the tool staying silent by default.
- Unlike typical web challenges, this one highlights **ICS/OT protocol fundamentals**: EtherNet/IP and CIP are ubiquitous in industrial control systems, and reading a tag off a live controller is the most basic — and most important — interaction to understand before looking at anything more advanced (write access, vendor-specific services, etc.).
