# XMPP - Authentification

`Network` • `Medium` • `45 pts`

## TL;DR

Analyze an XMPP (Jabber) network capture using `SCRAM-SHA-1` SASL authentication. Reconstruct the full SCRAM handshake from base64-encoded stanzas, then recover the password by exploiting the hint that it reuses part of the login — brute-forcing a small suffix space and validating candidates against both the captured client proof and server signature.

**Flag:** `[REDACTED]`

---

## Challenge Description

> En espionnant par dessus l'épaule de l'utilisateur au moment où il s'authentifiait, il semblerait que son mot de passe contienne une partie du login.
>
> Retrouvez le mot de passe de l'utilisateur dans cette capture réseau de session XMPP.
>
> Le flag est le condensat SHA1 de ce mot de passe.

**Provided file:** `ch8.pcap`

---

## Recon

`tshark -q -z conv,tcp` shows two TCP conversations to `208.68.163.220:5222` (standard XMPP client port), each a separate authentication attempt.

Following both streams (`tshark -z follow,tcp,ascii,<n>`) reveals:

- Both use the `SCRAM-SHA-1` SASL mechanism (offered alongside `CRAM-MD5`, `LOGIN`, `PLAIN`, `DIGEST-MD5`).
- **Stream 0** ends in `<failure><invalid-authzid/></failure>` — a decoy/failed attempt.
- **Stream 1** ends in `<success>` — the valid authentication to analyze.

---

## Exploitation

### 1) Decode the SCRAM-SHA-1 handshake (RFC 5802)

Base64-decoding every SASL stanza of the successful stream (Stream 1) gives the full exchange:

| Message | Decoded content |
|---------|------------------|
| `client-first-message` | `n,,n=koma_test,r=hydra` |
| `server-first-message` | `r=hydraFe3A1scL7C0jtKsm+kcg96MWg769FuRu,s=kM6lTjjnZW4F8WLboyagcA==,i=4096` |
| `client-final-message` | `c=biws,r=hydraFe3A1scL7C0jtKsm+kcg96MWg769FuRu,p=mZU2Qekd8JR7ybCtb3hnJMGEfIg=` |
| `server-success` | `v=YQlegvbEwDo2o60YiK2iAkYyPKE=` |

This exposes username (`koma_test`), nonces, salt, iteration count (`4096`), the client's `ClientProof`, and the server's `ServerSignature`.

### 2) Rebuild the SCRAM-SHA-1 key derivation

```
SaltedPassword  = PBKDF2-HMAC-SHA1(password, salt, iterations)
ClientKey       = HMAC-SHA1(SaltedPassword, "Client Key")
StoredKey       = SHA1(ClientKey)
AuthMessage     = client-first-bare + "," + server-first-message + "," + client-final-without-proof
ClientSignature = HMAC-SHA1(StoredKey, AuthMessage)
ClientProof     = ClientKey XOR ClientSignature

ServerKey       = HMAC-SHA1(SaltedPassword, "Server Key")
ServerSignature = HMAC-SHA1(ServerKey, AuthMessage)
```

Both `ClientProof` and `ServerSignature` are known and depend on `SaltedPassword`, so either can validate a password guess.

### 3) Exploit the hint: password contains part of the login

Username is `koma_test`. Narrow search to candidates starting from `koma` plus a short suffix. Example approach:

```python
charset = "_abcdefghijklmnopqrstuvwxyz"
for passlen in range(0, 4):
    for suffix in itertools.product(charset, repeat=passlen):
        candidate = "koma" + "".join(suffix)
        # derive SaltedPassword -> ServerKey -> ServerSignature
        # compare against captured server v=...
```

A small suffix search finds `komato` as the password: computed `ServerSignature` matches `v=YQlegvbEwDo2o60YiK2iAkYyPKE=` and `ClientProof` also validates.

---

## Final Reconstruction

| Element | Value |
|---------|-------|
| Login | `koma_test` |
| Password | `komato` |
| Validation | Matches both `ClientProof` and `ServerSignature` |
| Flag (`SHA1(password)`) | `8f653e36780d5dd7fe7b07e64ff6fde48c3199cb` |

---

## Key Takeaways

- **SCRAM captures allow offline verification** — salt, iterations, proof and signature are available.
- **Two independent verification points** (`ClientProof`, `ServerSignature`) reduce false positives.
- **Password reuse of login fragments collapses search space.**
- **PBKDF2 iterations help but targeted guess+hint attacks remain practical at low iteration counts.**

---

## References

- [RFC 5802 - SCRAM](https://datatracker.ietf.org/doc/html/rfc5802)
- [RFC 6120 - XMPP Core](https://datatracker.ietf.org/doc/html/rfc6120)
- [XMPP Wiki - SCRAM](https://wiki.xmpp.org/web/SASL_Authentication_and_SCRAM)
- [RFC 2898 - PBKDF2](https://datatracker.ietf.org/doc/html/rfc2898)
