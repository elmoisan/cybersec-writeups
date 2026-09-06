# SIP - Authentification

`Network` • `Easy` • `20 pts`

## TL;DR

Analyse d'une capture SIP pré-extrait (format `sipdump`/`sipcrack`). Parsage des champs, reconnaissance du schéma Digest Authentication, lecture du mot de passe en clair ou vérification via la réponse MD5 challenge-response pour récupérer le mot de passe du compte SIP.

**Flag:** `[REDACTED]`

---

## Challenge Description

> Analyse de capture réseau.
>
> Retrouvez le mot de passe utilisé pour s'authentifier sur l'infrastructure SIP.

**Provided file:** `ch4.txt`

---

## Recon

Le fichier n'est pas un PCAP brut — il est déjà au format `sipdump`/`sipcrack`, où les champs sont séparés par `"` :

```
SERVER_IP"CLIENT_IP"USER"REALM"METHOD"URI"NONCE"CNONCE"NC"QOP"ALGORITHM"HASH
```

Trois lignes sont présentes, toutes pour la même paire client/serveur (`172.25.105.3 <-> 172.25.105.40`, extension `555`, realm `asterisk`):

| Method | Nonce | Algorithm | Value |
|--------|-------|-----------|-------|
| `REGISTER` | `4787f7ce` | `PLAIN` | `1234` |
| `INVITE` `sip:1000@172.25.105.40` | `70fbfdae` | `MD5` | `aa533f6efa2b2abac675c1ee6cbde327` |
| `BYE` `sip:1000@172.25.105.40` | `70fbfdae` | `MD5` | `0b306e9db1f819dd824acf3227b60e07` |

La ligne `REGISTER` se distingue : taggée `PLAIN` au lieu de `MD5`, donc le mot de passe apparaît en clair.

---

## Exploitation

### 1) Installer `sipcrack` et reproduire le format

```bash
apt-get install -y sipcrack
```

Le fichier fourni correspond déjà à l'entrée attendue par `sipcrack` et peut être lu directement.

### 2) Lire le mot de passe en clair

Le champ `PLAIN"1234"` de la ligne `REGISTER` révèle le mot de passe en clair — pas besoin de cassage.

### 3) Vérification via SIP Digest (MD5)

Formules SIP Digest :

$$HA1 = MD5(user:realm:password)$$
$$HA2 = MD5(method:uri)$$
$$response = MD5(HA1:nonce:HA2)$$

Avec `user = 555`, `realm = asterisk`, `password = 1234` :

- `INVITE sip:1000@172.25.105.40`, nonce `70fbfdae` → réponse calculée correspond à `aa533f6efa2b2abac675c1ee6cbde327` ✅
- `BYE sip:1000@172.25.105.40`, nonce `70fbfdae` → réponse calculée correspond à `0b306e9db1f819dd824acf3227b60e07` ✅

Les deux digests correspondent, confirmant le mot de passe.

---

## Final Reconstruction

| Line | Method | Auth type | Result |
|------|--------|-----------|--------|
| 1 | `REGISTER` | `PLAIN` | Password leaked in cleartext |
| 2 | `INVITE` | `MD5` Digest | Confirms password via hash match |
| 3 | `BYE` | `MD5` Digest | Confirms password via hash match |

Password recovered: `1234`.

---

## Key Takeaways

- **SIP Digest weaknesses:** une seule ligne en clair peut compromettre tous les échanges basés sur Digest.
- **Cross-validation :** vérifier le mot de passe suspect contre la formule MD5 avant de le valider.
- **Tooling :** `sipcrack`/`sipdump` utilisent un format quote-delimited courant pour captures SIP.
- **Weak credentials :** un mot de passe numérique de 4 chiffres est trivialement devinable.

---

## References

- [RFC 3261 - SIP: Session Initiation Protocol](https://datatracker.ietf.org/doc/html/rfc3261)
- [RFC 2617 - HTTP Digest Access Authentication](https://datatracker.ietf.org/doc/html/rfc2617)
- [sipcrack / sipdump - man page](https://manpages.ubuntu.com/manpages/noble/man1/sipcrack.1.html)
