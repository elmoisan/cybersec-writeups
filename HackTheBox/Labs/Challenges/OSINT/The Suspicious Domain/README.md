# HTB — "The Suspicious Domain" (OSINT)

**Category:** OSINT  
**Difficulty:** Very Easy  
**XP reward:** 130

---

## Challenge Scenario

> Following the discovery of the suspicious social media profile "TechReviewer2024", investigators have identified a related domain that appears to be part of the same astroturfing campaign. The domain "alexmorgan-reviews.net" has been flagged for hosting fake review content targeting technology companies.
>
> Your task is to investigate this domain's registration information and uncover the contact details hidden within the WHOIS records.

The challenge spawns a web-based instance exposed as an `IP:PORT` pair:

```text
154.57.164.69:44231
```

> The IP and port change every time the instance is respawned.

This challenge is a direct follow-up to the **"Social Media Investigation Hub"** challenge (the `TechReviewer2024` / Alex Morgan astroturfing campaign), pivoting from a social media identity to the infrastructure (domain registration) backing it.

---

## Challenge Structure

The target is a self-contained **OSINT Investigation** web app themed around analyzing the **WHOIS record** of the domain `alexmorgan-reviews.net`. It presents **9 sequential questions**, grouped into several investigation categories (WHOIS Analysis, Contact Intelligence, Temporal Analysis, Entity Research, Geolocation Intelligence, Technical Analysis), with each question rated by difficulty (Easy/Medium/Hard) and accompanied by an explanation once answered correctly.

---

## Tooling

- A web browser — to navigate the challenge's investigation interface
- Basic WHOIS reading skills — to interpret registrant fields, dates, organization names, address data, domain status codes and DNS/hosting configuration

No external tooling is strictly required: the full WHOIS record (and the supporting DNS/hosting details needed for the last question) is presented directly within the challenge interface as the object of investigation.

---

## Investigating the WHOIS Record

### Question 1 — WHOIS Analysis (Easy)

> *What is the registrant's email address from the WHOIS record?*

```text
alex.morgan@tempmail.com
```

**Why it matters:** disposable/temporary email providers like `tempmail.com` are a classic red flag in WHOIS records — legitimate businesses rarely register domains with throwaway email addresses, and such services are favored by threat actors specifically because they're easy to abandon.

### Question 2 — Contact Intelligence (Easy)

> *What is the complete phone number including country code?*

```text
+1-408-555-0987
```

**Why it matters:** phone numbers are strong pivot points in OSINT — the same number reused across multiple domains or profiles is a reliable way to cluster infrastructure belonging to the same campaign or threat actor.

### Question 3 — Temporal Analysis (Medium)

> *When was the domain created?*

```text
2024-01-20
```

**Why it matters:** domain creation dates help establish a campaign's timeline; several related domains registered in a tight window is a strong indicator of coordinated, premeditated activity rather than coincidence.

### Question 4 — Entity Research (Medium)

> *What is the exact organization name from WHOIS?*

```text
Morgan Tech Reviews LLC
```

**Why it matters:** organization names in WHOIS records can be entirely fabricated, but they are still searchable intelligence — and the choice of an "LLC" suffix here is itself a signal of an attempt to appear as a legitimate business entity.

### Question 5 — Geolocation Intelligence (Easy)

> *What city is listed in the registrant's address?*

```text
San Jose
```

**Why it matters:** geographic details help build a profile of the threat actor's claimed location; San Jose's proximity to Silicon Valley makes it a plausible, deliberately chosen backdrop for a tech-industry-themed social engineering campaign.

### Question 6 — Technical Analysis (Hard)

> *What is the domain's transfer status?*

```text
clientTransferProhibited
```

**Why it matters:** domain status (EPP) codes reveal operational security posture. `clientTransferProhibited` is a standard protective measure against unauthorized domain transfers, but threat actors also deliberately set it on their own malicious domains to retain control over infrastructure they rely on.

### Question 7 — Entity Research (Medium)

> *What company is being targeted?*

```text
Techflow
```

Consistent with the astroturfing campaign context established by the prior "Social Media Investigation Hub" challenge (fake negative reviews targeting a tech company's product).

### Question 8 — WHOIS Analysis (Easy)

> *What email service is the threat actor using?*

```text
tempmail
```

### Question 9 — Technical Analysis (Easy)

> *How many GitHub Pages IPs are configured?*

```text
4
```

**Why it matters:** the domain's DNS/hosting configuration pointing to GitHub Pages IPs reveals the delivery infrastructure behind the campaign — a common, low-cost, and easily disposable hosting choice for throwaway astroturfing content.

---

## Summary Table

| # | Category | Difficulty | Question | Answer |
|---|----------|-----------|----------|--------|
| 1 | WHOIS Analysis | Easy | Registrant's email address | `alex.morgan@tempmail.com` |
| 2 | Contact Intelligence | Easy | Complete phone number with country code | `+1-408-555-0987` |
| 3 | Temporal Analysis | Medium | Domain creation date | `2024-01-20` |
| 4 | Entity Research | Medium | Exact organization name | `Morgan Tech Reviews LLC` |
| 5 | Geolocation Intelligence | Easy | City in registrant's address | `San Jose` |
| 6 | Technical Analysis | Hard | Domain transfer status | `clientTransferProhibited` |
| 7 | Entity Research | Medium | Targeted company | `Techflow` |
| 8 | WHOIS Analysis | Easy | Email service used | `tempmail` |
| 9 | Technical Analysis | Easy | Number of GitHub Pages IPs configured | `4` |

Each submission returned a `Correct!` confirmation, bringing the progress counter to **9/9 completed**.

---

## Completing the Investigation

Once every question is answered correctly, the challenge confirms:

```text
Congratulations!
You've answered all questions correctly!

Your final flag is:
```

---

## The Flag

```text
HTB{REDACTED}
```

---

## Takeaways

- WHOIS records remain a core OSINT source, even in an era of widespread privacy/proxy registration — when a registrant doesn't hide behind a privacy service, the registrant name, email, phone, organization, address and dates are all directly actionable.
- Disposable email providers are a reliable red flag. A temporary mail service tied to a domain registration is a strong, simple signal that the registrant did not intend the domain to be traceable long-term — exactly the behavior expected from throwaway astroturfing infrastructure.
- Dates and shared contact details are pivot points, not just facts. A creation date clustered with other related domains, or a phone number reused elsewhere, is what actually lets an investigator connect separate pieces of infrastructure into a single campaign.
- Domain status codes carry dual meaning. `clientTransferProhibited` is a standard legitimate protection, but its presence alone doesn't indicate trustworthiness — it only tells you the current owner wants to keep control of the domain, for whatever reason.
- Infrastructure OSINT complements identity OSINT. This challenge is a natural second step after identifying a person behind a campaign: once a name surfaces, pivoting to domains, hosting and registration data confirms and expands the picture of the operation.
