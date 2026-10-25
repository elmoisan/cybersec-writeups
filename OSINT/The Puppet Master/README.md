# HTB — "The Puppet Master" (OSINT)

**Category:** OSINT  
**Difficulty:** Very Easy  
**XP reward:** 130

---

## Challenge Scenario

> Trainee,
>
> Our investigation into the cryptocurrency funding trail has led us to RivalTech Corporation. A recent data breach at their corporate servers has exposed internal communications, employee records, and strategic planning documents.
>
> Your mission is to navigate the BreachScope database and identify the senior executive who orchestrated the comprehensive fake review campaign against XyloPhone Inc. Look for evidence of direct approval, budget authorization, and campaign coordination.
>
> Submit your findings in the format: `HTB{executive_identification}`. Example: `HTB{CEO_Thomas_Wilson_Approved_Budget}`
>
> – Training Division Digital Forensics Unit

The challenge spawns a web-based instance exposed as an `IP:PORT` pair:

```text
154.57.164.69:42328
```

> The IP and port change every time the instance is respawned.

---

## Challenge Structure

Unlike a classic single-stage OSINT challenge, this one is split into two layers:

1. A self-contained investigation inside a fictional "BreachScope" database (leaked emails, employee records, planning documents) that has to be navigated to identify the senior executive behind the fake review campaign against XyloPhone Inc.
2. A progressive, real-world OSINT quiz (5 sequential questions) built around a photo of a military vehicle, which has to be answered correctly, in order, before the final flag is revealed.

Both layers have to be completed for the "MISSION ACCOMPLISHED" screen and the flag to appear — this is explicitly the point of the challenge, as its own flag later confirms: *"c0mb1n1ng_r34l_w0rld_4nd_s3lf_c0nt41n3d_OSINT"*.

---

## Tooling

- A web browser — to navigate the BreachScope interface and read the leaked documents
- A reverse image search engine (Google Images, Yandex, TinEye) — to identify the vehicle in the photo
- General web search — to research the vehicle's manufacturer, service history, country of origin and capacity

---

## Stage 1 — Navigating the BreachScope Database

Opening the target in a browser presents a mock leaked-data portal ("BreachScope") themed around the fictional RivalTech Corporation. Browsing through the exposed internal communications, employee records and strategic planning documents reveals the paper trail of a fake review campaign against a competitor, XyloPhone Inc.:

- Internal messages discussing the campaign's planning and execution.
- A chain of approvals tied to budget authorization.
- A specific senior executive's name attached to the direct approval and coordination of the operation.

Following that evidence trail through the leaked documents identifies the executive responsible, which is the information requested in the scenario's submission format (`HTB{executive_identification}`).

---

## Stage 2 — The Progressive OSINT Quiz

The second part of the challenge shows a photograph of a military vehicle and asks five questions in sequence — each one must be answered correctly before the next unlocks.

### Question 1 — Vehicle Identification

> What type of military vehicle is shown in the image?

A reverse image search of the photo, combined with the visible characteristics described in the hint (wheeled, armored, personnel carrier), identifies the vehicle:

```text
Answer: Bushmaster
```

### Question 2 — Manufacturer Identification

> Who is the manufacturer/designer of this vehicle?

Researching the Bushmaster vehicle family identifies the company that designed and produces it:

```text
Answer: Thales Australia
```

### Question 3 — Service History

> When did this vehicle first enter military service?

```text
Answer: 1997
```

### Question 4 — Country of Origin

> What is the country of origin for this vehicle?

Consistent with the manufacturer (Thales Australia):

```text
Answer: Australia
```

### Question 5 — Vehicle Capacity

> What is the passenger capacity of this vehicle?

```text
Answer: 9 passengers and 1 driver
```

Each answer was accepted with a `Correct! Well done.` confirmation, progressing the counter to **5 / 5 completed**.

---

## Completing the Investigation

Once both stages are complete, the challenge displays:

```text
Investigation Complete
All evidence analyzed. Submit for final flag validation.

MISSION ACCOMPLISHED
Excellent OSINT analysis. Final flag:
```

---

## The Flag

```text
HTB{REDACTED}
```

---

## Takeaways

- Not all OSINT is about the open internet. This challenge deliberately mixes a self-contained investigation with a real-world OSINT task — the flag text itself calls this out directly.
- Progressive and sequential question flows are common in OSINT challenges. Each answer had to be submitted and validated before the next question appeared, so working methodically through the chain was more effective than trying to jump ahead.
- Reverse image search is often the fastest entry point for "what is this object" style OSINT questions — once the vehicle family is identified, the remaining details are public and easy to confirm with a couple of searches.
- Reading the fictional scenario carefully pays off. The expected submission format for the first stage was explicitly given in the briefing, which makes it clear what kind of evidence to look for while navigating the leaked documents.
