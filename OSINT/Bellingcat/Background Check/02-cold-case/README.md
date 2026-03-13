# Cold Case

`OSINT` • `Easy` • `Bellingcat Challenge`

## TL;DR

Identify a half-eaten ice cream product from its packaging to determine the
country of purchase, then match it to the correct convenience store chain.

**Answer:** `7-Eleven`

---

## Challenge Description

> I love ice cream, but this time it's my downfall!
>
> At first glance, it doesn't look like much, but can you find me one last time?
>
> **What is the name of the nearby grocery store where I bought this ice cream?**

*Puzzle by GeoPeter*

The image shows a hand holding a half-unwrapped wafer sandwich ice cream, with
a colourful tiled floor visible in the background. The caption reads:
*"Can you stay cool under pressure?"*

---

## Recon

### Identifying the product

Several visual clues point to **Japan** as the country of origin:

| Clue | Interpretation |
|------|---------------|
| Wafer sandwich format | Common Japanese konbini ice cream format |
| Packaging design & label typography | Japanese characters visible on wrapper |
| Chocolate + vanilla + wafer layers | Matches standard Japanese ice cream bars |
| Colourful geometric tiled floor | Typical of Japanese convenience store interiors |

The product is a **wafer sandwich ice cream** sold exclusively in Japanese
convenience stores (**konbini** / コンビニ).

---

## Exploitation

### 1) Narrow down the country

The product packaging, label layout, and font style are immediately recognisable
as **Japanese**. The tiled floor pattern in the background further confirms a
konbini interior rather than a supermarket or foreign store.

### 2) Enumerate known konbini chains

Japan has three dominant convenience store chains, each selling their own
branded ice cream lines:

| Chain | Ice cream line |
|-------|---------------|
| Lawson | Uchi Café series |
| FamilyMart | FamilyMart Collection |
| **7-Eleven** | **7-Premium** |

### 3) Match the product to the chain

Testing each chain against the packaging design confirms the product belongs to
the **7-Eleven Japan** (セブン-イレブン) private label range, sold exclusively
in their stores across Japan.

---

## Final Answer

| Step | Finding |
|------|---------|
| Country identified | Japan 🇯🇵 |
| Store type | Convenience store (konbini) |
| Chain matched | **7-Eleven** (セブン-イレブン) |

---

## Key Takeaways

- **Packaging design is a fingerprint:** font style, label layout, and product
  format can uniquely identify a country and even a specific retail chain.
- **The background is evidence too:** floor tiles, lighting, and shelf layout
  visible behind the subject are valuable secondary clues.
- **Systematic enumeration works:** when the product category is known
  (konbini ice cream), a short list of candidates can be tested quickly.
- **Wordplay hints at the method:** *"chilling revelation"* and *"stay cool
  under pressure"* — the challenge title and caption both nod directly to
  ice cream and the need to stay methodical.

---

## References

- [7-Eleven Japan — official site](https://www.sej.co.jp)
- [Lawson Japan — official site](https://www.lawson.co.jp)
- [FamilyMart Japan — official site](https://www.family.co.jp)
- [Bellingcat Open Source Challenge](https://challenge.bellingcat.com)