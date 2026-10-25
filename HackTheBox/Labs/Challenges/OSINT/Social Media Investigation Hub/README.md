# HTB — "Social Media Investigation Hub" (OSINT)

**Category:** OSINT  
**Difficulty:** Very Easy  
**XP reward:** 130

---

## Challenge Scenario

> A tech company has reported suspicious negative reviews appearing across multiple platforms for their new product, the "XyloPhone Pro." Initial investigations suggest these reviews might be part of a coordinated campaign by a competitor. The reviews appear authentic and well-written, but the consistently negative sentiment and coordinated timing across multiple social media platforms raises red flags.
>
> Your task is to investigate the username **"TechReviewer2024"** across multiple social media platforms and uncover evidence of this coordinated activity using cross-platform OSINT techniques.

The challenge is a self-contained web application, **"Social Media Investigation Hub"**, simulating three fictional social media platforms:

```text
ChirpNet
ConnectPro
ForumHub
```

> This challenge doesn't expose a real `IP:PORT` target to connect to with `curl`/`nc`; it is started from the platform's "Start Challenge" button and investigated entirely through the browser.

---

## Challenge Structure

Unlike infrastructure-style challenges, this one is a cross-platform OSINT simulation: three mock social networks each host a profile for the same username, `TechReviewer2024`, with different (but complementary) pieces of information scattered across them. The task is to correlate details across all three platforms — profile headline, employment history, education, posts, follower/following lists, karma — to answer 9 sequential questions, after which the final flag is revealed.

---

## Tooling

- A web browser — to navigate the three simulated platforms and read profiles, posts and connection lists
- No external OSINT tools are actually required: every answer lives inside the challenge's own fictional platforms (it is a self-contained OSINT exercise, not a real-world lookup)

---

## Investigating `TechReviewer2024` Across Platforms

### ChirpNet

Browsing the `TechReviewer2024` profile on **ChirpNet** and checking its **following list** shows a cluster of suspicious accounts (`@ReviewMaster_Bob`, `@TechTruth_Sally`, among others) that were all followed starting the same month — a strong indicator of a coordinated account creation wave rather than organic growth.

### ConnectPro

The **ConnectPro** profile is the richest source of real-world identity data:

- The professional **headline** reveals the real name behind the account: `Alex Morgan (Tech Reviewer)`.
- The **experience section** shows Alex previously worked as a **Marketing Specialist at RivalTech Inc.** from Jan 2021 to Dec 2023 — directly tying the "independent reviewer" persona to a competitor's marketing department.
- The **education section** shows a degree from the **University of California, Berkeley** (Bachelor of Science in Marketing, 2017–2021).
- The profile lists exactly **89 connections** — unusually low for someone presenting themselves as an established professional reviewer, another authenticity red flag.

### ForumHub

The **ForumHub** profile and posts provide the operational smoking gun:

- A post titled **"XyloPhone Pro Campaign Coordination"** names the product being targeted (**XyloPhone Pro**) and lays out talking points for negative reviews.
- The same post reveals the campaign's internal codename: `operation_social_storm_2024`.
- The `u/TechReviewer2024` profile shows a **moderator** role on the `r/TechReviews` subreddit, with 24 posts that month — an influential position to steer sentiment from.
- The profile also shows **1,247 post karma**, indicating a surprising amount of posting activity accumulated in a short time.

---

## Answering the Questions

| # | Question | Answer | Source |
|---|----------|--------|--------|
| 1 | Real name of the person behind `TechReviewer2024`? | `Alex Morgan` | ConnectPro professional headline |
| 2 | Previous employer according to the professional background? | `RivalTech Inc.` | ConnectPro experience section (Jan 2021 – Dec 2023) |
| 3 | Operation codename in the ForumHub coordination post? | `operation_social_storm_2024` | ForumHub post "XyloPhone Pro Campaign Coordination" |
| 4 | Month/year most suspicious reviewer accounts were created? | `February 2024` | ChirpNet following list timestamps |
| 5 | Product targeted by the negative review campaign? | `XyloPhone Pro` | ForumHub coordination post |
| 6 | Role of `TechReviewer2024` in the TechReviews subreddit? | `Moderator` | ForumHub profile (r/TechReviews, 24 posts/month) |
| 7 | Alex Morgan's educational background? | `University of California, Berkeley — B.S. Marketing (2017–2021)` | ConnectPro education section |
| 8 | Number of connections Alex Morgan has on ConnectPro? | `89` | ConnectPro profile |
| 9 | Total post karma of `u/TechReviewer2024` on ForumHub? | `1,247` | ForumHub profile |

Each submission returned a `Correct!` confirmation, progressing through all 9 questions.

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

- Cross-referencing multiple platforms reveals what a single profile hides. No single platform alone exposed the full picture: ChirpNet showed the behavioral pattern (coordinated follows), ConnectPro showed the real-world identity and conflict of interest, and ForumHub showed the actual operational evidence (codename, target product, influence position).
- Professional networking profiles are a goldmine for identity correlation. A "reviewer" persona's real name, employment history and education were all disclosed voluntarily on the ConnectPro-style profile — a common OSINT pattern on real platforms like LinkedIn.
- Small inconsistencies are strong signals. A low connection count for a claimed professional, a cluster of accounts all created in the same month, and surprisingly high karma in a short time are all classic authenticity red flags worth cross-checking rather than taking a profile at face value.
- This is a self-contained OSINT exercise, meaning all evidence lives inside the challenge's own simulated platforms rather than requiring external search engines — the skill being tested is methodical cross-platform correlation, not internet reconnaissance.
