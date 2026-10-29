---
brief_id: brief-2026-10-28-mozilla-advisory
event_id: brief-2026-10-28-mozilla-advisory
revision: 1
activity_at: "2026-10-28T23:59:19Z"
title: Mozilla Firefox, Firefox ESR, and Thunderbird vulnerabilities
slug: 2026-10-mozilla-advisory
description: Multiple vulnerabilities affecting Mozilla Firefox, Firefox ESR, and Thunderbird have been disclosed, necessitating updates to the latest versions to mitigate potential security risks.
date: "2026-10-28T23:59:19Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - informational
  - product-news
vendors:
  - Mozilla
products:
  - Firefox (< 159)
  - Firefox ESR (< 115.44)
  - Firefox ESR (< 153.6)
  - Thunderbird (< 159)
  - Thunderbird (< 153.6)
references:
  - https://cyber.gc.ca/en/alerts-advisories/mozilla-security-advisory-av26-1100
  - https://www.mozilla.org/en-US/security/advisories/mfsa2026-118/
  - https://www.mozilla.org/en-US/security/advisories/mfsa2026-119/
  - https://www.mozilla.org/en-US/security/advisories/mfsa2026-120/
  - https://www.mozilla.org/en-US/security/advisories/mfsa2026-121/
  - https://www.mozilla.org/en-US/security/advisories/mfsa2026-122/
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Update Firefox, Firefox ESR, and Thunderbird to the latest patched versions as identified in the advisory.
      owner: IT Operations
      addresses: Vulnerabilities addressed in MFSA2026-118 through MFSA2026-122
      evidence: The Cyber Centre encourages users and administrators to review the provided web links and apply any necessary updates as they become available.
---

The Canadian Centre for Cyber Security (CCCS) has issued an advisory (AV26-1100) regarding security vulnerabilities identified in Mozilla Firefox, Firefox ESR, and Thunderbird. Users and administrators are advised to update their software to the versions specified in the Mozilla Foundation Security Advisories (MFSA2026-118, 119, 120, 121, and 122).

## Recommendation

- Upgrade Firefox to version 159 or later.
- Upgrade Firefox ESR to version 115.44 or 153.6 or later.
- Upgrade Thunderbird to version 159 or 153.6 or later.
- Review the specific Mozilla Foundation Security Advisories linked in the references to understand the scope and impact of the patched vulnerabilities.
