---
brief_id: brief-2026-10-28-mozilla-advisory
event_id: brief-2026-10-28-mozilla-advisory
revision: 2
activity_at: "2026-11-03T16:02:10Z"
revision_history:
  - revision: 2
    at: "2026-11-03T16:02:10Z"
    checksum: sha256:e382a3947443e6afb0fe42d9a61b3bc18607de051bba6f42c09609af2590345e
    summary: added CVE-2026-120572
    changed_fields:
      - affected_products
      - claim_state
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-120572
title: Mozilla Firefox, Firefox ESR, and Thunderbird vulnerabilities
slug: 2026-10-mozilla-advisory
description: Multiple vulnerabilities affecting Mozilla Firefox, Firefox ESR, and Thunderbird have been disclosed, necessitating updates to the latest versions to mitigate potential security risks.
date: "2026-10-28T23:59:19Z"
lastmod: "2026-11-03T16:01:01Z"
type: advisory
claim_state: <nil>
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
  - Firefox (< 159.0.1)
cves:
  - id: CVE-2026-120572
    cvss: 8.8
    kev_status: "false"
references:
  - https://cyber.gc.ca/en/alerts-advisories/mozilla-security-advisory-av26-1100
  - https://www.mozilla.org/en-US/security/advisories/mfsa2026-118/
  - https://www.mozilla.org/en-US/security/advisories/mfsa2026-119/
  - https://www.mozilla.org/en-US/security/advisories/mfsa2026-120/
  - https://www.mozilla.org/en-US/security/advisories/mfsa2026-121/
  - https://www.mozilla.org/en-US/security/advisories/mfsa2026-122/
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120572
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
updates:
  - at: "2026-11-03T16:01:01Z"
    level: L2
    summary: added CVE-2026-120572
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-120572
---

The Canadian Centre for Cyber Security (CCCS) has issued an advisory (AV26-1100) regarding security vulnerabilities identified in Mozilla Firefox, Firefox ESR, and Thunderbird. Users and administrators are advised to update their software to the versions specified in the Mozilla Foundation Security Advisories (MFSA2026-118, 119, 120, 121, and 122).

## Recommendation

- Upgrade Firefox to version 159 or later.
- Upgrade Firefox ESR to version 115.44 or 153.6 or later.
- Upgrade Thunderbird to version 159 or 153.6 or later.
- Review the specific Mozilla Foundation Security Advisories linked in the references to understand the scope and impact of the patched vulnerabilities.
