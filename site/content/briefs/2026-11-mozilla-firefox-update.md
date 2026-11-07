---
brief_id: brief-2026-11-07-mozilla-firefox-update
event_id: brief-2026-11-07-mozilla-firefox-update
revision: 1
activity_at: "2026-11-07T09:39:37Z"
title: 'Mozilla Firefox: Security Vulnerability Update'
slug: 2026-11-mozilla-firefox-update
description: Mozilla has released Firefox version 159.0.1 to address unspecified security vulnerabilities affecting earlier versions.
date: "2026-11-07T09:39:37Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
qa_status:
  verdict: pass
tags:
  - informational
  - software-update
  - browser
vendors:
  - Mozilla
products:
  - Firefox (< 159.0.1)
references:
  - https://cyber.gc.ca/en/alerts-advisories/mozilla-security-advisory-av26-1131
  - https://www.mozilla.org/en-US/security/advisories/mfsa2026-123/
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade all enterprise instances of Mozilla Firefox to version 159.0.1 or later.
      owner: IT Operations
      addresses: Firefox (< 159.0.1)
      evidence: 'Mozilla is affected by a vulnerability in the following product: Firefox Prior to 159.0.1'
---

Mozilla has released an update for the Firefox browser to address security vulnerabilities affecting versions prior to 159.0.1. The specific nature of these vulnerabilities remains undisclosed in the provided advisory. Administrators and users are advised to update their installations to version 159.0.1 or later to mitigate potential risks.

## Recommendation

* Update all instances of Mozilla Firefox to version 159.0.1 or later across the enterprise.
* Monitor the Mozilla Foundation Security Advisories portal for further details on the specific vulnerabilities fixed in MFSA2026-123.
