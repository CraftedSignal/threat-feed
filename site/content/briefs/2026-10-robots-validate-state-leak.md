---
brief_id: brief-2026-10-22-robots-validate-state-leak
event_id: brief-2026-10-22-robots-validate-state-leak
revision: 1
activity_at: "2026-10-22T01:36:26Z"
title: 'Robots-Validate: User-Agent matcher state leakage (CVE-2026-112921)'
slug: 2026-10-robots-validate-state-leak
description: The Robots-Validate Perl module (versions 0.4.3 through 0.4.9) fails to clear User-Agent matcher state between requests, causing legitimate clients to be incorrectly classified as imposter robots.
date: "2026-10-22T01:36:26Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: unlikely
qa_status:
  verdict: pass
tags:
  - vulnerability
  - perl
  - software-bug
  - informational
products:
  - Robots-Validate (0.4.3-0.4.9)
cves:
  - id: CVE-2026-112921
    kev_status: "false"
references:
  - https://seclists.org/oss-sec/2026/q4/301
  - https://metacpan.org/dist/Robots-Validate
action_plan:
  priority: monitor_or_close
  owners:
    - IT Operations
  mitigation_plan:
    - priority: medium
      action: Upgrade Robots-Validate to version 0.4.10 or later
      owner: IT Operations
      addresses: CVE-2026-112921
      evidence: Source advisory reports the issue is resolved in version 0.4.10
---

The Robots-Validate Perl module, specifically versions 0.4.3 through 0.4.9, contains a flaw where the internal state of the User-Agent matcher persists across consecutive requests. This leakage can result in false positive identifications of legitimate clients as imposter robots. The issue is resolved in version 0.4.10.

## Impact

The vulnerability may cause unexpected denial of service or access rejection for legitimate web clients when using the affected module for request validation.

## Recommendation

- Audit systems for usage of the Robots-Validate Perl module.
- Upgrade the Robots-Validate module to version 0.4.10 or later.
