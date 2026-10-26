---
brief_id: brief-2026-10-26-deepseek-harness-auth
event_id: brief-2026-10-26-deepseek-harness-auth
revision: 1
activity_at: "2026-10-26T17:44:34Z"
title: 'DeepSeek Harness: Improper authorization in Browser Auth component (CVE-2026-116368)'
slug: 2026-10-deepseek-harness-auth
description: DeepSeek Harness up to 0.2.0-rc.2 contains a vulnerability in the Browser Auth component (packages/client/connection/src/browser-auth.ts) that leads to improper authorization and can be initiated remotely.
date: "2026-10-26T17:44:34Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:deepseek:harness:*:*:*:*:*:*:*:*
vendors:
  - DeepSeek
products:
  - Harness (up to 0.2.0-rc.2)
cves:
  - id: CVE-2026-116368
    cvss: 7.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116368
---

A vulnerability, identified as CVE-2026-116368, exists in DeepSeek Harness up to 0.2.0-rc.2. The issue affects the 'packages/client/connection/src/browser-auth.ts' file within the Browser Auth component. This manipulation results in improper authorization and can be exploited remotely. The vendor was contacted regarding this disclosure but did not respond.
