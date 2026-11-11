---
brief_id: brief-2026-11-10-amd-zen-info-disclosure
event_id: brief-2026-11-10-amd-zen-info-disclosure
revision: 1
activity_at: "2026-11-10T22:29:43Z"
title: 'AMD Zen: Information disclosure vulnerability (CVE-2026-84005)'
slug: 2026-11-amd-zen-info-disclosure
description: An information disclosure vulnerability in AMD Zen processors allows an authorized attacker to disclose information locally due to processor optimization removal or modification of security-critical code.
date: "2026-11-10T22:29:43Z"
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
  likelihood: unknown
cpes:
  - cpe:2.3:a:amd:zen:*:*:*:*:*:*:*:*
vendors:
  - AMD
products:
  - Zen (processors)
cves:
  - id: CVE-2026-84005
    cvss: 5.5
    kev_status: "false"
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-84005
---

CVE-2026-84005 is an information disclosure vulnerability affecting AMD Zen processors. Processor optimization removal or modification of security-critical code in AMD Zen allows an authorized attacker to disclose information locally.
