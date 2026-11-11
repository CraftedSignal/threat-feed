---
brief_id: brief-2026-11-11-amd-zen-info-disclosure-10959198
event_id: brief-2026-11-11-amd-zen-info-disclosure-10959198
revision: 1
activity_at: "2026-11-11T01:39:01Z"
title: 'AMD Zen: Information disclosure vulnerability (CVE-2026-84004)'
slug: 2026-11-amd-zen-info-disclosure-10959198
description: An information disclosure vulnerability in AMD Zen processors allows an authorized local attacker to disclose information due to processor optimization removal or modification of security-critical code.
date: "2026-11-11T01:39:01Z"
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
cpes:
  - cpe:2.3:a:amd:zen:*:*:*:*:*:*:*:*
vendors:
  - AMD
products:
  - Zen
cves:
  - id: CVE-2026-84004
    cvss: 5.5
    kev_status: "false"
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-84004
---

CVE-2026-84004 affects AMD Zen processors. The vulnerability is caused by the removal or modification of security-critical code during processor optimization. An authorized attacker can exploit this flaw to disclose information locally.
