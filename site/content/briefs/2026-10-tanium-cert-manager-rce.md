---
brief_id: brief-2026-10-27-tanium-cert-manager-rce
event_id: brief-2026-10-27-tanium-cert-manager-rce
revision: 1
activity_at: "2026-10-27T20:01:36Z"
title: 'Tanium Certificate Manager: Unauthorized code execution (CVE-2026-108303)'
slug: 2026-10-tanium-cert-manager-rce
description: Tanium has addressed an unauthorized code execution vulnerability in its Certificate Manager component.
date: "2026-10-27T20:01:36Z"
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
  - cpe:2.3:a:tanium:certificate_manager:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - tanium
vendors:
  - Tanium
products:
  - Certificate Manager
cves:
  - id: CVE-2026-108303
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108303
---

Tanium has addressed an unauthorized code execution vulnerability in Certificate Manager, identified as CVE-2026-108303. The vulnerability has a CVSS v3.1 base score of 8.8.
