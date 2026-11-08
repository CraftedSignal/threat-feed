---
brief_id: brief-2026-11-08-ibm-process-mining-info-disclosure
event_id: brief-2026-11-08-ibm-process-mining-info-disclosure
revision: 1
activity_at: "2026-11-08T19:33:00Z"
title: 'IBM Process Mining: Improper access control (CVE-2026-114464)'
slug: 2026-11-ibm-process-mining-info-disclosure
description: IBM Process Mining 2.0.0 through 2.2.1 could allow a remote attacker to obtain sensitive information due to improper access control.
date: "2026-11-08T19:33:00Z"
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
  - cpe:2.3:a:ibm:process_mining:*:*:*:*:*:*:*:*
vendors:
  - IBM
products:
  - Process Mining (2.0.0 through 2.2.1)
cves:
  - id: CVE-2026-114464
    cvss: 9.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-114464
---

IBM Process Mining versions 2.0.0 through 2.2.1 are affected by a vulnerability involving improper access control. This vulnerability could allow a remote attacker to obtain sensitive information.
