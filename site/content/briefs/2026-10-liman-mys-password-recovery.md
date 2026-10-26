---
brief_id: brief-2026-10-26-liman-mys-password-recovery
event_id: brief-2026-10-26-liman-mys-password-recovery
revision: 1
activity_at: "2026-10-26T15:44:14Z"
title: 'HAVELSAN Liman MYS: Password recovery mechanism vulnerability (CVE-2026-94380)'
slug: 2026-10-liman-mys-password-recovery
description: A Weak Password Recovery Mechanism for Forgotten Password vulnerability in HAVELSAN Inc. Liman MYS allows Password Recovery Exploitation.
date: "2026-10-26T15:44:14Z"
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
  - cpe:2.3:a:havelsan:liman_mys:*:*:*:*:*:*:*:*
vendors:
  - HAVELSAN
products:
  - Liman MYS (< 2.3.5-1131)
cves:
  - id: CVE-2026-94380
    cvss: 8.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-94380
---

HAVELSAN Inc. Liman MYS contains a vulnerability identified as CVE-2026-94380. The issue is a Weak Password Recovery Mechanism for Forgotten Password, which allows for Password Recovery Exploitation. 

## Scope

This issue affects Liman MYS from version 2.3.4-1124 before 2.3.5-1131.
