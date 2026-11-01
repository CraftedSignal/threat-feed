---
brief_id: brief-2026-11-01-ruijie-buffer-overflow
event_id: brief-2026-11-01-ruijie-buffer-overflow
revision: 1
activity_at: "2026-11-01T23:01:15Z"
title: 'Ruijie Managed Switches: Buffer overflow in firmware upgrade interface (CVE-2026-120241)'
slug: 2026-11-ruijie-buffer-overflow
description: A vulnerability in the Local Firmware Upgrade Interface of specific Ruijie switches allows for remote buffer overflow.
date: "2026-11-01T23:01:15Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
vendors:
  - Ruijie
products:
  - RG-ES205GC (ESW_1.0(1)B1P48)
  - RG-ES206GC-P (ESW_1.0(1)B1P48)
  - RG-ES208GC (ESW_1.0(1)B1P48)
  - RG-ES210GC-LP (ESW_1.0(1)B1P48)
  - RG-ES210GS-P (ESW_1.0(1)B1P48)
cves:
  - id: CVE-2026-120241
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120241
---

A vulnerability exists in the httpupg.cgi file within the Local Firmware Upgrade Interface of Ruijie RG-ES205GC, RG-ES206GC-P, RG-ES208GC, RG-ES210GC-LP, and RG-ES210GS-P (version ESW_1.0(1)B1P48). The vulnerability allows for remote buffer overflow. Public exploit code is available. The vendor did not respond to disclosure.
