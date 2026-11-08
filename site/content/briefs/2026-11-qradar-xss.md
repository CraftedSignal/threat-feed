---
brief_id: brief-2026-11-08-qradar-xss
event_id: brief-2026-11-08-qradar-xss
revision: 1
activity_at: "2026-11-08T19:34:15Z"
title: 'IBM QRadar: Reflected Cross-Site Scripting (CVE-2026-105467)'
slug: 2026-11-qradar-xss
description: IBM QRadar versions 7.5.0 through 7.5.0 Update Pack 16 Interim Fix 02, and 7.6.0.0 through 7.6.0.5 are vulnerable to Reflected XSS. Triggering the vulnerability requires an authenticated user to open a specifically crafted URL.
date: "2026-11-08T19:34:15Z"
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
  - cpe:2.3:a:ibm:qradar:*:*:*:*:*:*:*:*
vendors:
  - IBM
products:
  - QRadar (7.5.0 through 7.5.0 Update Pack 16 Interim Fix 02, 7.6.0.0 through 7.6.0.5)
cves:
  - id: CVE-2026-105467
    cvss: 8.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105467
---

IBM QRadar 7.5.0 through 7.5.0 Update Pack 16 Interim Fix 02, and 7.6.0.0 through 7.6.0.5 are vulnerable to Reflected XSS. A victim must open a specifically crafted URL while authenticated to QRadar to trigger this.
