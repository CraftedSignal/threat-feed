---
brief_id: brief-2026-11-10-ettercap-integer-underflow
event_id: brief-2026-11-10-ettercap-integer-underflow
revision: 1
activity_at: "2026-11-10T02:05:39Z"
title: 'Ettercap: Integer underflow in ccmp_decrypt (CVE-2026-125404)'
slug: 2026-11-ettercap-integer-underflow
description: Ettercap versions through 0.8.4.1 contain an integer underflow in the ccmp_decrypt function that can result in a stack buffer overflow.
date: "2026-11-10T02:05:39Z"
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
products:
  - Ettercap <= 0.8.4.1 (<= 0.8.4.1)
cves:
  - id: CVE-2026-125404
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-125404
---

Ettercap versions through 0.8.4.1 contain an integer underflow in `ccmp_decrypt()` in `src/ec_encryption_ccmp.c` due to a failure to check the minimum length when subtracting the 8-byte CCMP trailer. Attackers on a network where the WPA key is loaded can send a short, crafted CCMP frame to overflow a stack buffer in the Ettercap process, which normally runs as root.
