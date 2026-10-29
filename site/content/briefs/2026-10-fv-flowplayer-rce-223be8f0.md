---
brief_id: brief-2026-10-29-fv-flowplayer-rce-223be8f0
event_id: brief-2026-10-29-fv-flowplayer-rce-223be8f0
revision: 1
activity_at: "2026-10-29T17:37:08Z"
title: 'FV Flowplayer Video Player: PHP Object Injection (CVE-2026-118079)'
slug: 2026-10-fv-flowplayer-rce-223be8f0
description: FV Flowplayer Video Player versions 8.3.4 and earlier are affected by a PHP Object Injection vulnerability.
date: "2026-10-29T17:37:08Z"
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
  - FV Flowplayer Video Player (<= 8.3.4)
cves:
  - id: CVE-2026-118079
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-118079
---

CVE-2026-118079 identifies a PHP Object Injection vulnerability in the FV Flowplayer Video Player plugin, affecting versions 8.3.4 and earlier.

## Impact
Successful exploitation of PHP Object Injection vulnerabilities can lead to significant security risks, including potential data corruption or unauthorized code execution depending on the application environment.
