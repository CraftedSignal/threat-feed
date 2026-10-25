---
brief_id: brief-2026-10-25-eyoucms-ssrf
event_id: brief-2026-10-25-eyoucms-ssrf
revision: 1
activity_at: "2026-10-25T22:30:07Z"
title: 'EyouCMS: Server-side request forgery (CVE-2026-116094)'
slug: 2026-10-eyoucms-ssrf
description: EyouCMS versions up to 1.8.3 contain a server-side request forgery (SSRF) vulnerability in the remote_file_to_local function of application/function.php.
date: "2026-10-25T22:30:07Z"
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
  - cpe:2.3:a:eyoucms:eyoucms:*:*:*:*:*:*:*:*
vendors:
  - EyouCMS
products:
  - EyouCMS (<= 1.8.3)
cves:
  - id: CVE-2026-116094
    cvss: 7.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116094
---

A vulnerability has been identified in EyouCMS up to version 1.8.3. The vulnerability affects the function remote_file_to_local within the file application/function.php. This flaw allows for remote server-side request forgery (SSRF). The exploit has been publicly disclosed and may be utilized. The vendor was contacted but did not respond.
