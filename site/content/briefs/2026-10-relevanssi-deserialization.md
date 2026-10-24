---
brief_id: brief-2026-10-24-relevanssi-deserialization
event_id: brief-2026-10-24-relevanssi-deserialization
revision: 1
activity_at: "2026-10-24T16:16:25Z"
title: 'Christoph Vielgrader Relevanssi: Object injection via insecure deserialization (CVE-2026-114704)'
slug: 2026-10-relevanssi-deserialization
description: The Relevanssi WordPress plugin is vulnerable to object injection due to deserialization of untrusted data.
date: "2026-10-24T16:16:25Z"
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
  - cpe:2.3:a:christoph_vielgrader:relevanssi:*:*:*:*:*:*:*:*
vendors:
  - Christoph Vielgrader
products:
  - Relevanssi (n/a through 4.28.4)
cves:
  - id: CVE-2026-114704
    cvss: 7.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-114704
---

The Relevanssi plugin for WordPress, maintained by Christoph Vielgrader, contains a deserialization of untrusted data vulnerability (CVE-2026-114704). This vulnerability allows for object injection. The issue affects Relevanssi versions from n/a through 4.28.4.

## Impact
The vulnerability carries a CVSS v3.1 base score of 7.2.
