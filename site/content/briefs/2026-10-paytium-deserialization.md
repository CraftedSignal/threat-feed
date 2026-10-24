---
brief_id: brief-2026-10-24-paytium-deserialization
event_id: brief-2026-10-24-paytium-deserialization
revision: 1
activity_at: "2026-10-24T14:16:53Z"
title: 'Paytium: Deserialization of untrusted data (CVE-2026-114196)'
slug: 2026-10-paytium-deserialization
description: Paytium versions from n/a through 5.0.5 contain a Deserialization of Untrusted Data vulnerability that allows for Object Injection.
date: "2026-10-24T14:16:53Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:paytiumsupport:paytium:*:*:*:*:*:*:*:*
vendors:
  - paytiumsupport
products:
  - Paytium (n/a - 5.0.5)
cves:
  - id: CVE-2026-114196
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-114196
---

CVE-2026-114196 identifies a Deserialization of Untrusted Data vulnerability in the paytiumsupport Paytium plugin. This issue allows for Object Injection and affects versions from n/a through 5.0.5. The vulnerability has a CVSS v3.1 base score of 9.8.
