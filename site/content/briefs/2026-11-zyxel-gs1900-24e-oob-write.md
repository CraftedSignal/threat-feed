---
brief_id: brief-2026-11-03-zyxel-gs1900-24e-oob-write
event_id: brief-2026-11-03-zyxel-gs1900-24e-oob-write
revision: 1
activity_at: "2026-11-03T03:50:17Z"
title: 'Zyxel GS1900-24E: Out-of-bounds write vulnerability (CVE-2026-107441)'
slug: 2026-11-zyxel-gs1900-24e-oob-write
description: An out-of-bounds write vulnerability in the CGI program of Zyxel GS1900-24E firmware versions through 2.90(AAHK.2)C0 could allow an unauthenticated adjacent attacker to potentially execute OS commands via a crafted HTTP request.
date: "2026-11-03T03:50:17Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: not_observed
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:zyxel:gs1900_24e:*:*:*:*:*:*:*:*
vendors:
  - Zyxel
products:
  - GS1900-24E (through firmware 2.90(AAHK.2)C0)
cves:
  - id: CVE-2026-107441
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107441
---

An out-of-bounds write vulnerability exists in the CGI program of Zyxel GS1900-24E firmware versions through 2.90(AAHK.2)C0. This flaw may allow an unauthenticated adjacent attacker to potentially execute OS commands via a crafted HTTP request. The vulnerability is identified as CVE-2026-107441 with a CVSS v3.1 base score of 8.8.
