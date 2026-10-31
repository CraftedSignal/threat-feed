---
brief_id: brief-2026-10-31-jpom-auth-bypass-0b421525
event_id: brief-2026-10-31-jpom-auth-bypass-0b421525
revision: 1
activity_at: "2026-10-31T22:05:24Z"
title: 'Jpom: Authentication bypass and command execution (CVE-2026-120201)'
slug: 2026-10-jpom-auth-bypass-0b421525
description: Jpom versions 2.10.0 through 2.11.12 contain an authentication bypass vulnerability that allows unauthenticated attackers to gain super-administrator access and execute commands.
date: "2026-10-31T22:05:24Z"
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
  - cpe:2.3:a:jpom:jpom:*:*:*:*:*:*:*:*
vendors:
  - Jpom
products:
  - Jpom (2.10.0 through 2.11.12)
cves:
  - id: CVE-2026-120201
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120201
---

Jpom versions 2.10.0 through 2.11.12 are vulnerable to an authentication bypass. Unauthenticated attackers can gain super-administrator access by injecting query conditions into the JPOM-USER-TOKEN header. By providing a value such as 'is not null', the underlying Hutool Condition parser processes the input as an operator. Once access is gained, attackers can execute commands using Jpom's script features.
