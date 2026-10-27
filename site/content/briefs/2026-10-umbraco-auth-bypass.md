---
brief_id: brief-2026-10-27-umbraco-auth-bypass
event_id: brief-2026-10-27-umbraco-auth-bypass
revision: 1
activity_at: "2026-10-27T15:49:43Z"
title: 'Umbraco CMS: Authentication bypass (CVE-2026-117553)'
slug: 2026-10-umbraco-auth-bypass
description: Umbraco CMS contains an authentication bypass vulnerability involving Host header poisoning that allows unauthenticated attackers to hijack back-office sessions and execute code via Razor templates.
date: "2026-10-27T15:49:43Z"
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
  - cpe:2.3:a:umbraco:cms:*:*:*:*:*:*:*:*
vendors:
  - Umbraco
products:
  - Umbraco CMS (< 17.7.2)
  - Umbraco CMS (< 18.2.2)
cves:
  - id: CVE-2026-117553
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-117553
---

Umbraco CMS versions before 17.7.2 and 18.2.2 contain an authentication bypass vulnerability. Unauthenticated attackers can poison the Host header to register attacker-controlled OAuth redirect URIs. By sending authorization links using `response_mode=form_post` to signed-in users, attackers can capture authorization codes. These codes can be redeemed via HTTP Basic client credentials to hijack back-office sessions and execute code through Razor templates.
