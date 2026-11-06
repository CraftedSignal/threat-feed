---
brief_id: brief-2026-11-06-agenta-ssrf
event_id: brief-2026-11-06-agenta-ssrf
revision: 1
activity_at: "2026-11-06T17:26:18Z"
title: 'Agenta: Server-side request forgery vulnerability (CVE-2026-123786)'
slug: 2026-11-agenta-ssrf
description: Agenta versions before 0.122.5 contain a server-side request forgery vulnerability allowing workspace members with workflow edit rights to redirect workflow invocations via arbitrary revision URLs.
date: "2026-11-06T17:26:18Z"
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
  - cpe:2.3:a:agenta:agenta:*:*:*:*:*:*:*:*
vendors:
  - Agenta
products:
  - Agenta (< 0.122.5)
cves:
  - id: CVE-2026-123786
    cvss: 8.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-123786
---

Agenta before 0.122.5 contains a server-side request forgery vulnerability that allows workspace members with workflow edit rights to redirect workflow invocations by setting arbitrary revision URLs. Attackers can capture the attached secret-resolve Authorization token to read provider secrets from the vault API, or reach internal and cloud metadata addresses.
