---
brief_id: brief-2026-10-29-oapi-codegen-code-injection
event_id: brief-2026-10-29-oapi-codegen-code-injection
revision: 1
activity_at: "2026-10-29T15:37:07Z"
title: 'oapi-codegen: Code injection via crafted OpenAPI documents (CVE-2026-119027)'
slug: 2026-10-oapi-codegen-code-injection
description: oapi-codegen versions 2.5.0 before 2.8.1 contain a code injection vulnerability allowing attackers to execute Go code via crafted OpenAPI documents.
date: "2026-10-29T15:37:07Z"
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
  - oapi-codegen (2.5.0 before 2.8.1)
cves:
  - id: CVE-2026-119027
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119027
---

oapi-codegen versions 2.5.0 before 2.8.1 contain a code injection vulnerability. Attackers who control an OpenAPI document can supply a crafted servers[].x-go-name value, which the server-urls template emits unescaped. This allows an attacker to define an injected func init() that executes when the victim builds and imports the generated package.
