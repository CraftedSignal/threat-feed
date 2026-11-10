---
brief_id: brief-2026-11-10-kubero-auth-bypass
event_id: brief-2026-11-10-kubero-auth-bypass
revision: 1
activity_at: "2026-11-10T02:00:29Z"
title: 'Kubero: Authentication bypass via hardcoded JWT secret (CVE-2026-125370)'
slug: 2026-11-kubero-auth-bypass
description: Kubero versions 3.0.0 through 3.1.1 contain an authentication bypass vulnerability that allows unauthenticated remote attackers to forge administrative JWTs by using a hardcoded fallback signing secret when JWT_SECRET is unset.
date: "2026-11-10T02:00:29Z"
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
  - cpe:2.3:a:kubero:kubero:*:*:*:*:*:*:*:*
vendors:
  - Kubero
products:
  - Kubero (3.0.0 through 3.1.1)
cves:
  - id: CVE-2026-125370
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-125370
---

Kubero 3.0.0 through 3.1.1 contains an authentication bypass vulnerability. When JWT_SECRET is unset, the application uses a hardcoded fallback signing secret. This allows unauthenticated remote attackers to forge administrative JWTs with arbitrary role, userGroups, and permissions claims. The JwtStrategy.validate() method trusts these forged tokens without performing a database lookup, allowing attackers to take control of pipelines, applications, users, and API tokens.
