---
brief_id: brief-2026-10-30-lago-auth-bypass
event_id: brief-2026-10-30-lago-auth-bypass
revision: 1
activity_at: "2026-10-30T13:29:29Z"
title: 'Lago: Authentication bypass in acceptInvite mutation (CVE-2026-119420)'
slug: 2026-10-lago-auth-bypass
description: Lago versions through 1.55.0 contain an authentication bypass vulnerability that allows organization administrators to obtain session tokens for existing accounts via the acceptInvite mutation without a password check.
date: "2026-10-30T13:29:29Z"
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
  - Lago (<= 1.55.0)
cves:
  - id: CVE-2026-119420
    cvss: 8.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119420
---

Lago versions through 1.55.0 are vulnerable to an authentication bypass via the acceptInvite mutation. An attacker can invite a victim's email, accept the invitation with an arbitrary password, and receive a JWT. This enables access to the victim's organizations, billing data, API keys, and payment integrations.
