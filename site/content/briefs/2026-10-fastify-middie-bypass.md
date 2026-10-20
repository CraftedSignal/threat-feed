---
brief_id: brief-2026-10-20-fastify-middie-bypass
event_id: brief-2026-10-20-fastify-middie-bypass
revision: 1
activity_at: "2026-10-20T21:56:52Z"
title: '@fastify/middie: Security middleware bypass vulnerability (CVE-2026-112712)'
slug: 2026-10-fastify-middie-bypass
description: A path-handling flaw in @fastify/middie versions 9.0.0 through 9.3.5 causes security middleware to be silently skipped, enabling unauthorized access to route handlers.
date: "2026-10-20T21:56:52Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source-verified information only
cpes:
  - cpe:2.3:a:fastify:middie:*:*:*:*:*:*:*:*
tags:
  - web-application
  - security-bypass
  - cve
vendors:
  - Fastify
products:
  - '@fastify/middie (9.0.0-9.3.5)'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: When the two paths disagreed, the middleware was silently skipped while the route handler still ran, so path-scoped middleware such as authentication, authorization, or rate limiting could be bypassed by a single unauthenticated request.
    confidence_band: high
cves:
  - id: CVE-2026-112712
    cvss: 9.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112712
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade @fastify/middie to 9.3.6 or later
      owner: IT Operations
      due: 24h
      evidence: The issue is fixed in @fastify/middie 9.3.6, and users should upgrade to 9.3.6 or later.
  mitigation_plan:
    - priority: immediate
      action: Migrate authorization logic to Fastify preHandler hooks
      owner: IT Operations
      addresses: CVE-2026-112712
      evidence: As a workaround, enforce authorization in a Fastify hook such as preHandler that runs after the router has resolved the request.
---

The @fastify/middie middleware engine, used within the Fastify framework, contains a vulnerability (CVE-2026-112712) in versions 9.0.0 through 9.3.5. The vulnerability arises from an improper path-joining logic within the use() function. When a middleware is path-scoped and combined with a plugin scope prefix, the resulting mount path may diverge from the path recognized by the Fastify router. This issue specifically manifests when the scope prefix ends with a slash, when using array mount paths, or when mount paths are defined without a leading slash.

Crucially, when the router and the middleware engine disagree on the path, the middleware (intended for authentication, authorization, or rate limiting) is silently bypassed, but the intended route handler continues to execute. This vulnerability effectively allows an unauthenticated request to bypass security controls by targeting paths that exploit the path-mismatch. The vulnerability is resolved in @fastify/middie 9.3.6.

## Impact

Successful exploitation allows for the bypass of security guards such as authentication, authorization, and rate-limiting. This can lead to unauthenticated access to sensitive API endpoints, potential data exfiltration, or unauthorized execution of administrative functions within the application. The severity is reflected in a CVSS v3.1 base score of 9.1, indicating a critical impact for organizations relying on middie for access control.

## Recommendation

* Upgrade the @fastify/middie package to version 9.3.6 or later immediately to resolve the underlying path-joining logic issue (CVE-2026-112712).
* As an immediate, temporary mitigation, transition security authorization logic from middie-based path-scoped middleware to Fastify preHandler hooks, which execute after the router has resolved the request path.
* Audit existing middleware configurations to identify instances where plugin scope prefixes or array-based mount paths are used, as these configurations are most susceptible to the path-mismatch logic.
