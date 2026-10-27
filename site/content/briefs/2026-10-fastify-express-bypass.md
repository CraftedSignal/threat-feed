---
brief_id: brief-2026-10-27-fastify-express-bypass
event_id: brief-2026-10-27-fastify-express-bypass
revision: 1
activity_at: "2026-10-27T13:49:57Z"
title: '@fastify/express: Authentication bypass via path normalization (CVE-2026-112362)'
slug: 2026-10-fastify-express-bypass
description: An authentication and authorization bypass vulnerability in @fastify/express versions 4.0.5 through 4.0.8 occurs when the non-default ignoreDuplicateSlashes option is enabled, allowing attackers to access restricted handlers by misaligning path normalization between Fastify and Express middleware.
date: "2026-10-27T13:49:57Z"
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
cpes:
  - cpe:2.3:a:fastify:fastify-express:*:*:*:*:*:node.js:*:*
tags:
  - web-application
  - bypass
  - authentication
vendors:
  - Fastify
products:
  - '@fastify/express (4.0.5-4.0.8)'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker needs only the non-default ignoreDuplicateSlashes option to be enabled.
    confidence_band: high
cves:
  - id: CVE-2026-112362
    cvss: 9.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112362
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch @fastify/express to 4.0.9 or later across all production environments
      owner: IT Operations
      due: 24h
      evidence: The issue is fixed in @fastify/express 4.0.9, and users should upgrade to 4.0.9 or later.
  hunt_leads:
    - lead: 'Identify Node.js applications utilizing @fastify/express with ignoreDuplicateSlashes: true'
      technique_id: T1190
      data_needed:
        - Application configuration files (package.json, source code, environment variables)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: An unauthenticated attacker needs only the non-default ignoreDuplicateSlashes option to be enabled.
  mitigation_plan:
    - priority: immediate
      action: Disable ignoreDuplicateSlashes option in Fastify configuration
      owner: IT Operations
      addresses: CVE-2026-112362
      evidence: As a workaround, ... leave ignoreDuplicateSlashes at its default.
---

The @fastify/express plugin, which allows Express middleware to run within a Fastify application, is vulnerable to a bypass of security controls when the non-default `ignoreDuplicateSlashes` configuration is enabled. In versions 4.0.5 through 4.0.8, Fastify's router normalizes the path of an absolute-form request target by collapsing duplicate slashes, including those following the URL scheme. This mismatch causes the Fastify router to route requests to restricted paths while the Express middleware layer fails to recognize the path, effectively skipping authentication, authorization, or rate-limiting logic.

## Impact

An unauthenticated attacker can reach handlers on protected or scoped routes by crafting absolute-form request targets that trigger the path normalization mismatch, bypassing security middleware.

## Recommendation

- Upgrade `@fastify/express` to version 4.0.9 or later.
- As an immediate workaround, disable the `ignoreDuplicateSlashes` configuration option if it is currently enabled.
- Implement authentication/authorization logic within a Fastify `preHandler` hook, as these hooks are executed after the router resolves the request and are not bypassed by this vulnerability.
