---
title: Fastify Request Body Replacement Vulnerability via Async Validation Result
slug: 2026-10-fastify-validation-collision
description: A vulnerability in Fastify's request validation logic (CVE-2026-84504) allows attackers to perform request body replacement when using $async JSON schema validators, leading to potential unauthorized state changes or data disclosure.
date: "2026-10-01T04:21:02Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:fastify:fastify:*:*:*:*:*:*:*:*
  - cpe:2.3:a:fastify:fastify:*:*:*:*:*:node.js:*:*
tags:
  - web-application
  - vulnerability
  - cve
vendors:
  - Fastify
products:
  - fastify (< 5.12.2)
cves:
  - id: CVE-2026-84504
    cvss: 8.1
    epss: 0.00428
references:
  - https://github.com/advisories/GHSA-667r-xxjv-c9mm
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade Fastify to 5.12.2 or 6.0.0
      owner: IT Operations
      due: 48h
      evidence: Patched in fastify 5.12.2 and 6.0.0.
  mitigation_plan:
    - priority: immediate
      action: Identify routes using $async schemas and move sensitive validation to hooks
      owner: Application Security
      addresses: CVE-2026-84504
      evidence: Perform the security-sensitive check in an onRequest or preHandler hook.
---

Fastify suffers from a validation logic flaw (CVE-2026-84504) where the framework incorrectly processes results from asynchronous JSON schema validators. The framework is designed to unwrap results shaped like `{ value, error }` to support synchronous custom compilers, where the `value` replaces the request part and `error` triggers a failure. However, $async validators in JSON schema resolve to the validated data itself. Fastify incorrectly applied the same unwrapping logic to these asynchronous results. 

If a request body processed by an $async schema contains a top-level `value` property, Fastify replaces the entire request part with that nested value before the application handler executes. An attacker can manipulate this behavior by crafting a payload containing controlled `value` or `error` properties, effectively bypassing the intended schema validation. This allows attackers to submit payloads that the application incorrectly believes have been validated, potentially leading to unauthorized state changes or information disclosure if the backend logic relies on the integrity of the schema-validated object.

## Impact

The vulnerability affects applications built with Fastify versions prior to 5.12.2 and 6.0.0 that utilize $async request schemas. Successful exploitation allows an attacker to bypass data validation controls, potentially resulting in unauthorized administrative actions, privilege escalation, or unauthorized access to sensitive application data depending on the specific implementation of the endpoint logic.

## Recommendation

- Upgrade Fastify to version 5.12.2 or 6.0.0 immediately to apply the patch which prevents asynchronous validation results from triggering request part replacement.
- Audit existing routes to identify those utilizing $async request schemas and perform secondary validation within 'onRequest' or 'preHandler' hooks as a temporary mitigation.
- Refactor custom async validator compilers to signal failure by rejecting or throwing an exception, rather than returning an `{ error }` object, until a full patch is applied.
