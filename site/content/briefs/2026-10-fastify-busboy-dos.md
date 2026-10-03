---
title: Denial of Service in @fastify/busboy via Prototype Pollution
slug: 2026-10-fastify-busboy-dos
description: An unauthenticated remote attacker can trigger a Denial of Service (DoS) in Node.js applications using @fastify/busboy by submitting crafted multipart/form-data headers naming '__proto__' or 'constructor'.
date: "2026-10-03T04:50:34Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:fastify:busboy:*:*:*:*:*:node.js:*:*
  - cpe:2.3:a:fastify:fastify\/busyboy:*:*:*:*:*:node.js:*:*
vendors:
  - Fastify
products:
  - '@fastify/busboy (>= 1.0.0, < 3.2.1)'
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: The multipart header parser stores part-header names on a plain JavaScript object, so a part header named __proto__ or constructor resolves to an inherited value that is not an array, and the parser throws TypeError.
    confidence_band: high
cves:
  - id: CVE-2026-19481
    cvss: 7.5
    epss: 0.00493
references:
  - https://github.com/advisories/GHSA-x8mw-p69m-v3mx
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19481
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade @fastify/busboy to version 3.2.1 or later
      owner: IT Operations
      due: 48h
      evidence: Fixed in version 3.2.1.
  mitigation_plan:
    - priority: immediate
      action: Add error event listeners to all instances of busboy streams
      owner: Application Security
      addresses: CVE-2026-19481
      evidence: Attach an error listener to the Busboy stream so the parser failure is handled rather than crashing the process.
---

The @fastify/busboy library, a popular Node.js multipart form data parser, contains a critical vulnerability tracked as CVE-2026-19481. The flaw resides in the library's multipart header parser, which stores part-header names directly on a plain JavaScript object without appropriate validation. An attacker can supply a malicious header name, specifically '__proto__' or 'constructor', which resolves to inherited JavaScript object properties instead of the expected array. This discrepancy causes the parser to execute 'this.header[h].push', resulting in a 'TypeError: this.header[h].push is not a function'. If the application does not explicitly catch the error event or wrap the stream methods in a try/catch block, the resulting exception can cause the Node.js process to crash, facilitating a remote Denial of Service attack. This vulnerability affects all versions from 1.0.0 up to, but not including, 3.2.1.

## Impact

The vulnerability allows unauthenticated remote attackers to terminate Node.js processes handling multipart file uploads or form submissions. This impacts any application using @fastify/busboy for processing incoming web requests. If the application environment lacks robust supervisor processes to auto-restart the application, the service will remain unavailable, resulting in a complete denial of service for the affected component.

## Recommendation

Prioritized actions for engineering and security teams:

* Update the @fastify/busboy dependency to version 3.2.1 or later immediately to incorporate the upstream patch.
* For legacy deployments where patching is delayed, ensure all busboy stream instances have a registered 'error' event listener to prevent process termination on parser failure.
* Audit application code for direct usage of 'write()' or 'end()' methods on Busboy instances and wrap these calls in 'try/catch' blocks.
