---
title: Denial of Service in figlet Node.js Library
slug: 2026-10-figlet-dos
description: 'An infinite loop vulnerability in the figlet Node.js library, tracked as CVE-2026-96780, allows unauthenticated attackers to exhaust CPU and memory resources if they can influence the ''width'' parameter in applications using ''whitespaceBreak: true''.'
date: "2026-10-02T22:50:20Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:figlet_project:figlet:*:*:*:*:*:node.js:*:*
products:
  - figlet (< 1.11.3)
cves:
  - id: CVE-2026-96780
    epss: 0.00405
references:
  - https://github.com/advisories/GHSA-62ch-8vmq-8xm7
  - https://nvd.nist.gov/vuln/detail/CVE-2026-96780
action_plan:
  priority: elevated
  owners:
    - Development
    - DevOps
  immediate_actions:
    - action: Upgrade figlet to 1.11.3 across all production environments
      owner: Development
      due: 72h
      evidence: Fixed in figlet 1.11.3
  mitigation_plan:
    - priority: immediate
      action: Validate or sanitize user input used in the width parameter of figlet calls
      owner: Development
      addresses: CVE-2026-96780
      evidence: Do not expose width to untrusted input
---

The figlet Node.js library (versions prior to 1.11.3) is susceptible to a denial-of-service vulnerability triggered by an unbounded loop in the `breakWord()` function. The flaw occurs when an application calls `text()` or `textSync()` with the configuration `whitespaceBreak: true` and a `width` setting smaller than the width of a single character in the FIGlet font. Under these specific conditions, the word-wrapping logic in `generateFigTextLines()` fails to identify a valid break point, causing the process to enter an infinite loop. This behavior pins a single CPU core at 100% usage and results in unbounded memory growth, effectively blocking the Node.js event loop and rendering the service unresponsive. The issue is resolved in version 1.11.3 by updating the word-wrapping logic to guarantee forward progress and implementing validation to reject invalid header values like zero or negative widths.

## Impact

Successful exploitation results in a denial-of-service condition for the target Node.js application. This vulnerability is most dangerous in web applications that reflect user-supplied input into the `width` parameter of the figlet function. Continuous exploitation can lead to prolonged service outages, impacting availability for all users. The severity is mitigated by the fact that the exploit requires both non-default configuration (`whitespaceBreak: true`) and access to the function's parameters via untrusted input.

## Recommendation

Prioritize the following actions to mitigate this vulnerability:
- Upgrade the figlet dependency to version 1.11.3 or later in all projects.
- Audit applications utilizing figlet to determine if the `width` parameter is influenced by untrusted user input.
- Disable the `whitespaceBreak` option if it is not strictly required for business logic, as it remains the primary driver for this vulnerability.
