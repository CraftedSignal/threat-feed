---
title: Denial of Service in request-filtering-agent via Synchronous Exception
slug: 2026-09-request-filtering-agent-dos
description: A vulnerability in request-filtering-agent causes an unhandled exception and subsequent Node.js process crash when an HTTP request is made to a literal private IP address.
date: "2026-09-23T01:59:10Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:request-filtering-agent_project:request-filtering-agent:*:*:*:*:*:*:*:*
vendors:
  - request-filtering-agent
products:
  - request-filtering-agent (<= 3.2.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: The library synchronously throws an error within the createConnection() method... causing an unhandled exception that crashes the Node.js process.
    confidence_band: high
cves:
  - id: CVE-2026-62985
    cvss: 7.5
references:
  - https://github.com/advisories/GHSA-r3r9-wp5j-pq5g
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62985
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Development
  immediate_actions:
    - action: Upgrade request-filtering-agent to 3.2.1 or later
      owner: Development
      due: 24h
      evidence: CVE-2026-62985 identifies this package as vulnerable and provides a fix in 3.2.1
  mitigation_plan:
    - priority: immediate
      action: Upgrade request-filtering-agent to 3.2.1
      owner: IT Operations
      addresses: CVE-2026-62985
      evidence: Source advisory recommends version 3.2.1 as the fix
---

The request-filtering-agent library (versions <= 3.2.0) is susceptible to a denial-of-service (DoS) attack due to improper error handling within its connection logic. The library is intended to block requests to private IP addresses; however, when an application initiates an HTTP request to a literal private IP (e.g., 169.254.169.254 or 127.0.0.1), the library's createConnection() method performs a synchronous throw. 

In the Node.js runtime, http.request and http.get expect connection failures to be emitted asynchronously via the 'error' event on the request object. Because the library's error is thrown synchronously, it escapes the application's 'error' event handler, triggering an unhandled exception that crashes the Node.js process. This vulnerability (CVE-2026-62985) allows attackers who can influence the hostname parameter of outgoing HTTP requests to force a persistent process-level DoS, impacting any service relying on the library for request filtering.

## Impact

The vulnerability results in a total denial of service for the affected Node.js process. Any application using request-filtering-agent that processes user-supplied input to perform outbound HTTP requests is at risk. If an attacker identifies an endpoint where they can control or manipulate a destination hostname, they can trigger the synchronous exception to crash the backend service, leading to service disruption and potential availability loss for downstream users.

## Recommendation

1. Upgrade request-filtering-agent to version 3.2.1 or later to resolve the handling of synchronous errors.
2. Implement global 'uncaughtException' and 'unhandledRejection' handlers as a secondary defensive layer to catch and log unexpected crashes in Node.js processes.
3. Validate and sanitize all user-supplied input used to construct outbound HTTP requests before passing them to the request-filtering-agent.
4. Perform a code review of components utilizing request-filtering-agent to ensure they are not directly exposed to user-controlled literal IP inputs.
