---
title: React Router Denial of Service via Inefficient Route Matching (CVE-2026-55685)
slug: 2026-07-react-router-dos
description: An unauthenticated attacker can exploit CVE-2026-55685 in React Router versions 7.0.0 through 7.17.x, when used in Framework Mode applications, to cause a denial-of-service condition by repeatedly accessing the manifest endpoint, leading to heavy server load and slow response times.
date: "2026-07-24T14:09:28Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - web-vulnerability
  - denial-of-service
  - react-router
  - npm
vendors:
  - Remix
products:
  - react-router (7.0.0 - 7.17.x)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
    evidence: An unauthenticated attacker can trigger a denial-of-service condition by repeatedly accessing the manifest endpoint, leading to heavy server load and slow response times.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-chx6-hx7r-mcp5
---

A high-severity denial-of-service (DoS) vulnerability, identified as CVE-2026-55685, affects `npm/react-router` versions 7.0.0 through 7.17.x. This vulnerability is a follow-up to a previously identified issue and specifically impacts applications configured in "Framework Mode." An unauthenticated attacker can leverage this flaw by sending targeted, repetitive requests to the application's manifest endpoint. This exploitation leads to inefficient route matching processes, which consumes significant server resources, resulting in heavy server load, degraded response times, and ultimately a denial of service for legitimate users. Defenders using React Router in Framework Mode applications are advised to prioritize patching to mitigate this risk.

## Attack Chain

1. An unauthenticated attacker identifies a web application utilizing `npm/react-router` configured in "Framework Mode."
2. The attacker identifies the application's manifest endpoint through reconnaissance or publicly available information.
3. The attacker crafts HTTP requests targeting this specific manifest endpoint.
4. The attacker sends a high volume of these targeted requests to the identified manifest endpoint.
5. Due to inefficient route matching within the vulnerable React Router versions, each request consumes disproportionately high server resources (CPU, memory).
6. The continuous stream of requests causes the server to become overloaded, leading to resource exhaustion.
7. The application's performance degrades significantly, resulting in slow response times or complete unresponsiveness.
8. Legitimate users are unable to access the service, resulting in a denial-of-service condition.

## Impact

Successful exploitation of CVE-2026-55685 leads to a significant degradation or complete unavailability of affected web applications. Organizations relying on React Router in "Framework Mode" for critical services could experience severe operational disruption. The impact includes financial losses due to service downtime, reputational damage, and potential violation of service level agreements. Affected applications would suffer from resource exhaustion, making them unresponsive to legitimate user requests. While no specific victim counts are provided, React Router is a widely used library, making the potential scope of impact considerable for organizations that have not yet patched.

## Recommendation

* Upgrade `npm/react-router` to version 7.18.0 or later immediately to address CVE-2026-55685.
* Implement rate-limiting mechanisms at the web application firewall (WAF) or load balancer level to mitigate high-volume requests targeting web application endpoints, specifically focusing on the manifest endpoint referenced in the `Attack Chain` section.
* Monitor web server access logs for an unusually high volume of unauthenticated requests to the `/manifest` endpoint or similar paths, as described in the `Attack Chain`.
* Ensure server-side monitoring is in place to detect sudden spikes in CPU, memory, or network utilization that could indicate a denial-of-service attack.
