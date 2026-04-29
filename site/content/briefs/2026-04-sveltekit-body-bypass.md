---
title: '@sveltejs/adapter-node BODY_SIZE_LIMIT Bypass Vulnerability'
slug: 2026-04-sveltekit-body-bypass
description: A vulnerability exists in @sveltejs/adapter-node where requests could bypass the `BODY_SIZE_LIMIT` on SvelteKit applications, potentially leading to denial of service.
date: "2026-04-11T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - sveltekit
  - denial-of-service
  - vulnerability
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-40073
references:
  - https://github.com/advisories/GHSA-2crg-3p73-43xp
  - https://github.com/sveltejs/kit/releases/tag/%40sveltejs%2Fkit%402.57.1
rules:
  - title: Detect Large HTTP Request Size
    description: Detects unusually large HTTP request sizes, potentially indicating a BODY_SIZE_LIMIT bypass attempt.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - webserver
      - linux
  - title: Detect POST requests exceeding a specific size to any URI
    description: Detect POST requests with Content-Length header exceeding a threshold.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A high-severity vulnerability, CVE-2026-40073, affects SvelteKit applications using `@sveltejs/adapter-node` versions 2.57.0 and earlier. This vulnerability allows requests to bypass the intended `BODY_SIZE_LIMIT`, potentially leading to resource exhaustion and denial-of-service conditions. The bypass occurs specifically within the adapter itself and does not impact body size limits enforced by other layers such as Web Application Firewalls (WAFs), gateways, or platform-level configurations. Successful exploitation could allow an attacker to send arbitrarily large requests, overwhelming the server and causing it to become unresponsive. The vulnerability was patched in version 2.57.1.

## Attack Chain

1.  The attacker identifies a SvelteKit application using a vulnerable version of `@sveltejs/adapter-node` (<= 2.57.0).
2.  The attacker crafts an HTTP request with a body exceeding the configured `BODY_SIZE_LIMIT`.
3.  Due to the vulnerability, the adapter fails to enforce the size limit on the request body.
4.  The oversized request is processed by the SvelteKit application.
5.  The application consumes excessive server resources (CPU, memory) while handling the oversized request.
6.  The server becomes overloaded and unresponsive due to resource exhaustion.
7.  Legitimate users are unable to access the application, resulting in a denial-of-service condition.

## Impact

Successful exploitation of this vulnerability can lead to a denial-of-service condition, rendering the SvelteKit application unavailable to legitimate users. The number of affected applications is potentially large, given the popularity of SvelteKit for web development. Sectors utilizing SvelteKit for their web applications are all potentially at risk. If exploited, the application’s server can become overloaded causing a significant impact to availability.

## Recommendation

*   Upgrade `@sveltejs/kit` to version 2.57.1 or later to remediate CVE-2026-40073.
*   Monitor web server logs for unusually large HTTP request sizes, using a rule such as the example Sigma rule below.
*   Implement or reinforce body size limits at other layers of the application stack (e.g., WAF, gateway) to provide defense-in-depth.
