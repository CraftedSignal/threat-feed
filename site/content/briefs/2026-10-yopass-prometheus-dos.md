---
title: Unbounded Memory Exhaustion in yopass Prometheus Metrics Middleware
slug: 2026-10-yopass-prometheus-dos
description: An unauthenticated remote denial-of-service vulnerability in yopass allows attackers to trigger monotonic memory growth by injecting arbitrary HTTP method strings into Prometheus metrics labels.
date: "2026-10-09T21:25:37Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:yopass:yopass:*:*:*:*:*:*:*:*
products:
  - yopass (< 0.0.0-20260727191436-61e31ead04a4)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An attacker issuing requests with unique method values causes monotonic memory growth until the process is OOM-killed.
    confidence_band: high
cves:
  - id: CVE-2026-107840
    cvss: 7.5
references:
  - https://github.com/advisories/GHSA-6r69-c6wg-7g8m
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107840
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade yopass to version 14.7.0 or later
      owner: IT Operations
      addresses: CVE-2026-107840
      evidence: 'Remediation: Upgrade to 14.7.0 or later'
---

The yopass server, specifically within its Prometheus metrics middleware in pkg/server/server.go, is vulnerable to a denial-of-service (DoS) attack caused by improper handling of HTTP request method labels. The application incorrectly uses the raw HTTP request method string as a label for Prometheus counter and histogram metrics. Because the catch-all routing mechanism accepts arbitrary method strings from an unauthenticated request, an attacker can flood the server with requests using unique, randomized method strings. 

Each unique method creates a new entry in the Prometheus registry's internal data structures. As these registry maps lack an eviction mechanism, each injection consumes additional memory. Continued exploitation results in unbounded memory growth, eventually triggering an OOM (Out-of-Memory) kill of the yopass process. Furthermore, the registry growth causes severe degradation of the /metrics scraping latency, preventing visibility and monitoring before the service crashes. This vulnerability is tracked as CVE-2026-107840 and affects versions prior to 0.0.0-20260727191436-61e31ead04a4.

## Impact

Successful exploitation results in a persistent denial-of-service condition, rendering the yopass instance unavailable. The impact includes the loss of secret sharing capabilities and the blindness of infrastructure monitoring due to the degradation and eventual timeout of the /metrics scrape endpoint. Given the ease of exploitation via simple HTTP requests, the risk to availability for internet-facing yopass instances is significant.

## Recommendation

Prioritize upgrading yopass to version 14.7.0 or later, which implements an allowlist for HTTP methods (GET, POST, PUT, DELETE, OPTIONS, HEAD, CONNECT, TRACE) and sanitizes unknown methods by mapping them to an 'other' label.
