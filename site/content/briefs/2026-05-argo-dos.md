---
title: Argo Workflows Webhook Interceptor Vulnerable to Unauthenticated Memory Exhaustion (CVE-2026-42294)
slug: 2026-05-argo-dos
description: Argo Workflows is vulnerable to a denial-of-service (DoS) attack due to unbounded memory allocation in the Webhook Interceptor component.
date: "2026-05-04T20:11:01Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - argo-workflows
  - cloud
vendors:
  - Argoproj
products:
  - Argo Workflows < 3.7.14
  - Argo Workflows >= 4.0.0
  - Argo Workflows < 4.0.5
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-jcc8-g2q4-9fxq
rules:
  - title: Detect Large HTTP POST Requests to Argo Webhook Endpoint
    description: Detects HTTP POST requests with a large Content-Length header targeting the Argo Workflows webhook endpoint, indicating a potential DoS attempt.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499
    data_sources:
      - webserver
      - linux
  - title: Detect HTTP 413 Errors on Argo Webhook Endpoint
    description: Detects HTTP 413 Payload Too Large errors on the Argo Workflows webhook endpoint, which may indicate attempts to exploit the DoS vulnerability.
    platform: sigma
    severity: low
    tactics:
      - availability
    techniques:
      - T1499
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Argo Workflows is vulnerable to a denial-of-service (DoS) attack (CVE-2026-42294) due to unbounded memory allocation in the Webhook Interceptor. The vulnerability resides in the `server/auth/webhook/interceptor.go` component, specifically within the `/api/v1/events/` endpoint. This endpoint, intended for webhook integrations, reads the entire request body into memory without proper size limits, leading to potential memory exhaustion. An attacker can exploit this vulnerability by sending a crafted request with an extremely large body, causing the Argo Server to allocate excessive memory and potentially crash, resulting in a denial of service. Affected versions include Argo Workflows versions prior to 3.7.14 and versions 4.0.0 up to 4.0.5.

## Attack Chain

1.  The attacker identifies an Argo Workflows instance with a publicly accessible `/api/v1/events/` endpoint.
2.  The attacker crafts an HTTP POST request targeting the `/api/v1/events/` endpoint.
3.  The attacker sets the `Content-Length` header of the request to a very large value (e.g., 1GB or more).
4.  The attacker sends the malicious request with a large amount of arbitrary data as the request body.
5.  The Argo Server receives the request and, within the `WebhookInterceptor`, calls `io.ReadAll(r.Body)`, allocating memory to store the entire request body.
6.  Due to the large request body, the Argo Server's memory consumption increases significantly.
7.  If the attacker sends a sufficiently large request, the Argo Server exhausts its available memory.
8.  The Argo Server process crashes due to an Out-Of-Memory (OOM) error, leading to a denial of service.

## Impact

Successful exploitation of this vulnerability results in a denial-of-service condition, disrupting workflow execution and API access for all users of the Argo Workflows instance. The Argo Server crashes, making it unavailable until restarted. This impacts service availability and potentially causes data loss if workflows are interrupted during execution. The number of victims depends on the number of Argo Workflows instances exposed and targeted by attackers.

## Recommendation

*   Enforce a strict limit on webhook body size (e.g., 10MB) using `http.MaxBytesReader` or similar mechanisms within your ingress controller or reverse proxy to prevent oversized requests from reaching the Argo Server.
*   Upgrade Argo Workflows to version 3.7.14 or 4.0.5 or later to patch CVE-2026-42294 and mitigate the risk of denial-of-service attacks.
*   Monitor memory usage of the Argo Server process and set up alerts for unusually high memory consumption to detect potential exploitation attempts.
