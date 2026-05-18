---
title: Dozzle Pre-Auth SSRF Vulnerability via /api/notifications/test-webhook (CVE-2026-45298)
slug: 2026-05-dozzle-ssrf
description: Dozzle is vulnerable to a pre-authentication Server-Side Request Forgery (SSRF) vulnerability (CVE-2026-45298) in the default no-auth deployment that can expose internal resources.
date: "2026-05-18T16:42:39Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - dozzle
  - cve-2026-45298
vendors:
  - amir20
products:
  - dozzle
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-3v9w-6365-9w54
iocs:
  - type: url
    value: http://169.254.169.254/latest/meta-data/iam/security-credentials/
ioc_counts:
  url: 1
rules:
  - title: Detect Dozzle SSRF Attempt via test-webhook
    description: Detects CVE-2026-45298 exploitation — attempts to exploit the Dozzle SSRF vulnerability by sending POST requests to the /api/notifications/test-webhook endpoint with potentially malicious URLs in the request body.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Dozzle test-webhook with suspicious headers
    description: Detects CVE-2026-45298 exploitation — attempts to exploit the Dozzle SSRF vulnerability by sending POST requests to the /api/notifications/test-webhook endpoint with suspicious headers to inject into the downstream request
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

Dozzle, a real-time log viewer for Docker containers, is vulnerable to a Server-Side Request Forgery (SSRF) attack (CVE-2026-45298) via the `/api/notifications/test-webhook` endpoint. This endpoint is exposed without authentication in default deployments where the `DOZZLE_AUTH_PROVIDER` environment variable is not set. An attacker can exploit this vulnerability to send arbitrary HTTP POST requests to internal or external resources accessible from the Dozzle host. The application reflects the response body, up to 1MB, back to the attacker, enabling the retrieval of sensitive information from internal services, cloud metadata endpoints, or other reachable targets. This affects Dozzle version 8.14.12 and earlier.

## Attack Chain

1. An attacker identifies a Dozzle instance running with the default no-authentication configuration.
2. The attacker crafts a malicious HTTP POST request to the `/api/notifications/test-webhook` endpoint.
3. The request body includes a JSON payload containing the `url` parameter, which specifies the target URL for the SSRF attack. The `headers` parameter can be used to inject arbitrary headers into the outgoing request.
4. The Dozzle server receives the request and, due to the lack of authentication, processes the request without validation.
5. The `WebhookDispatcher` creates an HTTP POST request to the attacker-specified URL, including the attacker-provided headers.
6. The Dozzle server sends the crafted HTTP request to the target URL.
7. If the target URL responds with a non-2xx status code, the server reads up to 1MB of the response body.
8. The server includes the status code and the response body in the JSON response to the attacker, exposing sensitive information.

## Impact

Successful exploitation allows an attacker to read data from internal services, potentially exposing sensitive information such as configuration details, API keys, or internal documents. It also allows probing for the existence of internal resources and potentially injecting headers into requests to internal services. This can lead to further compromise of internal systems.

## Recommendation

*   Refuse `test-webhook` requests when `Authorization.Provider` is set to `NONE`.
*   Implement SSRF hardening for `WebhookDispatcher` by validating and sanitizing the input URL, resolving the host IP address via `net.LookupIP`, refusing private, loopback, link-local, and CGNAT addresses, pinning the `http.Transport.DialContext` to the resolved IP address, and refusing non-HTTP(S) schemes, as suggested in the advisory.
*   Disable the reflection of the response body in the `testWebhook` handler. Modify the handler to only return the `Success` boolean and `StatusCode` integer values, as suggested in the advisory.
*   Monitor web server logs for POST requests to the `/api/notifications/test-webhook` endpoint with suspicious URLs (internal IPs, cloud metadata endpoints) in the request body and deploy the Sigma rule `Detect Dozzle SSRF Attempt via test-webhook` to identify exploitation attempts.
