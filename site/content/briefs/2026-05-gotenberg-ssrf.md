---
title: Gotenberg Unauthenticated SSRF Vulnerability
slug: 2026-05-gotenberg-ssrf
description: Gotenberg version 8.29.1 is vulnerable to Server-Side Request Forgery (SSRF) due to an unfiltered webhook URL, allowing unauthenticated attackers to force outbound HTTP POST requests to arbitrary destinations, enabling internal network probing and interaction with internal services.
date: "2026-04-30T17:24:55Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - gotenberg
  - cve-2026-39383
vendors:
  - gotenberg
products:
  - Gotenberg (8.29.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-5vh4-rgv7-p9g4
rules:
  - title: Detect Gotenberg SSRF via Webhook URL Header
    description: Detects attempts to exploit the Gotenberg SSRF vulnerability by identifying POST requests to the conversion endpoint with a webhook URL pointing to a private IP range.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Outbound Connection from Gotenberg to Internal IP
    description: Detects outbound network connections from a Gotenberg instance to internal IP ranges, which could indicate SSRF exploitation.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - linux
  - title: Gotenberg - Detect Webhook Error URL Usage
    description: Detects use of the Gotenberg-Webhook-Error-Url header, which may be used to confirm exploitability of the SSRF.
    platform: sigma
    severity: informational
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 3
---

Gotenberg version 8.29.1, as distributed in the default `gotenberg/gotenberg:8` Docker image, contains an unauthenticated Server-Side Request Forgery (SSRF) vulnerability. Discovered on April 4, 2026, this flaw allows an attacker with network access to the Gotenberg instance to specify an arbitrary URL via the `Gotenberg-Webhook-Url` request header, forcing the server to make outbound HTTP POST requests. This is a blind SSRF vulnerability, where the attacker cannot directly read the response body, but can infer information based on the success or failure of the request. The vulnerability exists due to an insecure default in the `FilterDeadline` function, which, when unconfigured, permits all webhook URLs. The impact includes internal network probing, forced POST requests to internal services, and cloud metadata interaction.

## Attack Chain

1. The attacker identifies a vulnerable Gotenberg instance exposed on the network (default port 3000).
2. The attacker crafts an HTTP POST request to the `/forms/chromium/convert/url` endpoint.
3. The attacker includes the `Gotenberg-Webhook-Url` header, setting it to an internal IP address and port (e.g., `http://192.168.1.10:8080/`).
4. The attacker may also set the `Gotenberg-Webhook-Error-Url` to an attacker-controlled server to monitor for request failures.
5. Gotenberg's `FilterDeadline` function fails to properly validate the supplied webhook URL due to an insecure default.
6. Gotenberg makes an outbound HTTP POST request to the specified internal IP address and port using the retryablehttp client, potentially retrying the request up to 4 times.
7. If the internal target responds with a 2xx status code, the attacker infers that the host and port are open and accepting POST requests. The error URL is NOT called.
8. If the internal target responds with a 4xx/5xx status code, times out, or rejects the connection, the attacker receives a request at the `Gotenberg-Webhook-Error-Url` endpoint, indicating the port is likely closed or the service is unavailable.

## Impact

The SSRF vulnerability in Gotenberg 8.29.1 allows attackers to probe internal networks, potentially mapping out internal infrastructure by observing the success or failure of requests. Attackers can also force Gotenberg to send POST requests to internal services that perform actions upon receiving such requests, potentially triggering unintended behavior. Although the attacker cannot directly read response bodies, the ability to determine reachability and trigger actions makes this a significant security risk. The retry mechanism amplifies the probing effect, as each request generates up to 4 attempts.

## Recommendation

*   Apply the recommended configuration to either set `--env GOTENBERG_API_WEBHOOK_ALLOW_LIST` or `--env GOTENBERG_API_WEBHOOK_DENY_LIST` to restrict or block internal ranges to mitigate the SSRF vulnerability.
*   Monitor web server logs for POST requests to `/forms/chromium/convert/url` with the `Gotenberg-Webhook-Url` header containing suspicious internal IP addresses or domains using the provided Sigma rule.
*   Deploy the Sigma rule to detect suspicious outbound network connections originating from the Gotenberg process to internal IP ranges or cloud metadata endpoints.
