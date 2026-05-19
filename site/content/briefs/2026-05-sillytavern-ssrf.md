---
title: SillyTavern SSRF Vulnerability in SearXNG Search Proxy via Unvalidated baseUrl
slug: 2026-05-sillytavern-ssrf
description: SillyTavern version 1.17.0 is vulnerable to server-side request forgery (SSRF) via the `/api/search/searxng` route, allowing authenticated low-privilege users to control the `baseUrl` parameter for outbound server-side fetches, potentially disclosing sensitive information from internal HTTP services or cloud metadata endpoints.
date: "2026-05-19T20:11:03Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - sillytavern
  - github advisory
vendors:
  - npm
products:
  - sillytavern (<= 1.17.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-qg89-qwwh-5f3j
rules:
  - title: Detect Suspicious SillyTavern SSRF Attempt
    description: Detects CVE-2026-46372 exploitation — An authenticated user attempts to exploit SSRF in SillyTavern by sending a request to the /api/search/searxng endpoint with a suspicious baseUrl.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect SillyTavern SSRF Attempt via Internal IP
    description: Detects CVE-2026-46372 exploitation — An authenticated user attempts to exploit SSRF in SillyTavern by sending a request to the /api/search/searxng endpoint with a baseUrl containing an internal IP address.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

SillyTavern version 1.17.0 contains a server-side request forgery (SSRF) vulnerability in the `/api/search/searxng` route. This endpoint accepts a `baseUrl` parameter from the request body and uses it to construct outbound HTTP requests without proper validation. An authenticated, low-privilege user can manipulate the `baseUrl` to point to internal or loopback HTTP services. SillyTavern 1.18.0 introduced a request filter, but it is disabled by default and must be manually enabled and configured. This vulnerability allows attackers to potentially access sensitive data, interact with internal services, and exploit cloud metadata endpoints if the application is not properly secured.

## Attack Chain

1. Attacker authenticates to the SillyTavern application using valid credentials.
2. The attacker crafts a POST request to the `/api/search/searxng` endpoint.
3. In the request body, the attacker sets the `baseUrl` parameter to a malicious URL, such as an internal service on the loopback address (e.g., `http://127.0.0.1:9091/`).
4. The attacker sets the `query` parameter to a benign value to satisfy the application's requirements.
5. The SillyTavern server receives the POST request and extracts the `baseUrl` and `query` parameters.
6. The server constructs a new URL using the attacker-controlled `baseUrl` and makes an HTTP request to it.
7. The server fetches `/search` endpoint on the attacker controlled base URL and appends the attacker controlled query parameter (e.g., `http://127.0.0.1:9091/search?q=x`).
8. The server receives the response from the malicious URL and returns it to the attacker, effectively disclosing information from the internal service.

## Impact

Successful exploitation of this SSRF vulnerability allows an attacker to disclose responses from loopback or internal HTTP services reachable from the SillyTavern host. This can lead to the exposure of sensitive information, such as internal admin panels, development services, and cloud metadata endpoints in applicable deployments. It can also enable service discovery across private networks. If the request filter is not enabled and properly configured, the attacker can potentially gain unauthorized access to internal resources and compromise the confidentiality and integrity of the SillyTavern environment.

## Recommendation

*   Apply a patch upgrading to SillyTavern version 1.18.0 or later.
*   Enable and properly configure the Private Request Whitelisting filter in SillyTavern, as described in the documentation: [https://docs.sillytavern.app/administration/config-yaml/#private-address-whitelisting](https://docs.sillytavern.app/administration/config-yaml/#private-address-whitelisting) and [https://docs.sillytavern.app/administration/#security-checklist](https://docs.sillytavern.app/administration/#security-checklist).
*   Deploy the Sigma rule `Detect Suspicious SillyTavern SSRF Attempt` to your SIEM to detect attempts to exploit CVE-2026-46372.
