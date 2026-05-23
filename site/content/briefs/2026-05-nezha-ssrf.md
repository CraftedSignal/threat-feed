---
title: Nezha Monitoring RoleMember SSRF with Full Response Body Reflection
slug: 2026-05-nezha-ssrf
description: Nezha Monitoring is vulnerable to a server-side request forgery (SSRF) vulnerability, where a low-privilege RoleMember user can call notification routes and send HTTP requests to a user-controlled URL, with the entire response body reflected back to the caller, potentially exposing intranet resources and causing denial of service.
date: "2026-05-23T00:11:36Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - ssrf
  - nezha
  - vulnerability
vendors:
  - GitHub
products:
  - Nezha Monitoring
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1018
    technique_name: Remote System Discovery
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499.001
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-w4g9-mxgg-j532
  - CVE-2026-46717
rules:
  - title: Detect Nezha Monitoring SSRF Attempt via Notification API
    description: Detects potential SSRF attempts in Nezha Monitoring by monitoring POST requests to the /api/v1/notification endpoint with URLs containing IP addresses, potentially indicating an attempt to access internal resources.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Nezha Monitoring Large Response Body SSRF
    description: Detects potential denial-of-service attacks by monitoring for error responses with exceptionally large bodies returned from the `/api/v1/notification` endpoint, indicative of an SSRF attempt targeting a large file.
    platform: sigma
    severity: low
    tactics:
      - impact
    techniques:
      - T1499.001
    data_sources:
      - webserver
rules_count: 2
---

Nezha Monitoring is affected by a server-side request forgery (SSRF) vulnerability that allows a low-privileged `RoleMember` user (Role==1) to perform actions normally restricted to `RoleAdmin`. The vulnerability resides in the notification routes `POST /api/v1/notification` and `PATCH /api/v1/notification/:id`, which are accessible to `RoleMember` users due to being wired through `commonHandler` instead of `adminHandler`. By crafting malicious HTTP requests to user-controlled URLs via these routes, attackers can force the Nezha dashboard's hub to send requests to internal resources. The entire response body, without any size limitation, is then reflected back to the attacker, enabling the exposure of sensitive intranet data and potential denial-of-service (DoS) attacks by targeting large internal files. The vulnerability exists in versions up to commit `50dc8e660326b9f22990898142c58b7a5312b42a` on the `master` branch.

## Attack Chain

1.  Attacker obtains a valid `RoleMember` account, likely through legitimate registration or compromise.
2.  Attacker crafts a malicious HTTP POST request to `/api/v1/notification` or `PATCH /api/v1/notification/:id`.
3.  The request includes a JSON payload containing a user-controlled `URL` parameter pointing to an internal resource (e.g., `http://192.168.1.1/admin/index.html` or `http://169.254.169.254/latest/meta-data/iam/security-credentials/`).
4.  The `NotificationServerBundle.Send()` function is called, which uses either `utils.HttpClient` or `utils.HttpClientSkipTlsVerify` (depending on the `VerifyTLS` setting) to send the request. Critically, the request is sent synchronously, and `VerifyTLS` can be set to false to bypass TLS certificate validation.
5.  The target internal resource responds to the request. If the response status code is not in the 200-299 range, the entire response body is read via `io.ReadAll` and included in an error message.
6.  The error message, containing the full response body of the internal resource, is returned to the attacker via `newErrorResponse` in a JSON response.
7.  The attacker parses the JSON response to extract the reflected content of the internal resource.
8.  If the attacker targets a large internal file, the dashboard may experience a denial-of-service due to excessive memory consumption by `io.ReadAll`.

## Impact

Successful exploitation of this SSRF vulnerability allows a `RoleMember` to read the contents of internal web pages, potentially exposing sensitive information like API keys, configuration details, or internal application data. The ability to disable TLS verification expands the scope of attack to internal HTTPS endpoints. Furthermore, an attacker can trigger a denial-of-service (DoS) by targeting large internal files, causing the dashboard server to consume excessive memory. The vulnerability is rated as medium severity with a CVSS score of 6.4, considering the low privileges required and potential for limited data exposure and service disruption.

## Recommendation

*   Immediately apply the suggested fix by switching the `/notification` routes to use `adminHandler` to restrict access to administrators only. This mitigation directly addresses the root cause by preventing `RoleMember` users from accessing the vulnerable endpoints (`cmd/dashboard/controller/controller.go:121-122`).
*   Implement SSRF hardening measures in the `NotificationServerBundle.Send()` function as suggested in the advisory. This should include validating the target URL, resolving the host IP address, and enforcing HTTP(S) schemes to prevent requests to arbitrary protocols.
*   Cap the response body size using `io.LimitReader(resp.Body, 4096)` within the `NotificationServerBundle.Send()` function to mitigate the DoS risk associated with reading large internal files (`model/notification.go:113-159`).
*   Deploy the provided Sigma rule `Detect Nezha Monitoring SSRF Attempt via Notification API` to identify attempts to exploit this vulnerability by monitoring requests to the `/api/v1/notification` endpoint with suspicious URLs.
