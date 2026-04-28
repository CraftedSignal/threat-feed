---
title: Movary SSRF Vulnerability (CVE-2026-40348)
slug: 2026-04-movary-ssrf
description: Movary versions before 0.71.1 are vulnerable to server-side request forgery (SSRF) via the `/settings/jellyfin/server-url-verify` endpoint, allowing authenticated users to probe internal network resources.
date: "2026-04-18T00:16:38Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - ssrf
  - cve-2026-40348
  - movary
  - web-application
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1539
    technique_name: Uncontrolled Resource Consumption
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-40348
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40348
rules:
  - title: Detect Movary SSRF Attempt
    description: Detects attempts to exploit the SSRF vulnerability in Movary by monitoring requests to the /settings/jellyfin/server-url-verify endpoint with suspicious URLs.
    platform: sigma
    severity: medium
    tactics:
      - discovery
      - initial_access
    techniques:
      - T1190
      - T1539
    data_sources:
      - webserver
      - linux
  - title: Detect Movary SSRF Response Code
    description: Detects abnormal HTTP response codes after a request to the /settings/jellyfin/server-url-verify endpoint, indicating a successful SSRF.
    platform: sigma
    severity: low
    tactics:
      - discovery
      - initial_access
    techniques:
      - T1190
      - T1539
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Movary, a self-hosted web application for tracking and rating movies, is susceptible to a Server-Side Request Forgery (SSRF) vulnerability (CVE-2026-40348) in versions prior to 0.71.1. This flaw allows authenticated users to manipulate the `/settings/jellyfin/server-url-verify` endpoint to initiate server-side HTTP requests to arbitrary internal targets. The application uses the Guzzle HTTP client to send requests based on a user-supplied URL, to which `/system/info/public` is appended. The absence of input validation on the target URL allows attackers to bypass intended restrictions and access internal network resources. This vulnerability enables threat actors to perform internal reconnaissance activities such as host discovery, port scanning, and service fingerprinting. Successful exploitation can lead to further compromise by exposing internal administrative interfaces or cloud metadata endpoints.

## Attack Chain

1. An attacker authenticates to the Movary web application with a valid user account.
2. The attacker crafts a malicious URL targeting an internal resource, such as `http://127.0.0.1/`.
3. The attacker sends a `POST` request to `/settings/jellyfin/server-url-verify` with the crafted URL as the `serverUrl` parameter.
4. The Movary server receives the request and appends `/system/info/public` to the user-provided URL.
5. The Movary server uses the Guzzle HTTP client to initiate an HTTP request to the modified URL (e.g., `http://127.0.0.1/system/info/public`).
6. The internal service at the targeted IP address responds to the Movary server.
7. Based on the HTTP response code and content, the attacker can infer the existence and status of internal services. This allows for port scanning and service fingerprinting.
8. The attacker leverages discovered services to escalate privileges, potentially accessing sensitive data or internal administrative panels.

## Impact

Successful exploitation of the SSRF vulnerability (CVE-2026-40348) in Movary can enable attackers to discover internal network infrastructure and identify vulnerable services. This can allow attackers to gain unauthorized access to sensitive information, pivot to other internal systems, or perform other malicious activities. Although no specific victim count is given, the impact of this vulnerability is potentially high for any organization using a vulnerable version of Movary.

## Recommendation

*   Upgrade Movary to version 0.71.1 or later to patch the SSRF vulnerability (CVE-2026-40348).
*   Deploy the Sigma rule `Detect Movary SSRF Attempt` to identify potential exploitation attempts in web server logs.
*   Implement network segmentation and access controls to restrict access to sensitive internal services, limiting the impact of potential SSRF attacks.
