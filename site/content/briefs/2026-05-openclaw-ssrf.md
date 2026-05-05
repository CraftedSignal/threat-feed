---
title: OpenClaw SSRF Policy Bypass Vulnerability
slug: 2026-05-openclaw-ssrf
description: OpenClaw before version 2026.4.10 is vulnerable to a server-side request forgery (SSRF) policy bypass, allowing attackers to perform unauthorized tab navigation operations by exploiting the /tabs/action endpoint.
date: "2026-05-05T12:16:18Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssrf
  - cve-2026-42439
  - openclaw
vendors:
  - OpenClaw
products:
  - OpenClaw
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Server-Side Request Forgery
cves:
  - id: CVE-2026-42439
    cvss: 8.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-42439
  - https://github.com/openclaw/openclaw/commit/48c0347921b7e9438af0312968fc360ca88023f3
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-rj2p-j66c-mgqh
  - https://www.vulncheck.com/advisories/openclaw-ssrf-policy-bypass-in-browser-tabs-action-routes
rules:
  - title: Detect Suspicious OpenClaw Tab Action Requests
    description: Detects suspicious requests to the /tabs/action endpoint in OpenClaw, potentially indicating an SSRF attempt.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1199
      - T1595
    data_sources:
      - webserver
      - linux
  - title: Detect OpenClaw SSRF via External URL in Tab Action
    description: Detects attempts to trigger SSRF in OpenClaw by using the /tabs/action endpoint to access external URLs. This rule looks for common URL patterns associated with external connections.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1199
      - T1595
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenClaw before version 2026.4.10 is susceptible to a server-side request forgery (SSRF) policy bypass vulnerability. This flaw resides in the browser tabs action select and close routes, specifically within the `/tabs/action` endpoint. An unauthenticated attacker can leverage this vulnerability to circumvent configured SSRF policy protections. This allows them to initiate unauthorized tab navigation actions, potentially gaining access to internal resources or performing other malicious activities within the context of the OpenClaw application. The vulnerability was reported by VulnCheck and assigned CVE-2026-42439. Successful exploitation could lead to the exposure of sensitive information and compromise of internal services.

## Attack Chain

1.  The attacker identifies an OpenClaw instance running a version prior to 2026.4.10.
2.  The attacker crafts a malicious request targeting the `/tabs/action` endpoint.
3.  The crafted request is designed to bypass the configured SSRF policy protections.
4.  The attacker injects a URL pointing to an internal resource or an external malicious site.
5.  The OpenClaw application processes the request without proper validation, initiating a request to the attacker-controlled URL.
6.  The server-side component of OpenClaw unwittingly fetches the content from the specified URL.
7.  The attacker gains access to potentially sensitive information from internal resources if the request was directed internally.
8.  The attacker uses the unauthorized tab navigation to further compromise the application or network.

## Impact

Successful exploitation of this SSRF vulnerability could allow attackers to bypass configured SSRF policy protections. This may lead to unauthorized access to internal resources, information disclosure, or the ability to pivot to other internal systems. Given the nature of SSRF, the impact could range from reading sensitive configuration files to executing arbitrary commands on backend servers, depending on the internal network configuration and the services accessible from the OpenClaw server.

## Recommendation

*   Upgrade OpenClaw to version 2026.4.10 or later to patch CVE-2026-42439.
*   Deploy the Sigma rule `Detect Suspicious OpenClaw Tab Action Requests` to identify potential exploitation attempts targeting the `/tabs/action` endpoint.
*   Monitor web server logs for suspicious activity related to the `/tabs/action` endpoint, specifically requests with unusual URLs or parameters, to detect and respond to potential exploitation attempts.
