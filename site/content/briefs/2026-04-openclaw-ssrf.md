---
title: OpenClaw Server-Side Request Forgery Vulnerability (CVE-2026-41297)
slug: 2026-04-openclaw-ssrf
description: OpenClaw before 2026.3.31 is vulnerable to server-side request forgery (SSRF) in the marketplace plugin download functionality, allowing attackers to access internal resources by exploiting unvalidated redirects via the marketplace.ts module.
date: "2026-04-21T00:16:30Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - ssrf
  - cve-2026-41297
  - openclaw
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-41297
    cvss: 7.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41297
  - https://github.com/openclaw/openclaw/commit/2ce44ca6a1302b166a128abbd78f72114f2f4f52
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-vjx8-8p7h-82gr
  - https://www.vulncheck.com/advisories/openclaw-server-side-request-forgery-via-marketplace-plugin-download-redirect
rules:
  - title: Detect OpenClaw SSRF Attempt via HTTP Redirect
    description: Detects potential SSRF attempts in OpenClaw by monitoring HTTP traffic for suspicious redirects to internal or unexpected external IPs or domains.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1021.001
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect OpenClaw SSRF Attempt via DNS Query to Internal Domain
    description: Detects potential SSRF attempts in OpenClaw by monitoring DNS queries for internal domains.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1021.001
      - T1190
    data_sources:
      - dns_query
      - windows
rules_count: 2
---

OpenClaw before version 2026.3.31 contains a server-side request forgery (SSRF) vulnerability in its marketplace plugin download functionality. This flaw, identified as CVE-2026-41297, allows remote attackers to access internal resources by exploiting unvalidated redirects. The issue lies within the `marketplace.ts` module, which fails to properly restrict redirect destinations during archive downloads. An attacker can manipulate the download process to redirect requests to arbitrary internal or external servers, potentially exposing sensitive information or allowing unauthorized actions. Successful exploitation can lead to information disclosure or further compromise of the OpenClaw server and its environment.

## Attack Chain

1.  Attacker identifies an OpenClaw instance running a vulnerable version (prior to 2026.3.31).
2.  Attacker crafts a malicious request to the marketplace plugin download functionality.
3.  The crafted request includes a manipulated URL designed to redirect the server's request.
4.  The vulnerable `marketplace.ts` module fails to validate the redirect destination.
5.  The OpenClaw server initiates a request to the attacker-specified URL, which could be an internal resource or an external server.
6.  If the redirection points to an internal resource, the server fetches and potentially exposes sensitive information.
7.  If the redirection points to an external server, the server may leak internal information within the request headers or body.
8.  The attacker gains unauthorized access to internal resources or sensitive information via the SSRF vulnerability.

## Impact

Successful exploitation of CVE-2026-41297 can allow attackers to access internal resources, potentially exposing sensitive data such as configuration files, database credentials, or internal application data. The impact depends on the internal resources accessible from the OpenClaw server. If the OpenClaw instance has access to critical internal systems, this vulnerability could lead to a significant compromise of the network. While the specific number of victims and targeted sectors are unknown, any organization using a vulnerable version of OpenClaw is at risk.

## Recommendation

*   Upgrade OpenClaw to version 2026.3.31 or later to patch CVE-2026-41297.
*   Deploy the Sigma rule `Detect OpenClaw SSRF Attempt via HTTP Redirect` to detect suspicious HTTP traffic indicative of SSRF exploitation.
*   Implement strict input validation and sanitization on all user-supplied URLs, especially those used in redirect operations, to prevent similar SSRF vulnerabilities in other applications.
*   Monitor web server logs for unusual outbound connections originating from the OpenClaw server, which may indicate an SSRF attempt.
*   Review and harden internal network segmentation to limit the impact of potential SSRF attacks, minimizing the resources accessible from the OpenClaw server.
