---
title: OpenClaw Authentication Bypass Vulnerability in noVNC Helper Route
slug: 2026-05-openclaw-auth-bypass
description: OpenClaw versions before 2026.4.10 contain an authentication bypass vulnerability (CVE-2026-43575) in the sandbox noVNC helper route, allowing attackers to access interactive browser session credentials without proper authentication.
date: "2026-05-06T20:16:33Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - authentication-bypass
  - web-application
  - cve-2026-43575
vendors:
  - OpenClaw
products:
  - OpenClaw
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
cves:
  - id: CVE-2026-43575
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-43575
  - https://github.com/openclaw/openclaw/commit/8dfbf3268bd224b7377d1ecca77a445100746085
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-92jp-89mq-4374
  - https://www.vulncheck.com/advisories/openclaw-authentication-bypass-in-sandbox-novnc-helper-route
rules:
  - title: Detect Access to OpenClaw noVNC Helper Route
    description: Detects unauthorized access attempts to the OpenClaw noVNC helper route.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1190
      - T1555
    data_sources:
      - webserver
      - linux
  - title: Detect Github Commit Referenced in CVE-2026-43575
    description: Detects user agents requesting the specific Github commit referenced in CVE-2026-43575, possibly indicating reconnaissance activity.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1595
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenClaw versions 2026.2.21 before 2026.4.10 are vulnerable to an authentication bypass (CVE-2026-43575) in the sandbox noVNC helper route. This vulnerability allows an attacker to bypass bridge authentication and gain unauthorized access to interactive browser sessions. The vulnerability stems from missing authorization checks within the noVNC helper route. Successful exploitation could allow an attacker to view or control the browser session and potentially access sensitive information. The vulnerability was reported and patched in OpenClaw version 2026.4.10.

## Attack Chain

1.  Attacker identifies an OpenClaw instance running a vulnerable version (prior to 2026.4.10).
2.  Attacker crafts a malicious request targeting the `/novnc_helper` route.
3.  The request bypasses the expected bridge authentication mechanism due to the missing authorization check (CWE-862).
4.  The server processes the request without proper authentication, granting access to the noVNC helper.
5.  Attacker gains access to interactive browser session credentials exposed through the noVNC helper.
6.  Attacker uses the stolen credentials to access and interact with the active browser session.
7.  Attacker monitors the browser session and intercepts sensitive information (e.g., credentials, API keys, personal data).

## Impact

Successful exploitation of this vulnerability allows attackers to gain unauthorized access to interactive browser sessions within OpenClaw. This can lead to the theft of sensitive information displayed or entered within the browser, such as user credentials, API keys, or personal data. Given the critical nature of the affected component, organizations using vulnerable versions of OpenClaw are at high risk of data breaches and unauthorized access to their systems.

## Recommendation

*   Upgrade OpenClaw installations to version 2026.4.10 or later to patch CVE-2026-43575.
*   Monitor web server logs for suspicious requests to the `/novnc_helper` route, using the Sigma rule provided below.
*   Implement network segmentation to limit the blast radius of potential exploitation.
