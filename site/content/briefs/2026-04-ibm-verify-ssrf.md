---
title: IBM Verify and Security Verify Access Container Server-Side Request Forgery Vulnerability (CVE-2026-1343)
slug: 2026-04-ibm-verify-ssrf
description: CVE-2026-1343 allows an attacker to contact internal authentication endpoints protected by the Reverse Proxy in IBM Verify Identity Access Container and IBM Security Verify Access Container.
date: "2026-04-08T01:16:40Z"
severities:
  - medium
tags:
  - cve
  - cve-2026-1343
  - ssrf
  - ibm
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1068
    technique_name: Proxying
cves:
  - id: CVE-2026-1343
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-1343
  - https://www.ibm.com/support/pages/node/7268253
rules:
  - title: Detect Suspicious Access to Internal Endpoints via Proxy Bypass
    description: Detects potential exploitation of CVE-2026-1343 by monitoring for suspicious access attempts to internal authentication endpoints bypassing the reverse proxy.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1068
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious POST Requests to Internal Authentication Endpoints
    description: Detects potential exploitation of CVE-2026-1343 by monitoring for suspicious POST requests to internal authentication endpoints bypassing the reverse proxy.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1068
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

IBM Verify Identity Access Container versions 11.0 through 11.0.2 and IBM Security Verify Access Container versions 10.0 through 10.0.9.1, as well as IBM Verify Identity Access versions 11.0 through 11.0.2 and IBM Security Verify Access versions 10.0 through 10.0.9.1, are vulnerable to Server-Side Request Forgery (SSRF). This flaw, identified as CVE-2026-1343, allows a remote, unauthenticated attacker to bypass the reverse proxy and access internal authentication endpoints. The vulnerability…
