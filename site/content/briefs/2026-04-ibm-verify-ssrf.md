---
title: IBM Verify and Security Verify Access Container Server-Side Request Forgery Vulnerability (CVE-2026-1343)
slug: 2026-04-ibm-verify-ssrf
description: CVE-2026-1343 allows an attacker to contact internal authentication endpoints protected by the Reverse Proxy in IBM Verify Identity Access Container and IBM Security Verify Access Container.
date: "2026-04-08T01:16:40Z"
severities:
  - medium
type: advisory
types:
  - advisory
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

IBM Verify Identity Access Container versions 11.0 through 11.0.2 and IBM Security Verify Access Container versions 10.0 through 10.0.9.1, as well as IBM Verify Identity Access versions 11.0 through 11.0.2 and IBM Security Verify Access versions 10.0 through 10.0.9.1, are vulnerable to Server-Side Request Forgery (SSRF). This flaw, identified as CVE-2026-1343, allows a remote, unauthenticated attacker to bypass the reverse proxy and access internal authentication endpoints. The vulnerability exists due to insufficient access controls on internal endpoints. Exploitation could lead to information disclosure or further compromise of the affected systems. Defenders should prioritize patching and monitoring for suspicious activity targeting internal resources.

## Attack Chain

1. Attacker identifies a vulnerable IBM Verify Identity Access or Security Verify Access Container instance.
2. The attacker crafts a malicious request targeting an internal authentication endpoint.
3. The crafted request bypasses the reverse proxy due to inadequate access controls.
4. The vulnerable server processes the malicious request, unintentionally exposing internal resources.
5. Sensitive information about internal systems is exposed to the attacker.
6. The attacker uses gathered information to perform unauthorized actions or further reconnaissance.
7. Attacker potentially compromises user accounts or internal infrastructure.

## Impact

Successful exploitation of CVE-2026-1343 can lead to unauthorized access to sensitive internal information, potentially compromising user accounts and internal systems. This can result in data breaches, privilege escalation, and further attacks within the organization. While the specific number of affected organizations isn't available, any organization using vulnerable versions of IBM Verify Identity Access Container or IBM Security Verify Access Container is at risk.

## Recommendation

*   Apply the patch or upgrade to a secure version of IBM Verify Identity Access Container or IBM Security Verify Access Container as described in [IBM's advisory](https://www.ibm.com/support/pages/node/7268253) to remediate CVE-2026-1343.
*   Deploy the Sigma rule `Detect Suspicious Access to Internal Endpoints via Proxy Bypass` to detect exploitation attempts by monitoring web server logs for abnormal requests patterns targeting internal endpoints.
*   Implement network segmentation to restrict access to internal resources from the internet.
*   Review access control configurations on the reverse proxy to ensure proper protection of internal endpoints.
