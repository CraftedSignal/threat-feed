---
title: NVIDIA KAI Scheduler Authentication Bypass Vulnerability
slug: 2026-04-nvidia-kai-auth-bypass
description: CVE-2026-24177 describes an authentication bypass vulnerability in NVIDIA KAI Scheduler that could allow unauthorized access to API endpoints, leading to information disclosure.
date: "2026-04-22T12:00:00Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
tags:
  - vulnerability
  - authentication-bypass
  - nvidia
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Software Discovery
cves:
  - id: CVE-2026-24177
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-24177
  - https://nvidia.custhelp.com/app/answers/detail/a_id/5818
  - https://www.cve.org/CVERecord?id=CVE-2026-24177
rules:
  - title: Detect Unauthorized Access to NVIDIA KAI Scheduler API
    description: Detects attempts to access NVIDIA KAI Scheduler API endpoints without proper authorization.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1552
    data_sources:
      - webserver
      - linux
  - title: Detect NVIDIA KAI Scheduler API Endpoint Access
    description: Detects access to NVIDIA KAI Scheduler API endpoints. This rule should be tuned to filter out legitimate access.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-24177 details a security flaw within the NVIDIA KAI Scheduler. This vulnerability stems from a lack of proper authentication mechanisms for critical API endpoints. An attacker exploiting this flaw could potentially bypass authorization checks and gain unauthorized access to sensitive functionalities. Successful exploitation leads to information disclosure. The affected product is NVIDIA KAI Scheduler. As of April 2026, exploitation in the wild has not been confirmed, but the potential impact warrants immediate attention from security teams. This vulnerability allows an attacker with network access to the KAI Scheduler to retrieve sensitive information without proper authorization.

## Attack Chain

1.  The attacker identifies an exposed NVIDIA KAI Scheduler instance.
2.  The attacker crafts a malicious HTTP request targeting an API endpoint lacking authentication (CWE-306).
3.  The attacker sends the request to the KAI Scheduler.
4.  Due to the missing authentication check, the KAI Scheduler processes the request without verifying the attacker's identity.
5.  The KAI Scheduler returns sensitive information to the attacker.
6.  The attacker analyzes the disclosed information for further exploitation.
7. The attacker uses the disclosed information to access other systems.

## Impact

Successful exploitation of CVE-2026-24177 enables an attacker to bypass authentication and access sensitive information managed by the NVIDIA KAI Scheduler. The type of information exposed depends on the specific API endpoint accessed, and could include configuration data, user credentials, or internal system details. The NIST advisory assigns a CVSS v3.1 base score of 7.7 (HIGH), highlighting the significant risk of information disclosure.

## Recommendation

*   Monitor web server logs for suspicious requests to NVIDIA KAI Scheduler API endpoints (webserver category, product linux/windows).
*   Inspect network traffic for unauthorized access to NVIDIA KAI Scheduler API endpoints (network_connection category).
*   Deploy the Sigma rules provided to detect potential exploitation attempts against NVIDIA KAI Scheduler.
