---
title: ORY Oathkeeper Authorization Bypass via Path Traversal (CVE-2026-33494)
slug: 2024-01-ory-oathkeeper-path-traversal
description: ORY Oathkeeper versions prior to 26.2.0 are vulnerable to an authorization bypass (CVE-2026-33494) via HTTP path traversal, enabling attackers to access protected resources by crafting URLs with path traversal sequences.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - CVE-2026-33494
  - ORY Oathkeeper
  - path traversal
  - authorization bypass
vendors:
  - ORY
products:
  - Oathkeeper
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33494
rules:
  - title: Detect ORY Oathkeeper Path Traversal Attempts
    description: Detects potential exploitation attempts of CVE-2026-33494 in ORY Oathkeeper by identifying HTTP requests with path traversal sequences targeting protected paths.
    platform: sigma
    severity: critical
    tactics:
      - cve-2026-33494
      - defense_evasion
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Generic HTTP Path Traversal
    description: Detects generic HTTP path traversal attempts using common patterns in the URI.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

ORY Oathkeeper, an Identity & Access Proxy (IAP) and Access Control Decision API, is susceptible to an authorization bypass vulnerability affecting versions prior to 26.2.0. This vulnerability, identified as CVE-2026-33494, stems from improper handling of HTTP path traversal sequences. Attackers can exploit this flaw by crafting malicious URLs containing sequences like `/public/../admin/secrets`. The application normalizes the path, resolving it to a protected resource. However, the authorization check uses the original, un-normalized path, potentially matching it against a permissive rule and granting unauthorized access. Organizations using affected versions of ORY Oathkeeper are at risk of unauthorized access to sensitive data and functionalities. Version 26.2.0 addresses this vulnerability with a patch.

## Attack Chain

1. The attacker identifies an ORY Oathkeeper instance running a version prior to 26.2.0.
2. The attacker crafts a malicious HTTP request URL containing path traversal sequences, such as `/public/../admin/secrets`, targeting a protected resource.
3. The request is sent to the ORY Oathkeeper instance.
4. ORY Oathkeeper receives the request and normalizes the path, correctly resolving it to `/admin/secrets`.
5. However, the authorization check uses the raw, un-normalized path (`/public/../admin/secrets`) to evaluate access rules.
6. A permissive rule matching the un-normalized path is found, potentially granting access.
7. ORY Oathkeeper incorrectly authorizes the request based on the flawed path evaluation.
8. The attacker gains unauthorized access to the protected resource `/admin/secrets`, potentially exfiltrating sensitive information or performing unauthorized actions.

## Impact

Successful exploitation of CVE-2026-33494 allows attackers to bypass intended access controls within ORY Oathkeeper deployments. This can lead to unauthorized access to sensitive data, configuration settings, and administrative functionalities. Given the role of ORY Oathkeeper in securing HTTP requests, a successful attack can compromise the confidentiality and integrity of protected applications and resources. The CVSS v3.1 base score of 10.0 reflects the criticality of this vulnerability.

## Recommendation

*   Immediately upgrade ORY Oathkeeper to version 26.2.0 or later to remediate CVE-2026-33494.
*   Deploy the Sigma rule "Detect ORY Oathkeeper Path Traversal Attempts" to identify exploitation attempts in web server logs.
*   Monitor web server logs for HTTP requests containing path traversal sequences (e.g., `..`, `%2e%2e`) in the URI, as detected by the Sigma rule "Detect Generic HTTP Path Traversal".
*   Implement web application firewall (WAF) rules to block requests with malicious path traversal patterns.
