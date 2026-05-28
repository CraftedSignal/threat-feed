---
title: 'CVE-2026-46833: Oracle Database Server Net Service Takeover'
slug: 2026-05-oracle-net-service-rce
description: CVE-2026-46833 allows an unauthenticated attacker with network access via TLS to compromise the Net Service component of Oracle Database Server versions 23.4.0 through 23.26.2, potentially leading to takeover of the Net Service and significant impact on other products.
date: "2026-05-28T21:18:32Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve
  - oracle
  - database
  - netservice
  - rce
  - network
vendors:
  - Oracle
products:
  - Database Server (23.4.0-23.26.2)
  - Net Service
cves:
  - id: CVE-2026-46833
    cvss: 9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-46833
  - CVE-2026-46833
rules:
  - title: Detect CVE-2026-46833 Exploitation Attempt
    description: Detects CVE-2026-46833 exploitation — Monitors network traffic for suspicious patterns indicative of CVE-2026-46833 exploitation attempts against Oracle Net Service.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - windows
  - title: Detect Suspicious TLS Handshake
    description: Detects suspicious TLS handshakes that may indicate an attempt to exploit CVE-2026-46833 by monitoring for unusual TLS extensions or cipher suites.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CVE-2026-46833 is a critical vulnerability affecting the Net Service component of Oracle Database Server. This vulnerability exists in versions 23.4.0 through 23.26.2. An unauthenticated attacker with network access via TLS can exploit this vulnerability to compromise the Net Service. While the vulnerability resides within the Net Service, successful exploitation may lead to a scope change, significantly impacting other products within the Oracle Database Server ecosystem. Successful exploitation leads to complete takeover of the Net Service. This vulnerability poses a severe risk to organizations utilizing affected versions of Oracle Database Server, as it can allow for unauthorized access and control over critical database functions.

## Attack Chain

1.  Attacker establishes a TLS connection to the vulnerable Oracle Database Server Net Service.
2.  The attacker sends a specially crafted request to the Net Service exploiting CVE-2026-46833.
3.  The vulnerable Net Service improperly processes the request, bypassing authentication checks.
4.  The attacker gains unauthorized access to the Net Service due to the authentication bypass.
5.  The attacker leverages the compromised Net Service to execute arbitrary commands within the Net Service context.
6.  The attacker uses the compromised Net Service as a pivot point to target other products within the Oracle Database Server environment.
7.  The attacker escalates privileges within the Net Service to gain full control over the component.
8.  The attacker takes complete control of the Net Service, potentially disrupting database operations and exfiltrating sensitive data.

## Impact

Successful exploitation of CVE-2026-46833 can result in a complete takeover of the Oracle Database Server Net Service. Given that the vulnerability is rated as difficult to exploit, targeted attacks are more likely than widespread opportunistic exploitation. Due to the potential for scope change, other database products are significantly impacted. A successful attack can lead to confidentiality breaches, data integrity violations, and complete disruption of database services.

## Recommendation

*   Apply the latest security patches provided by Oracle to address CVE-2026-46833 on all affected Oracle Database Server installations (Database Server (23.4.0-23.26.2)).
*   Deploy the Sigma rule `Detect CVE-2026-46833 Exploitation Attempt` to identify potential exploitation attempts targeting the Net Service.
*   Monitor network traffic for suspicious TLS connections to the Oracle Database Server, specifically looking for unusual patterns or malformed requests as detected by Sigma rule `Detect Suspicious TLS Handshake`.
*   Implement network segmentation to limit the potential impact of a successful Net Service compromise on other products, mitigating the scope change mentioned in the overview.
