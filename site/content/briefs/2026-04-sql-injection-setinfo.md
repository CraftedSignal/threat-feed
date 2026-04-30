---
title: Unauthenticated SQL Injection Vulnerability in setinfo Endpoint
slug: 2026-04-sql-injection-setinfo
description: An unauthenticated remote attacker can exploit a SQL Injection vulnerability (CVE-2026-33615) in the setinfo endpoint by injecting malicious code into a SQL UPDATE command, leading to a total loss of integrity and availability.
date: "2026-04-02T10:16:16Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - sql-injection
  - vulnerability
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-33615
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33615
  - https://certvde.com/de/advisories/VDE-2026-030
  - https://mbconnectline.csaf-tp.certvde.com/.well-known/csaf/white/2026/vde-2026-030.json
iocs:
  - type: url
    value: https://certvde.com/de/advisories/VDE-2026-030
  - type: url
    value: https://mbconnectline.csaf-tp.certvde.com/.well-known/csaf/white/2026/vde-2026-030.json
  - type: email
    value: '[email protected]'
ioc_counts:
  email: 1
  url: 2
rules:
  - title: Detect Potential SQL Injection in setinfo Endpoint
    description: Detects potential SQL injection attempts in requests to the setinfo endpoint by looking for common SQL keywords.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Error Messages Indicating Potential Injection
    description: Detects SQL error messages in web server responses which may indicate successful or attempted SQL injection.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-33615 describes a critical security vulnerability affecting the `setinfo` endpoint. This vulnerability allows an unauthenticated remote attacker to inject malicious SQL code due to the improper neutralization of special elements within a SQL UPDATE command. The vulnerability was published on April 2, 2026. Successful exploitation can lead to complete data compromise, system downtime, and a total loss of integrity and availability. This vulnerability poses a significant risk to organizations utilizing the affected `setinfo` endpoint.

## Attack Chain

1.  The attacker identifies the vulnerable `setinfo` endpoint, which is accessible without authentication.
2.  The attacker crafts a malicious HTTP request containing SQL injection payloads within the parameters intended for the `setinfo` function.
3.  The application fails to properly sanitize or validate the input, allowing the SQL injection payload to be passed directly to the database.
4.  The injected SQL code is executed within the context of the SQL UPDATE command, potentially modifying sensitive data.
5.  The attacker leverages the SQL injection to escalate privileges or gain access to other parts of the database.
6.  The attacker may exfiltrate sensitive information or modify database records to cause a denial of service.
7.  The attacker can potentially overwrite critical data, leading to a total loss of integrity.
8.  The attacker may use the compromised system as a pivot point to attack other internal systems.

## Impact

Successful exploitation of this vulnerability (CVE-2026-33615) can lead to a total loss of data integrity and system availability. This could result in significant financial losses, reputational damage, and disruption of critical services. Since the vulnerability is unauthenticated, any attacker on the network can potentially exploit it, leading to widespread compromise.

## Recommendation

*   Inspect web server logs for unusual requests to the `setinfo` endpoint containing SQL syntax to identify potential exploitation attempts (Log source: webserver).
*   Monitor database logs for SQL UPDATE commands originating from the application that contain suspicious or unexpected syntax to detect potential SQL injection (Log source: database).
*   Implement input validation and sanitization measures to neutralize special elements in SQL commands to prevent future exploitation of SQL injection vulnerabilities.
*   Deploy the Sigma rule "Detect Potential SQL Injection in setinfo Endpoint" to your SIEM and tune for your environment.
