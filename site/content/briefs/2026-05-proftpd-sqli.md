---
title: ProFTPD Vulnerability Allows SQL Injection
slug: 2026-05-proftpd-sqli
description: A remote, anonymous attacker can exploit a SQL injection vulnerability in ProFTPD, potentially leading to unauthorized data access or modification.
date: "2026-05-06T10:26:06Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - proftpd
  - sql-injection
  - vulnerability
  - linux
vendors:
  - ProFTPD
products:
  - ProFTPD
affected_os:
  - linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-1363
rules:
  - title: ProFTPD SQL Injection Attempt
    description: Detects potential SQL injection attempts against ProFTPD servers based on URI patterns.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: ProFTPD POST Request SQL Injection
    description: Detects potential SQL injection attempts in POST requests to ProFTPD based on content patterns.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A vulnerability exists within ProFTPD that allows for SQL injection attacks. This issue enables a remote, anonymous attacker to inject malicious SQL code into ProFTPD processes. The vulnerability could be exploited without authentication, meaning any ProFTPD instance exposed to the internet is a potential target. Successful exploitation of this vulnerability may allow the attacker to read, modify, or delete sensitive data stored within the ProFTPD database, or potentially gain further access to the underlying system. Defenders should prioritize patching ProFTPD installations and implementing detection mechanisms to identify potential exploitation attempts.

## Attack Chain

1. An anonymous attacker identifies a ProFTPD server exposed to the internet.
2. The attacker crafts a malicious SQL injection payload.
3. The attacker sends a specially crafted request to the ProFTPD server, injecting the SQL payload into a vulnerable parameter.
4. The ProFTPD server processes the malicious SQL payload without proper sanitization.
5. The injected SQL code is executed against the ProFTPD database.
6. Depending on the injected SQL, the attacker may be able to read sensitive data, such as usernames, passwords, or file listings.
7. The attacker could also modify data within the ProFTPD database, potentially granting themselves administrative privileges.
8. The attacker could leverage gained privileges to execute arbitrary commands on the underlying system.

## Impact

Successful exploitation of this SQL injection vulnerability could allow attackers to compromise ProFTPD servers. This could lead to unauthorized access to sensitive data, including usernames, passwords, and file listings. In a worst-case scenario, attackers could gain complete control over the affected server, potentially impacting data confidentiality, integrity, and availability. While specific victim counts are unavailable, any organization utilizing a vulnerable ProFTPD installation is at risk.

## Recommendation

*   Deploy the Sigma rule `ProFTPD SQL Injection Attempt` to your SIEM to detect potential exploitation attempts based on specific patterns in web server logs.
*   Apply available patches or updates for ProFTPD from the vendor to remediate the underlying vulnerability.
*   Review and harden ProFTPD configurations to limit potential attack vectors and strengthen security measures.
*   Enable and review webserver logs (cs-uri-query, cs-method, sc-status) for anomalies related to potential SQL injection attempts.
