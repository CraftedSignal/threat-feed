---
title: ProFTPD SQL Injection Vulnerability
slug: 2024-01-proftpd-sqli
description: An anonymous remote attacker can exploit a SQL injection vulnerability in ProFTPD.
date: "2026-04-29T09:54:05Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - sqli
  - proftpd
  - linux
vendors:
  - ProFTPD
products:
  - ProFTPD
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-1297
rules:
  - title: Detect ProFTPD SQL Injection Attempts in Logs
    description: Detects potential SQL injection attempts in ProFTPD logs based on common SQL syntax.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect ProFTPD Authentication Bypass via SQL Injection
    description: Detects potential ProFTPD authentication bypass by using SQL injection.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A vulnerability in ProFTPD allows for SQL injection attacks by remote, unauthenticated attackers. The specific flaw and version number are not mentioned in the source, but the generic report indicates a potentially widespread issue affecting publicly accessible ProFTPD servers. Successful exploitation could lead to unauthorized data access, modification, or potentially complete system compromise depending on the database permissions configured for ProFTPD. Defenders should apply all available security patches for ProFTPD.

## Attack Chain

1. Attacker identifies a ProFTPD server exposed to the internet.
2. Attacker crafts a malicious SQL injection payload.
3. Attacker sends the crafted SQL injection payload through a ProFTPD command or parameter.
4. ProFTPD processes the malicious payload without proper sanitization.
5. The payload is passed to the underlying database server.
6. The database executes the injected SQL command.
7. The attacker retrieves sensitive data or modifies database records.
8. Attacker may use the gained access to further compromise the server or network.

## Impact

Successful exploitation of the SQL injection vulnerability in ProFTPD allows unauthorized access to the underlying database. This can lead to the disclosure of sensitive information, modification of data, or even complete database compromise. The number of victims and sectors targeted are currently unknown, but public-facing ProFTPD servers are at risk. A successful attack could lead to significant data breaches, service disruption, and reputational damage.

## Recommendation

*   Apply the latest security patches for ProFTPD as soon as they are available to remediate SQL injection vulnerabilities.
*   Monitor ProFTPD logs for suspicious activity and SQL injection attempts (see Sigma rule below).
*   Implement proper input validation and sanitization techniques to prevent SQL injection vulnerabilities in ProFTPD configurations.
*   Review database access permissions for the ProFTPD user to minimize the impact of potential SQL injection attacks.
