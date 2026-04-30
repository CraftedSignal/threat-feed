---
title: ElectricSQL /v1/shape API SQL Injection Vulnerability
slug: 2026-04-electric-sql-injection
description: The ElectricSQL sync engine is vulnerable to SQL injection, potentially allowing authenticated users to read, write, and destroy the underlying PostgreSQL database.
date: "2026-04-22T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - sql-injection
  - electricsql
  - postgresql
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-40906
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40906
  - https://github.com/electric-sql/electric/pull/4081
  - https://github.com/electric-sql/electric/security/advisories/GHSA-h5rg-pxx7-r2hj
rules:
  - title: Detect Suspicious SQL Injection Attempt in ElectricSQL API Request
    description: Detects potential SQL injection attempts targeting the ElectricSQL /v1/shape API by looking for specific SQL keywords in the order_by parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious SQL Injection Error Messages
    description: Detects potential SQL injection exploitation by identifying common SQL error messages in server responses.
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

Electric, a Postgres sync engine, is vulnerable to SQL injection in the `order_by` parameter of the ElectricSQL `/v1/shape` API endpoint. This vulnerability exists in versions 1.1.12 to before 1.5.0. Exploitation allows any authenticated user to execute arbitrary SQL queries, leading to potential data breaches, data manipulation, and complete database compromise. Successful exploitation can result in unauthorized access to sensitive information, modification of critical data, and denial of service. Organizations using vulnerable versions of ElectricSQL are at high risk. The vulnerability is resolved in version 1.5.0.

## Attack Chain

1. An attacker authenticates to the ElectricSQL application.
2. The attacker crafts a malicious HTTP request targeting the `/v1/shape` API endpoint.
3. The crafted request includes a SQL injection payload within the `order_by` parameter.
4. The ElectricSQL application processes the request without proper sanitization of the `order_by` parameter.
5. The malicious SQL payload is executed against the underlying PostgreSQL database.
6. The attacker leverages the SQL injection vulnerability to extract sensitive data, such as user credentials or proprietary information, using `SELECT` statements.
7. The attacker escalates privileges by manipulating database objects or creating new administrative accounts using `CREATE` and `ALTER` statements.
8. The attacker destroys data or renders the database unavailable using `DELETE` and `DROP` statements, achieving complete system compromise.

## Impact

Successful exploitation of this SQL injection vulnerability could lead to a complete compromise of the underlying PostgreSQL database. This may result in unauthorized access to sensitive data, including customer information, financial records, and intellectual property. Attackers could also modify or delete data, leading to data loss, service disruption, and reputational damage. Given the potential for complete data destruction, organizations are urged to remediate this vulnerability immediately.

## Recommendation

*   Upgrade ElectricSQL to version 1.5.0 or later to patch the vulnerability (CVE-2026-40906).
*   Implement input validation and sanitization for all user-supplied data, especially in the `order_by` parameter of the `/v1/shape` API.
*   Monitor web server logs for suspicious activity, such as unusual characters or SQL keywords in the `order_by` parameter of requests to the `/v1/shape` API to enable the "Detect Suspicious SQL Injection Attempt in ElectricSQL API Request" rule.
*   Deploy the Sigma rule "Detect Suspicious SQL Injection Error Messages" to identify potential exploitation attempts based on error responses from the database server.
