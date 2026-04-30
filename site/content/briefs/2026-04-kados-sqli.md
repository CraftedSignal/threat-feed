---
title: Kados R10 GreenBee SQL Injection Vulnerability (CVE-2019-25692)
slug: 2026-04-kados-sqli
description: Kados R10 GreenBee is vulnerable to SQL injection via the 'id_to_modify' parameter, enabling attackers to manipulate database queries and potentially extract or modify sensitive data.
date: "2026-04-05T21:16:47Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - sqli
  - cve-2019-25692
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2019-25692
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25692
  - https://www.exploit-db.com/exploits/46505
  - https://www.vulncheck.com/advisories/kados-r10-greenbee-sql-injection-via-id-to-modify-parameter
rules:
  - title: Detect Suspicious SQL Injection Attempt
    description: Detects potential SQL injection attempts by looking for common SQL keywords in the 'id_to_modify' parameter within web server logs.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection via HTTP Request
    description: This rule detects potential SQL injection attempts by looking for common SQL injection payloads in HTTP requests.
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

Kados R10 GreenBee is susceptible to an SQL injection vulnerability (CVE-2019-25692) affecting the 'id_to_modify' parameter. An attacker can inject malicious SQL code into this parameter through crafted HTTP requests. Successful exploitation allows the attacker to manipulate database queries, potentially leading to unauthorized data access, modification, or deletion. This vulnerability poses a significant risk to organizations using Kados R10 GreenBee, as it could compromise the confidentiality, integrity, and availability of their data. The vulnerability was reported in 2026. The scope of targeting is any system running a vulnerable version of Kados R10 GreenBee.

## Attack Chain

1.  The attacker identifies an endpoint in the Kados R10 GreenBee application that utilizes the 'id_to_modify' parameter in a database query.
2.  The attacker crafts a malicious HTTP request containing SQL injection payloads within the 'id_to_modify' parameter.
3.  The attacker sends the crafted HTTP request to the vulnerable Kados R10 GreenBee endpoint.
4.  The Kados R10 GreenBee application fails to properly sanitize the 'id_to_modify' parameter before incorporating it into a database query.
5.  The database server executes the malicious SQL code injected by the attacker.
6.  The attacker retrieves sensitive database information via SELECT queries (e.g., usernames, passwords, personal data).
7.  Alternatively, the attacker modifies database records using INSERT, UPDATE, or DELETE queries, causing data corruption or unauthorized modifications.
8.  The attacker may attempt to escalate privileges within the database or gain access to the underlying operating system depending on the database configuration and permissions.

## Impact

Successful exploitation of this SQL injection vulnerability can lead to a range of damaging consequences. An attacker could potentially access sensitive customer data, financial records, or proprietary information. They could also modify or delete data, leading to data corruption, service disruption, or financial loss. The number of affected systems and the potential damage depend on the deployment and data stored within the vulnerable Kados R10 GreenBee instance.

## Recommendation

*   Inspect web server logs for suspicious requests targeting Kados R10 GreenBee endpoints that use the `id_to_modify` parameter, looking for SQL syntax such as `UNION`, `SELECT`, `UPDATE`, or `DELETE` (see "Detect Suspicious SQL Injection Attempt" Sigma rule).
*   Deploy the "Detect SQL Injection via HTTP Request" Sigma rule to monitor for potential SQL injection attempts based on common SQL injection payloads in HTTP requests.
*   Implement input validation and sanitization measures for all user-supplied data, especially the 'id_to_modify' parameter, to prevent SQL injection attacks.
*   Upgrade Kados R10 GreenBee to a patched version that addresses CVE-2019-25692.
