---
title: SourceCodester Pharmacy Sales and Inventory System SQL Injection Vulnerability
slug: 2024-01-pharmacy-inventory-sqli
description: CVE-2026-6187 is a remote SQL injection vulnerability in SourceCodester Pharmacy Sales and Inventory System 1.0 via the ID parameter in /ajax.php?action=chk_prod_availability, allowing unauthenticated attackers to execute arbitrary SQL queries.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - sqli
  - vulnerability
  - web-application
vendors:
  - SourceCodester
products:
  - Pharmacy Sales and Inventory System
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-6187
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6187
rules:
  - title: Detect SQL Injection Attempt
    description: Detects potential SQL injection attempts by identifying SQL keywords in URI query parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Access to Sensitive Files via SQL Injection
    description: Detects attempts to access sensitive files (e.g., /etc/passwd) using SQL injection techniques.
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

SourceCodester Pharmacy Sales and Inventory System version 1.0 is vulnerable to SQL injection via the `/ajax.php?action=chk_prod_availability` endpoint. The vulnerability, identified as CVE-2026-6187, allows a remote attacker to manipulate the `ID` argument to inject arbitrary SQL queries into the application's database. Given the public availability of the exploit, organizations using this vulnerable software are at immediate risk. Exploitation does not require authentication, making it easier to exploit and potentially leading to complete database compromise. The lack of required authentication combined with the ease of exploitation, means that any unpatched instance is at high risk of being exploited.

## Attack Chain

1.  The attacker identifies an instance of SourceCodester Pharmacy Sales and Inventory System 1.0.
2.  The attacker crafts a malicious HTTP GET request targeting the `/ajax.php?action=chk_prod_availability` endpoint.
3.  The attacker injects SQL code into the `ID` parameter of the request.
4.  The vulnerable application processes the attacker-supplied SQL code without proper sanitization or validation.
5.  The injected SQL code is executed against the application's database.
6.  The attacker retrieves sensitive information from the database, such as user credentials, financial data, or inventory details.
7.  The attacker uses the obtained credentials to gain unauthorized access to the application or the underlying system.

## Impact

Successful exploitation of this vulnerability can lead to complete database compromise, potentially exposing sensitive patient data, financial records, and proprietary business information. The vulnerability affects all installations of SourceCodester Pharmacy Sales and Inventory System 1.0 that have not been patched. Given the nature of the software, successful attacks could lead to significant financial losses, reputational damage, and regulatory penalties.

## Recommendation

*   Apply the patch or upgrade to a secure version of SourceCodester Pharmacy Sales and Inventory System to remediate CVE-2026-6187.
*   Implement the Sigma rule `Detect SQL Injection Attempt` to identify potential exploitation attempts in web server logs.
*   Monitor web server logs for suspicious requests targeting the `/ajax.php?action=chk_prod_availability` endpoint, specifically looking for unusual characters or SQL keywords in the `ID` parameter.
