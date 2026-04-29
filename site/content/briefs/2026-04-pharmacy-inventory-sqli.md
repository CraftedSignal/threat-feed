---
title: SourceCodester Pharmacy Sales and Inventory System SQL Injection Vulnerability (CVE-2026-7199)
slug: 2026-04-pharmacy-inventory-sqli
description: A SQL injection vulnerability (CVE-2026-7199) exists in SourceCodester Pharmacy Sales and Inventory System 1.0, allowing remote attackers to execute arbitrary SQL commands by manipulating the 'ID' parameter in the `/ajax.php?action=delete_product` endpoint, potentially leading to data breach or system compromise.
date: "2026-04-28T00:16:26Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - sql-injection
  - cve-2026-7199
  - web-application
vendors:
  - SourceCodester
products:
  - Pharmacy Sales and Inventory System 1.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7199
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7199
  - https://github.com/3436567162/vlun/issues/2
  - https://vuldb.com/submit/801109
  - https://vuldb.com/vuln/359800
  - https://vuldb.com/vuln/359800/cti
  - https://www.sourcecodester.com/
rules:
  - title: Detecting SQL Injection Attempts via URI
    description: Detects potential SQL injection attempts by identifying requests containing common SQL injection payloads in the URI.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detecting SQL Injection in Pharmacy System
    description: Detects SQL injection attempts targeting the /ajax.php?action=delete_product endpoint.
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

A SQL injection vulnerability has been identified in SourceCodester Pharmacy Sales and Inventory System version 1.0. This vulnerability, assigned CVE-2026-7199, affects the `/ajax.php?action=delete_product` endpoint. Attackers can remotely exploit this vulnerability by manipulating the `ID` parameter. The vulnerability was published on April 27, 2026, and the exploit is now publicly available. Successful exploitation allows attackers to execute arbitrary SQL commands, potentially leading to unauthorized data access, modification, or deletion. Due to the ease of exploitation and the sensitive nature of pharmacy data, this vulnerability poses a significant risk to organizations using the affected system.

## Attack Chain

1.  The attacker identifies a vulnerable instance of SourceCodester Pharmacy Sales and Inventory System 1.0.
2.  The attacker crafts a malicious HTTP request targeting the `/ajax.php?action=delete_product` endpoint.
3.  The attacker injects SQL code into the `ID` parameter of the request.
4.  The server-side application fails to properly sanitize the input, passing the malicious SQL code to the database.
5.  The database executes the injected SQL code, potentially allowing the attacker to bypass authentication, access sensitive data, modify database records, or execute system commands.
6.  The attacker retrieves sensitive data, such as patient information, prescription details, or financial records.
7.  The attacker may escalate privileges within the application and the underlying system.
8.  The attacker can then exfiltrate the compromised data or maintain persistent access to the system for future attacks.

## Impact

Successful exploitation of this SQL injection vulnerability can lead to a complete compromise of the Pharmacy Sales and Inventory System. This can result in the theft of sensitive patient data, financial records, and other confidential information. The vulnerability allows attackers to potentially modify or delete critical data, leading to disruption of pharmacy operations, financial losses, and regulatory penalties. As the exploit is publicly available, the likelihood of widespread exploitation is high, impacting any organization using the vulnerable version of the software.

## Recommendation

*   Apply the Sigma rule `Detecting SQL Injection Attempts via URI` to identify potential exploitation attempts against the `/ajax.php?action=delete_product` endpoint.
*   Inspect web server logs for requests to `/ajax.php?action=delete_product` containing suspicious characters or SQL keywords in the `ID` parameter, as detected by the `Detecting SQL Injection in Pharmacy System` Sigma rule.
*   Implement input validation and sanitization measures to prevent SQL injection vulnerabilities in the SourceCodester Pharmacy Sales and Inventory System, mitigating the underlying issue.
*   Restrict access to the database server and sensitive data to only authorized personnel, reducing the potential impact of a successful SQL injection attack.
*   Monitor database logs for suspicious activity, such as unauthorized data access or modification, which may indicate successful exploitation of CVE-2026-7199.
