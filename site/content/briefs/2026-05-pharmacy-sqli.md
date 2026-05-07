---
title: SourceCodester Pharmacy Sales and Inventory System SQL Injection Vulnerability
slug: 2026-05-pharmacy-sqli
description: A remote SQL injection vulnerability exists in SourceCodester Pharmacy Sales and Inventory System 1.0 via manipulation of the ID argument in the /ajax.php?action=save_user file, potentially allowing attackers to execute arbitrary SQL queries.
date: "2026-05-07T19:16:02Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - web-application
  - cve-2026-8083
vendors:
  - SourceCodester
products:
  - Pharmacy Sales and Inventory System 1.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
cves:
  - id: CVE-2026-8083
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-8083
  - https://github.com/zhi-cyber/cve-2/issues/1
  - https://vuldb.com/vuln/361837
rules:
  - title: Detect Pharmacy Sales SQL Injection in Save User
    description: Detects SQL injection attempts in the /ajax.php?action=save_user endpoint by identifying suspicious characters and keywords commonly used in SQL injection payloads.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1595.002
    data_sources:
      - webserver
      - linux
  - title: Detect Pharmacy Sales SQL Injection via POST
    description: Detects SQL injection attempts via POST data in the /ajax.php?action=save_user endpoint by identifying suspicious characters and keywords commonly used in SQL injection payloads.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1595.002
    data_sources:
      - webserver
      - linux
rules_count: 2
---

SourceCodester Pharmacy Sales and Inventory System 1.0 is vulnerable to SQL injection. The vulnerability, identified as CVE-2026-8083, resides within the /ajax.php?action=save_user file. By manipulating the ID argument, a remote attacker can inject arbitrary SQL code, potentially leading to unauthorized data access, modification, or deletion. The exploit has been publicly disclosed, increasing the risk of exploitation. This vulnerability poses a significant threat to organizations using the affected software, as it can compromise the integrity and confidentiality of sensitive pharmacy and inventory data.

## Attack Chain

1.  Attacker identifies the vulnerable endpoint: `/ajax.php?action=save_user`.
2.  Attacker crafts a malicious SQL payload, injecting it into the `ID` parameter of the request.
3.  The vulnerable application fails to properly sanitize the input provided by the attacker.
4.  The application executes the crafted SQL query against the database.
5.  The attacker gains the ability to read sensitive data from the database, such as user credentials, patient information, or inventory details.
6.  The attacker modifies or deletes data within the database, potentially disrupting pharmacy operations or altering financial records.

## Impact

Successful exploitation of this SQL injection vulnerability could lead to significant data breaches, including unauthorized access to sensitive patient information, financial records, and inventory data. This could result in regulatory fines, reputational damage, and disruption of pharmacy operations. Given the public availability of the exploit, organizations using SourceCodester Pharmacy Sales and Inventory System 1.0 are at increased risk.

## Recommendation

*   Deploy the Sigma rule `Detect_Pharmacy_SQLi_Save_User` to identify attempts to exploit the SQL injection vulnerability in the `/ajax.php?action=save_user` endpoint.
*   Apply input validation and sanitization to the `ID` parameter in `/ajax.php?action=save_user` to prevent SQL injection, mitigating CVE-2026-8083.
