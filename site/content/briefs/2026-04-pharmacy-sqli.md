---
title: SourceCodester Pharmacy Sales and Inventory System SQL Injection Vulnerability
slug: 2026-04-pharmacy-sqli
description: A remote SQL injection vulnerability exists in SourceCodester Pharmacy Sales and Inventory System 1.0 via manipulation of the ID parameter in the /ajax.php?action=delete_category endpoint, potentially leading to unauthorized data access or modification.
date: "2026-04-28T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sqli
  - web-application
  - cve-2026-7130
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
  - id: CVE-2026-7130
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7130
  - https://github.com/lonelyuan/vunls/issues/11
  - https://vuldb.com/vuln/359729
rules:
  - title: Detect SQL Injection Attempt in Pharmacy Sales System
    description: Detects potential SQL injection attempts targeting the /ajax.php endpoint by looking for common SQL syntax in the ID parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1595
    data_sources:
      - webserver
      - linux
  - title: Detect Hex Encoded SQL Injection in Pharmacy Sales System
    description: Detects potential SQL injection attempts using hex encoding in the /ajax.php endpoint.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1595
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A SQL injection vulnerability has been identified in SourceCodester Pharmacy Sales and Inventory System version 1.0. The vulnerability resides within the `/ajax.php?action=delete_category` endpoint, where a manipulation of the `ID` argument can lead to arbitrary SQL command execution. This allows remote attackers to potentially bypass authentication, access sensitive data, modify database contents, or even compromise the entire system. Given the availability of a published exploit, this vulnerability poses a significant risk to organizations utilizing the affected software. Successful exploitation requires no authentication.

## Attack Chain

1. Attacker identifies an instance of SourceCodester Pharmacy Sales and Inventory System 1.0.
2. Attacker crafts a malicious HTTP request targeting the `/ajax.php?action=delete_category` endpoint.
3. The attacker injects SQL code into the `ID` parameter of the request.
4. The application fails to properly sanitize the input, passing the malicious SQL code to the database.
5. The database executes the attacker-controlled SQL query.
6. Depending on the injected SQL, the attacker can read sensitive data from the database (e.g., user credentials, financial records).
7. The attacker could also modify data, such as altering inventory levels or creating unauthorized accounts.
8. Ultimately, the attacker could gain full control of the database and the application.

## Impact

Successful exploitation of this SQL injection vulnerability could result in unauthorized access to sensitive patient data, financial records, and other confidential information stored within the Pharmacy Sales and Inventory System database. Attackers could potentially modify data, leading to incorrect inventory levels, fraudulent transactions, or even complete system compromise. This could result in significant financial losses, reputational damage, and legal repercussions for affected organizations. Given that the exploit is public, organizations using this software are at immediate risk.

## Recommendation

*   Apply input validation and sanitization to the `ID` parameter within the `/ajax.php?action=delete_category` endpoint to prevent SQL injection (reference CVE-2026-7130).
*   Deploy the provided Sigma rule to detect suspicious requests to the `/ajax.php?action=delete_category` endpoint containing potential SQL injection attempts.
*   Implement regular security audits and penetration testing to identify and remediate vulnerabilities in web applications.
*   Restrict database access privileges to the minimum necessary for each user and application to limit the potential impact of a successful SQL injection attack.
