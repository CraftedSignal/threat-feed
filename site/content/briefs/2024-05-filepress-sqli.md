---
title: zyx0814 FilePress SQL Injection Vulnerability (CVE-2026-8133)
slug: 2024-05-filepress-sqli
description: A remote SQL injection vulnerability (CVE-2026-8133) exists in zyx0814 FilePress up to version 2.2.0 via the Shares Filelist API by manipulating the argument order, potentially leading to unauthorized data access or modification.
date: "2024-05-29T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - vulnerability
  - web-application
vendors:
  - zyx0814
products:
  - FilePress (<= 2.2.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-8133
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-8133
rules:
  - title: Detect FilePress SQL Injection Attempt via admin.php
    description: Detects CVE-2026-8133 exploitation — Monitors HTTP requests to the vulnerable admin.php endpoint with suspicious SQL syntax in the query parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect FilePress SQL Injection - Filter Bypass Attempts
    description: Detects CVE-2026-8133 exploitation — Detects attempts to bypass SQL injection filters using comment obfuscation or encoding techniques in FilePress admin.php.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

A SQL injection vulnerability, identified as CVE-2026-8133, affects zyx0814 FilePress versions up to 2.2.0. The vulnerability resides within the Shares Filelist API, specifically in the `dzz/shares/admin.php` file. Attackers can exploit this flaw by manipulating the argument order in requests to this API, leading to the execution of arbitrary SQL queries. Public disclosure of the exploit makes this vulnerability particularly dangerous, as it increases the likelihood of widespread exploitation. A patch, identified as `e20ec58414103f781858f2951d178e19b1736664`, is available to address this issue. This vulnerability allows remote attackers to potentially read, modify, or delete sensitive data stored in the FilePress database.

## Attack Chain

1.  The attacker identifies a FilePress instance running a vulnerable version (<= 2.2.0).
2.  The attacker crafts a malicious HTTP request targeting the `dzz/shares/admin.php` endpoint.
3.  The request includes specially crafted parameters designed to manipulate the argument order in the SQL query.
4.  The application fails to properly sanitize or validate the input, allowing the malicious SQL code to be injected.
5.  The injected SQL code is executed against the FilePress database.
6.  The attacker extracts sensitive information from the database, such as usernames, passwords, or file metadata.
7.  The attacker may further modify database records to escalate privileges or plant malicious code.
8.  The attacker gains unauthorized access to files or system resources, potentially leading to data theft or system compromise.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2026-8133) can have significant consequences. Attackers can gain unauthorized access to sensitive data stored in the FilePress database, potentially leading to data breaches and financial losses. Attackers could modify or delete data, disrupt services, or even gain complete control of the affected FilePress instance. Given the public disclosure of the exploit, organizations using FilePress are at an elevated risk.

## Recommendation

*   Apply the patch `e20ec58414103f781858f2951d178e19b1736664` provided by zyx0814 to remediate CVE-2026-8133.
*   Deploy the Sigma rule "Detect FilePress SQL Injection Attempt via admin.php" to your SIEM to identify potential exploitation attempts against the vulnerable `dzz/shares/admin.php` endpoint.
*   Review and harden input validation mechanisms in FilePress to prevent future SQL injection vulnerabilities.
*   Monitor web server logs for suspicious requests targeting the `dzz/shares/admin.php` endpoint (webserver category).
