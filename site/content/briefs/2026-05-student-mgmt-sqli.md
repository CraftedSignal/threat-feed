---
title: SQL Injection Vulnerability in StudentManagementSystem (CVE-2026-9474)
slug: 2026-05-student-mgmt-sqli
description: A SQL injection vulnerability (CVE-2026-9474) exists in the StudentManagementSystem application, specifically affecting the confirm_logged_in function within the /studentdel.php file, allowing remote attackers to execute arbitrary SQL commands by manipulating the ID parameter.
date: "2026-05-26T14:23:34Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve
  - sql injection
  - web application
products:
  - StudentManagementSystem
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-9474
    cvss: 7.3
    epss: 0.0003
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9474
  - CVE-2026-9474
rules:
  - title: Detects CVE-2026-9474 Exploitation — SQL Injection Attempt in StudentManagementSystem
    description: Detects CVE-2026-9474 exploitation — SQL injection attempts targeting the /studentdel.php endpoint by identifying common SQL injection payloads in the ID parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2026-9474 Exploitation — Student Management System SQL Injection via POST Request
    description: Detects CVE-2026-9474 exploitation — Identifies SQL injection attempts targeting the /studentdel.php endpoint using POST requests with suspicious characters.
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

A SQL injection vulnerability, identified as CVE-2026-9474, has been discovered in the StudentManagementSystem application, affecting versions up to commit cb2f558ddf8d19396de0f92abf2d224d46a0a203. The vulnerability is located in the `confirm_logged_in` function of the `/studentdel.php` file. An attacker can remotely exploit this vulnerability by manipulating the `ID` argument passed to the function, enabling them to inject and execute arbitrary SQL commands. While the vulnerability has been publicly disclosed, the vendor has not yet responded to the report. Given the continuous delivery model, specific affected or updated version details are unavailable, increasing the risk for deployments relying on this system.

## Attack Chain

1. An attacker identifies an instance of StudentManagementSystem running a vulnerable version (<= cb2f558ddf8d19396de0f92abf2d224d46a0a203).
2. The attacker crafts a malicious HTTP request targeting the `/studentdel.php` endpoint.
3. The crafted request includes a manipulated `ID` parameter containing SQL injection payloads (e.g., `1' OR '1'='1`).
4. The `confirm_logged_in` function in `/studentdel.php` receives the tainted `ID` parameter without proper sanitization.
5. The application executes a SQL query that incorporates the attacker-controlled `ID` value.
6. The injected SQL code modifies the original query, allowing the attacker to bypass authentication or access unauthorized data.
7. The application returns sensitive data or allows the attacker to perform administrative actions.
8. The attacker gains unauthorized access to the database, potentially exfiltrating data or modifying application settings.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2026-9474) can lead to unauthorized access to sensitive student data, modification of records, or complete database compromise. The lack of versioning information due to the rolling release nature of the application makes patching and mitigation challenging. The vulnerability allows attackers to bypass authentication and potentially escalate privileges. While the exact number of affected installations is unknown, any system running a vulnerable version is at risk of data breaches and service disruption.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM to detect potential SQL injection attempts targeting `/studentdel.php` and the `ID` parameter.
*   Implement input validation and sanitization for the `ID` parameter in the `confirm_logged_in` function within `/studentdel.php` to prevent SQL injection.
*   Monitor web server logs for suspicious requests to `/studentdel.php` containing SQL injection payloads.
*   Consider using a web application firewall (WAF) to filter out malicious requests targeting the vulnerable endpoint.
*   Follow secure coding practices to prevent SQL injection vulnerabilities in future releases of StudentManagementSystem.
*   Apply any available patches or updates released by the vendor as soon as they become available, even without version numbers.
