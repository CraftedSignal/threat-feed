---
title: 'CVE-2026-14642: SourceCodester Class and Exam Timetabling System SQL Injection'
slug: 2026-07-sourcecodester-sqli
description: A critical SQL injection vulnerability, identified as CVE-2026-14642, exists in SourceCodester Class and Exam Timetabling System version 1.0, allowing remote attackers to inject SQL commands by manipulating the 'ID' argument within the '/edit_class2.php' file, with an exploit publicly available.
date: "2026-07-04T19:24:10Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-application
  - sql-injection
  - remote-code-execution
  - data-exfiltration
  - vulnerability
  - cve
vendors:
  - SourceCodester
products:
  - Class and Exam Timetabling System 1.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A vulnerability was identified in SourceCodester Class and Exam Timetabling System 1.0. ... The manipulation of the argument ID leads to sql injection. The attack is possible to be carried out remotely. The exploit is publicly available and might be used.
    confidence_band: high
cves:
  - id: CVE-2026-14642
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14642
  - https://github.com/sunjingyuan123/ccvvee/issues/1
  - https://vuldb.com/cve/CVE-2026-14642
  - https://vuldb.com/submit/846144
  - https://vuldb.com/vuln/376158
  - https://vuldb.com/vuln/376158/cti
  - https://www.sourcecodester.com/
iocs:
  - type: url
    value: https://github.com/sunjingyuan123/ccvvee/issues/1
  - type: url
    value: https://vuldb.com/cve/CVE-2026-14642
  - type: url
    value: https://vuldb.com/vuln/376158
  - type: url
    value: https://www.sourcecodester.com/
ioc_counts:
  url: 4
rules:
  - title: Detect CVE-2026-14642 Exploitation — SourceCodester SQL Injection
    description: Detects CVE-2026-14642 exploitation against SourceCodester Class and Exam Timetabling System 1.0 via SQL injection in the 'ID' parameter of /edit_class2.php.
    platform: sigma
    severity: high
    tactics:
      - impact
      - initial_access
    techniques:
      - T1190
      - T1567
    data_sources:
      - webserver
rules_count: 1
---

A significant vulnerability, tracked as CVE-2026-14642, has been discovered in SourceCodester Class and Exam Timetabling System version 1.0. This flaw specifically affects an unknown functionality within the `/edit_class2.php` file, where improper handling of the `ID` argument allows for SQL injection. The vulnerability can be exploited remotely by an unauthenticated attacker, posing a substantial risk to organizations utilizing this system. The public availability of an exploit intensifies the threat, making it highly probable for malicious actors to leverage this weakness for unauthorized access to sensitive database information, data manipulation, or even further system compromise. Defenders must prioritize patching or mitigating this vulnerability immediately to prevent potential data breaches and system integrity compromises.

## Attack Chain

1.  An unauthenticated attacker identifies a SourceCodester Class and Exam Timetabling System 1.0 instance accessible over the internet.
2.  The attacker crafts a specially malformed HTTP GET request targeting the `/edit_class2.php` endpoint.
3.  The attacker manipulates the `ID` argument in the URL query string by injecting SQL metacharacters and payloads (e.g., `' OR 1=1--`).
4.  The vulnerable application processes this request without proper input validation, incorporating the malicious payload directly into a database query.
5.  The backend database executes the attacker-controlled SQL query, potentially disclosing sensitive data, modifying existing records, or executing arbitrary commands (if the database user has sufficient privileges).
6.  The application responds to the attacker with the results of the executed SQL query, allowing for data exfiltration or confirmation of successful command execution.
7.  The attacker extracts sensitive information from the database or uses the RCE capabilities to establish persistence or pivot further into the network.

## Impact

Successful exploitation of CVE-2026-14642 can lead to severe consequences for affected organizations. Attackers can gain unauthorized access to the application's underlying database, potentially exfiltrating sensitive student or class scheduling data, modifying records, or even deleting critical information. Given the nature of SQL injection, this could result in a complete compromise of confidentiality, integrity, and availability of the application's data. As the exploit is publicly available, organizations running the affected version are at immediate risk of data breaches and operational disruption. The CVSS score of 7.3 (High) reflects the significant potential for impact.

## Recommendation

*   Patch CVE-2026-14642 by upgrading SourceCodester Class and Exam Timetabling System to a version where this vulnerability has been fixed, if available, or applying vendor-supplied patches immediately.
*   Implement a Web Application Firewall (WAF) to detect and block malicious HTTP requests targeting `/edit_class2.php` with SQL injection payloads, as indicated by the Sigma rule below.
*   Deploy the Sigma rule titled "Detect CVE-2026-14642 Exploitation — SourceCodester SQL Injection" to your SIEM and tune for your environment, ensuring it triggers on requests to `/edit_class2.php` with suspicious `ID` parameters.
*   Review web server logs for `/edit_class2.php` access patterns, especially for `cs-uri-query` fields containing SQL injection artifacts, to identify potential exploitation attempts.
*   Implement strict input validation for all user-supplied input, especially for the `ID` parameter used in `/edit_class2.php`, to prevent SQL injection.
