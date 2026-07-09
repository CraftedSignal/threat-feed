---
title: 'CVE-2026-15137: Remote SQL Injection in code-projects Interview Management System'
slug: 2026-07-interview-management-sql-injection
description: A critical SQL injection vulnerability (CVE-2026-15137) has been identified in code-projects Interview Management System version 1.0, allowing remote unauthenticated attackers to manipulate the 'ID' argument in the '/inc/classes/View.php' file, leading to arbitrary SQL query execution and potential data compromise; a public exploit is available.
date: "2026-07-09T00:28:02Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - sql-injection
  - webserver
  - vulnerability
  - cve
  - code-projects
  - interview-management-system
vendors:
  - code-projects
products:
  - Interview Management System 1.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A weakness has been identified in code-projects Interview Management System 1.0. This vulnerability ... The attack can be initiated remotely. The exploit has been made available to the public and could be used for attacks.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1213
    technique_name: Data from Information Repositories
    evidence: This manipulation of the argument ID causes sql injection.
    confidence_band: high
cves:
  - id: CVE-2026-15137
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15137
  - https://code-projects.org/
  - https://github.com/susususua-AI/CVE/issues/2
  - https://vuldb.com/cve/CVE-2026-15137
  - https://vuldb.com/submit/851066
  - https://vuldb.com/vuln/376952
  - https://vuldb.com/vuln/376952/cti
iocs:
  - type: url
    value: https://code-projects.org/
  - type: url
    value: https://github.com/susususua-AI/CVE/issues/2
  - type: url
    value: https://vuldb.com/cve/CVE-2026-15137
  - type: url
    value: https://vuldb.com/submit/851066
  - type: url
    value: https://vuldb.com/vuln/376952
  - type: url
    value: https://vuldb.com/vuln/376952/cti
ioc_counts:
  url: 6
rules:
  - title: 'CVE-2026-15137: SQL Injection Attempt in Interview Management System'
    description: Detects CVE-2026-15137 exploitation attempts by identifying common SQL injection payloads within the 'ID' parameter targeting the '/inc/classes/View.php' endpoint of code-projects Interview Management System 1.0.
    platform: sigma
    severity: high
    tactics:
      - collection
      - initial_access
    techniques:
      - T1190
      - T1213
    data_sources:
      - webserver
rules_count: 1
---

A critical SQL injection vulnerability, tracked as CVE-2026-15137, has been identified in version 1.0 of code-projects Interview Management System. The flaw resides within the `\inc\classes\View.php` file, specifically in the handling of the `ID` argument. Attackers can remotely exploit this weakness by manipulating the `ID` parameter in HTTP requests, leading to SQL injection. This allows unauthorized access to or manipulation of the underlying database. The vulnerability has been publicly disclosed, and a proof-of-concept exploit is available, increasing the likelihood of active exploitation. Defenders should prioritize patching or mitigating this vulnerability immediately to prevent potential data breaches, unauthorized data modification, or further system compromise by remote attackers leveraging the public exploit.

## Attack Chain

1. A remote, unauthenticated attacker sends a specially crafted HTTP GET or POST request to the vulnerable `code-projects Interview Management System 1.0` web application.
2. The request targets the `/inc/classes/View.php` endpoint, including a malicious SQL payload within the `ID` parameter in the URL query string or request body.
3. The vulnerable application processes the `ID` argument without proper input sanitization, leading to the execution of the attacker's arbitrary SQL queries against the backend database.
4. Successful exploitation results in the attacker being able to read sensitive data, modify database records, or potentially gain further access to the system via database-specific functions or escalated privileges.

## Impact

Successful exploitation of CVE-2026-15137 allows unauthenticated remote attackers to perform arbitrary SQL queries against the application's database. This can lead to unauthorized access to sensitive information stored within the Interview Management System, such as applicant details, interview schedules, or system configurations. Attackers could also tamper with data, modify application behavior, or potentially achieve remote code execution depending on the database's privileges and underlying operating system configuration. The public availability of an exploit increases the risk of widespread attacks targeting unpatched systems, potentially resulting in data breaches and operational disruption.

## Recommendation

* Immediately update `code-projects Interview Management System 1.0` to a patched version if available, or apply vendor-provided mitigations for CVE-2026-15137.
* Deploy the provided Sigma rule (`CVE-2026-15137: SQL Injection Attempt in Interview Management System`) to your SIEM/detection platform and monitor for suspicious web requests containing SQL injection payloads targeting the `/inc/classes/View.php` endpoint.
* Ensure comprehensive web server logging is enabled and configured to capture full HTTP request details, including URL paths and query parameters, to facilitate detection and investigation of web-based attacks.
