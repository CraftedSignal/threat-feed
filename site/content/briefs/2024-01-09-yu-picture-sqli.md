---
title: liyupi yu-picture SQL Injection Vulnerability (CVE-2026-7060)
slug: 2024-01-09-yu-picture-sqli
description: A SQL injection vulnerability (CVE-2026-7060) exists in liyupi yu-picture versions up to a053632c41340152bf75b66b3c543d129123d8ec, allowing a remote attacker to execute arbitrary SQL commands by manipulating the sortField argument in the PageRequest function of PictureServiceImpl.java.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - cve-2026-7060
  - web-application
vendors:
  - liyupi
products:
  - yu-picture
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7060
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7060
rules:
  - title: Detect Malicious SortField SQL Injection
    description: Detects potential SQL injection attempts in the sortField parameter of web requests based on common SQL injection payloads.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect MyBatis-Plus SQL Injection via sortField
    description: Detects SQL injection attempts specifically targeting the sortField parameter used in MyBatis-Plus applications.
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

A SQL injection vulnerability has been identified in liyupi yu-picture, a web application, affecting versions up to commit a053632c41340152bf75b66b3c543d129123d8ec. The vulnerability, tracked as CVE-2026-7060, resides in the PageRequest function within the PictureServiceImpl.java file, specifically related to the MyBatis-Plus component. An attacker can exploit this vulnerability remotely by manipulating the `sortField` argument. Public exploitation details are available, increasing the risk. Given the lack of versioning in the product, determining affected and unaffected releases is challenging, emphasizing the need for immediate patching.

## Attack Chain

1.  The attacker identifies an endpoint that utilizes the vulnerable `PageRequest` function in `PictureServiceImpl.java`.
2.  The attacker crafts a malicious HTTP request targeting the vulnerable endpoint.
3.  The attacker injects a SQL payload into the `sortField` parameter of the `PageRequest` function.
4.  The application processes the crafted request, passing the malicious SQL payload to the MyBatis-Plus component.
5.  MyBatis-Plus executes the injected SQL query against the application's database.
6.  The database executes the injected SQL, potentially allowing the attacker to read, modify, or delete data.
7.  The attacker retrieves sensitive information from the database, such as user credentials or configuration details.
8.  The attacker uses the compromised data to further compromise the application or gain access to the underlying system.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2026-7060) can lead to unauthorized data access, modification, or deletion, potentially resulting in complete compromise of the application and its underlying database. The absence of versioning makes identifying vulnerable installations difficult. Given the publicly available exploit, affected organizations are at increased risk of attack.

## Recommendation

*   Apply the patch or update the liyupi yu-picture application to a version containing the fix for CVE-2026-7060 as soon as it becomes available.
*   Implement input validation and sanitization on the `sortField` parameter within the `PageRequest` function to prevent SQL injection.
*   Deploy the Sigma rule `Detect Malicious SortField SQL Injection` to identify attempts to exploit this vulnerability in web server logs.
*   Monitor web server logs for suspicious activity targeting endpoints that use the `PageRequest` function.
