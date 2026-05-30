---
title: eNdonesia Portal 8.7 SQL Injection Vulnerabilities
slug: 2026-05-endonesia-sqli
description: eNdonesia Portal 8.7 contains multiple SQL injection vulnerabilities allowing unauthenticated attackers to execute arbitrary SQL queries via crafted parameters in mod.php.
date: "2026-05-30T16:18:28Z"
type: threat
types:
  - threat
severities:
  - critical
tags:
  - sql-injection
  - web-application
vendors:
  - eNdonesia
products:
  - Portal
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2018-25407
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25407
  - CVE-2018-25407
rules:
  - title: Detects CVE-2018-25407 Exploitation Attempt — SQL Injection in eNdonesia Portal mod.php
    description: Detects CVE-2018-25407 exploitation attempt — SQL injection attempts targeting the artid, cid, did, contid, and aboutid parameters in mod.php of eNdonesia Portal.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2018-25407 Exploitation Attempt - SQL Error Responses
    description: Detects potential CVE-2018-25407 exploitation attempts by monitoring server error responses related to SQL queries in mod.php.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

eNdonesia Portal version 8.7 is susceptible to SQL injection vulnerabilities that can be exploited by unauthenticated attackers. These vulnerabilities exist within the `mod.php` file, where insufficient input validation allows attackers to inject malicious SQL code through various parameters. Specifically, the `artid`, `cid`, `did`, `contid`, and `aboutid` parameters within the `publisher`, `diskusi`, `galeri`, `content`, and `about` modules are vulnerable. Successful exploitation allows attackers to execute arbitrary SQL queries, potentially leading to the extraction of sensitive database information, including usernames, database names, and version details. This vulnerability poses a significant risk to organizations using the affected portal, as it could lead to unauthorized access and data breaches.

## Attack Chain

1. An unauthenticated attacker identifies the vulnerable eNdonesia Portal 8.7 instance.
2. The attacker crafts a malicious HTTP request targeting the `mod.php` file.
3. The attacker injects SQL code into one or more of the vulnerable parameters: `artid`, `cid`, `did`, `contid`, or `aboutid`.
4. The crafted request is sent to the web server hosting the eNdonesia Portal.
5. The web server processes the request without proper sanitization of the injected SQL code.
6. The injected SQL code is executed against the database.
7. The attacker retrieves sensitive information, such as usernames, database names, or version details, from the database.
8. The attacker may further exploit the compromised database for lateral movement or data exfiltration.

## Impact

Successful exploitation of these SQL injection vulnerabilities allows attackers to extract sensitive information, potentially leading to unauthorized access, data breaches, and further compromise of the affected system. There is no information available regarding the number of victims or sectors targeted. The impact is severe, as it allows unauthenticated attackers to directly query the database.

## Recommendation

*   Apply available patches or upgrades to eNdonesia Portal to version later than 8.7 to remediate CVE-2018-25407.
*   Deploy the Sigma rules provided to detect potential exploitation attempts against the vulnerable parameters (`artid`, `cid`, `did`, `contid`, `aboutid`) in `mod.php`.
*   Implement input validation and sanitization on all user-supplied data, especially within the `mod.php` file to prevent future SQL injection attacks.
