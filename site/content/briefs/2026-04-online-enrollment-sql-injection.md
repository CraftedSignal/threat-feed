---
title: SQL Injection Vulnerability in itsourcecode Online Enrollment System 1.0
slug: 2026-04-online-enrollment-sql-injection
description: A SQL injection vulnerability exists in itsourcecode Online Enrollment System 1.0 within the Parameter Handler component at /enrollment/index.php, where manipulating the deptid argument can lead to remote code execution, with public exploits available.
date: "2026-04-02T14:16:37Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - sql-injection
  - web-application
  - cve-2026-5334
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5334
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5334
  - https://github.com/yuji0903/silver-guide/issues/15
  - https://itsourcecode.com/
  - https://vuldb.com/vuln/354668
rules:
  - title: Detect SQL Injection Attempt via deptid Parameter
    description: Detects potential SQL injection attempts targeting the deptid parameter in the /enrollment/index.php endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Request to Vulnerable Enrollment Endpoint
    description: Detects requests to the vulnerable endpoint /enrollment/index.php?view=edit&id=3 which may be an attempt to exploit CVE-2026-5334
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A SQL injection vulnerability has been identified in itsourcecode Online Enrollment System version 1.0. The vulnerability resides within the Parameter Handler component of the application, specifically affecting the `/enrollment/index.php` endpoint. By manipulating the `deptid` argument, a remote attacker can inject malicious SQL queries, potentially leading to unauthorized data access, modification, or even remote code execution. This vulnerability is particularly concerning because a public exploit is available, increasing the likelihood of active exploitation. Defenders should prioritize patching or mitigating this vulnerability to prevent potential compromise of their systems. The scope of impact includes any system running the vulnerable version of itsourcecode Online Enrollment System.

## Attack Chain

1.  The attacker identifies a vulnerable instance of itsourcecode Online Enrollment System 1.0.
2.  The attacker crafts a malicious HTTP request targeting `/enrollment/index.php?view=edit&id=3`.
3.  The attacker injects SQL code into the `deptid` parameter of the HTTP request.
4.  The web server processes the request and passes the tainted `deptid` parameter to the SQL query.
5.  The injected SQL code is executed against the database, allowing the attacker to bypass authentication or access sensitive data.
6.  The attacker may escalate the attack by attempting to execute arbitrary commands on the server.
7.  Successful exploitation allows the attacker to dump database contents, modify enrollment records, or gain administrative access.

## Impact

Successful exploitation of this SQL injection vulnerability could lead to complete compromise of the Online Enrollment System. This includes unauthorized access to sensitive student data, modification of enrollment records, and potentially remote code execution on the server. Given that a public exploit exists, organizations using the vulnerable software are at high risk of experiencing data breaches, financial losses, and reputational damage. The potential victim count depends on the number of installations of the affected Online Enrollment System.

## Recommendation

*   Inspect web server logs for suspicious POST requests to `/enrollment/index.php` containing potentially malicious SQL syntax within the `deptid` parameter to identify potential exploitation attempts.
*   Deploy the Sigma rule `Detect SQL Injection Attempt via deptid Parameter` to detect exploitation attempts targeting the vulnerable endpoint.
*   Block requests to `/enrollment/index.php?view=edit&id=3` containing SQL keywords in the `deptid` parameter at the WAF or reverse proxy.
*   Apply input validation and sanitization to the `deptid` parameter within the application code to prevent SQL injection attacks in the future.
