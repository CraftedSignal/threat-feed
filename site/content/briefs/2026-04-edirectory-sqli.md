---
title: eDirectory SQL Injection Vulnerability (CVE-2019-25675)
slug: 2026-04-edirectory-sqli
description: Unauthenticated attackers can exploit SQL injection vulnerabilities in eDirectory (CVE-2019-25675) to bypass administrator authentication and disclose sensitive files.
date: "2026-04-05T21:16:45Z"
severities:
  - critical
tags:
  - sqli
  - edirectory
  - cve-2019-25675
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
cves:
  - id: CVE-2019-25675
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25675
  - https://www.edirectory.com/
  - https://www.exploit-db.com/exploits/46423
  - https://www.vulncheck.com/advisories/edirectory-all-versions-sql-injection-authentication-bypass
rules:
  - title: Detect eDirectory language_file.php File Disclosure
    description: Detects attempts to exploit the file disclosure vulnerability in language_file.php by looking for requests with specific parameters.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1580
    data_sources:
      - webserver
      - linux
  - title: Detect eDirectory SQL Injection Attempt
    description: Detects potential SQL injection attempts against the eDirectory login endpoint by looking for common SQL injection keywords in the key parameter.
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

CVE-2019-25675 describes multiple SQL injection vulnerabilities affecting eDirectory. An unauthenticated attacker can exploit these vulnerabilities to bypass administrator authentication and disclose sensitive files. The vulnerability lies in the `key` parameter of the login endpoint. By injecting SQL code, specifically a UNION-based SQL injection, an attacker can authenticate as an administrator. After successful authentication, the attacker can then exploit file disclosure vulnerabilities in…
