---
title: SourceCodester SUP Online Shopping 1.0 SQL Injection Vulnerability
slug: 2026-05-sup-online-shopping-sqli
description: SourceCodester SUP Online Shopping 1.0 is vulnerable to SQL injection via the msgid parameter in /admin/replymsg.php, allowing remote attackers to execute arbitrary SQL commands.
date: "2026-05-08T04:16:24Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sqli
  - cve-2026-8131
  - web-application
vendors:
  - SourceCodester
products:
  - SUP Online Shopping 1.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-8131
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-8131
  - https://github.com/redshadowword-cell/CVE/issues/12
  - https://vuldb.com/vuln/361921
rules:
  - title: Detect SQL Injection Attempt via msgid Parameter
    description: Detects CVE-2026-8131 exploitation — SQL injection attempts via the msgid parameter in /admin/replymsg.php
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect SQL Injection Error Messages
    description: Detects potential SQL injection attempts by identifying common database error messages in the server response.
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

SourceCodester SUP Online Shopping 1.0 is vulnerable to SQL injection in the /admin/replymsg.php file. The vulnerability is triggered by manipulating the `msgid` argument, allowing remote attackers to inject and execute arbitrary SQL commands. This vulnerability, identified as CVE-2026-8131, has a CVSS v3.1 score of 7.3, indicating a high severity. Public exploits are available, increasing the risk of exploitation. Successful exploitation could allow attackers to read, modify, or delete sensitive data, potentially leading to full database compromise.

## Attack Chain

1.  Attacker identifies the vulnerable endpoint: `/admin/replymsg.php`.
2.  Attacker crafts a malicious HTTP GET or POST request targeting `/admin/replymsg.php`.
3.  The malicious request includes the `msgid` parameter with a crafted SQL injection payload.
4.  The application fails to properly sanitize the `msgid` input.
5.  The unsanitized input is directly incorporated into an SQL query.
6.  The injected SQL code is executed against the database.
7.  Attacker retrieves sensitive information or modifies database entries.

## Impact

Successful exploitation of this SQL injection vulnerability (CVE-2026-8131) can lead to unauthorized access to sensitive data, modification of existing records, or complete database compromise. The impact includes potential data breaches, financial losses, and reputational damage for organizations using the vulnerable SourceCodester SUP Online Shopping 1.0. Given the availability of public exploits, the risk of widespread exploitation is elevated.

## Recommendation

*   Apply appropriate input validation and sanitization to the `msgid` parameter in `/admin/replymsg.php` to prevent SQL injection, mitigating CVE-2026-8131.
*   Deploy the Sigma rule `Detect SQL Injection Attempt via msgid Parameter` to identify and block malicious requests targeting the vulnerable endpoint.
*   Upgrade to a patched version of SourceCodester SUP Online Shopping that addresses the SQL injection vulnerability.
