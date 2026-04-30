---
title: ChurchCRM Time-Based Blind SQL Injection Vulnerability (CVE-2026-34402)
slug: 2026-04-churchcrm-sql-injection
description: CVE-2026-34402 is a time-based blind SQL injection vulnerability in ChurchCRM versions prior to 7.1.0. Authenticated users with Edit Records or Manage Groups permissions can exploit the PropertyAssign.php endpoint to exfiltrate or modify database content, including user credentials, PII, and configuration secrets.
date: "2026-04-06T16:16:35Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - sqlinjection
  - cve-2026-34402
  - churchcrm
  - webserver
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-34402
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34402
  - https://github.com/ChurchCRM/CRM/security/advisories/GHSA-r57q-r5v3-v5h8
rules:
  - title: Detect SQL Injection Attempts in ChurchCRM PropertyAssign.php
    description: Detects potential SQL injection attempts targeting the PropertyAssign.php endpoint in ChurchCRM by looking for common SQL injection payloads.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Potential ChurchCRM SQL Injection via Error Messages
    description: Detects potential SQL injection attempts targeting ChurchCRM based on common database error messages in the web server response.
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

ChurchCRM is an open-source church management system. Prior to version 7.1.0, the application suffers from a time-based blind SQL injection vulnerability (CVE-2026-34402). Authenticated users with either "Edit Records" or "Manage Groups" permissions can exploit this flaw. Successful exploitation allows attackers to exfiltrate or modify any database content, which could include user credentials, personally identifiable information (PII), and configuration secrets. The vulnerable endpoint is `PropertyAssign.php`. This vulnerability was addressed and fixed in version 7.1.0 of ChurchCRM. Defenders should prioritize patching vulnerable instances to prevent unauthorized access and data breaches.

## Attack Chain

1. An attacker gains valid credentials for ChurchCRM, with "Edit Records" or "Manage Groups" permissions. This could be achieved through credential stuffing, password reuse, or other means.
2. The attacker crafts a malicious HTTP request targeting the `PropertyAssign.php` endpoint. This request contains a SQL injection payload within a parameter processed by the application.
3. The application processes the malicious SQL query, injecting it into the database query without proper sanitization.
4. Due to the blind nature of the SQL injection, the attacker uses time-based techniques (e.g., `SLEEP()`) to infer information about the database structure and content.
5. The attacker iterates through various SQL injection payloads, slowly extracting sensitive data such as usernames, password hashes, and other PII.
6. The attacker may modify database records to escalate privileges, create new administrative accounts, or sabotage the application's functionality.
7. The attacker exfiltrates the stolen data.
8. The final objective is to compromise the confidentiality, integrity, and availability of the ChurchCRM database, potentially leading to significant data breaches and reputational damage.

## Impact

Successful exploitation of CVE-2026-34402 can have serious consequences. An attacker can gain unauthorized access to sensitive data stored within the ChurchCRM database. This includes user credentials, PII, and configuration secrets. The attacker can also modify database records, potentially disrupting church operations or causing financial harm. Given the sensitive nature of the data often stored in church management systems, the impact of this vulnerability could be substantial. The vulnerability affects ChurchCRM installations prior to version 7.1.0.

## Recommendation

*   Upgrade ChurchCRM installations to version 7.1.0 or later to remediate CVE-2026-34402.
*   Deploy the Sigma rule detecting requests to PropertyAssign.php with sleep commands to your SIEM and tune for your environment.
*   Monitor web server logs for suspicious activity targeting the `PropertyAssign.php` endpoint.
*   Implement web application firewall (WAF) rules to block SQL injection attempts.
*   Review user access controls within ChurchCRM to ensure that only authorized personnel have "Edit Records" or "Manage Groups" permissions.
