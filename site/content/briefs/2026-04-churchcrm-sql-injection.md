---
title: ChurchCRM Time-Based Blind SQL Injection Vulnerability (CVE-2026-34402)
slug: 2026-04-churchcrm-sql-injection
description: CVE-2026-34402 is a time-based blind SQL injection vulnerability in ChurchCRM versions prior to 7.1.0. Authenticated users with Edit Records or Manage Groups permissions can exploit the PropertyAssign.php endpoint to exfiltrate or modify database content, including user credentials, PII, and configuration secrets.
date: "2026-04-06T16:16:35Z"
severities:
  - high
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

ChurchCRM is an open-source church management system. Prior to version 7.1.0, the application suffers from a time-based blind SQL injection vulnerability (CVE-2026-34402). Authenticated users with either "Edit Records" or "Manage Groups" permissions can exploit this flaw. Successful exploitation allows attackers to exfiltrate or modify any database content, which could include user credentials, personally identifiable information (PII), and configuration secrets. The vulnerable endpoint is…
