---
title: Kados R10 GreenBee SQL Injection Vulnerability (CVE-2019-25704)
slug: 2026-04-kados-sql-injection
description: Kados R10 GreenBee is vulnerable to SQL injection (CVE-2019-25704), allowing attackers to manipulate database queries via the filter_user_mail parameter, potentially leading to data extraction or modification.
date: "2026-04-05T21:16:48Z"
severities:
  - high
tags:
  - sql-injection
  - cve-2019-25704
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2019-25704
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25704
  - https://www.exploit-db.com/exploits/46505
rules:
  - title: Detect SQL Injection Attempts via filter_user_mail Parameter
    description: Detects potential SQL injection attempts targeting the filter_user_mail parameter in web server logs.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1595.002
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection Error Messages
    description: Detects common SQL error messages in web server logs, which may indicate a successful or attempted SQL injection attack.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1595.002
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Kados R10 GreenBee is susceptible to SQL injection attacks due to improper input validation. Specifically, the `filter_user_mail` parameter does not adequately sanitize user-supplied input, which enables attackers to inject arbitrary SQL code into database queries. Publicly disclosed as CVE-2019-25704, successful exploitation of this vulnerability can result in the unauthorized disclosure of sensitive information, modification of existing data, or potentially complete compromise of the…
