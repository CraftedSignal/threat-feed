---
title: Dolibarr ERP-CRM 8.0.4 SQL Injection Vulnerability
slug: 2026-04-dolibarr-sqli
description: Dolibarr ERP-CRM 8.0.4 is vulnerable to SQL injection via the rowid parameter in the admin dict.php endpoint, allowing attackers to execute arbitrary SQL queries and extract sensitive database information.
date: "2026-04-12T13:16:34Z"
severities:
  - high
tags:
  - sqli
  - cve-2019-25710
  - dolibarr
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2019-25710
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25710
  - https://www.vulncheck.com/advisories/dolibarr-erp-crm-sql-injection-via-rowid-parameter
  - https://www.exploit-db.com/exploits/46095
rules:
  - title: Detect Suspicious Dolibarr rowid Parameter SQL Injection Attempt
    description: Detects potential SQL injection attempts targeting the rowid parameter in the Dolibarr admin/dict.php endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Dolibarr admin/dict.php Access
    description: Detects access to the Dolibarr admin/dict.php endpoint. This can be used to monitor for potential reconnaissance or exploitation attempts.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Dolibarr ERP-CRM is a popular open-source enterprise resource planning and customer relationship management software. Version 8.0.4 of Dolibarr is susceptible to a critical SQL injection vulnerability (CVE-2019-25710) affecting the `rowid` parameter in the `admin dict.php` endpoint. This flaw allows unauthenticated attackers to inject malicious SQL code through the `rowid` POST parameter. Successful exploitation enables attackers to execute arbitrary SQL queries against the Dolibarr database…
