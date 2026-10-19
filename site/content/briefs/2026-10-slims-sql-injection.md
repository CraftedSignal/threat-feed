---
title: SQL Injection Vulnerability in SENAYAN Library Management System
slug: 2026-10-slims-sql-injection
description: SENAYAN Library Management System (SLiMS) Bulian 9.8.0 contains an unauthenticated SQL injection vulnerability in the dl_detail.php script that allows for unauthorized database access.
date: "2026-10-19T22:24:08Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:slims:senayan_library_management_system:9.8.0:*:*:*:*:*:*:*
tags:
  - sql-injection
  - web-security
vendors:
  - SLiMS
products:
  - SENAYAN Library Management System (9.8.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: SLiMS Bulian 9.8.0 is vulnerable to SQL Injection in admin/modules/reporting/customs/dl_detail.php via the parameter fileID.
    confidence_band: high
cves:
  - id: CVE-2026-107083
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107083
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Identify and audit all SLiMS 9.8.0 installations in the environment.
      owner: IT Operations
      due: 24h
      evidence: Vulnerability confirmed in SLiMS 9.8.0
  mitigation_plan:
    - priority: immediate
      action: Apply security patches or restrict network access to the admin/modules/reporting/customs/ directory until a patch is applied.
      owner: IT Operations
      addresses: CVE-2026-107083
      evidence: Unauthenticated SQL injection in fileID parameter
---

The SENAYAN Library Management System (SLiMS) Bulian version 9.8.0 is susceptible to an unauthenticated SQL injection vulnerability identified as CVE-2026-107083. The vulnerability exists within the 'admin/modules/reporting/customs/dl_detail.php' script, where the 'fileID' parameter fails to properly sanitize user-supplied input before being included in a database query. This flaw allows an attacker to manipulate SQL queries, potentially resulting in the exfiltration of sensitive database content, modification of application data, or complete takeover of the underlying database backend. As this endpoint resides within the administrative reporting module, exploitation could allow attackers to bypass standard access controls to extract sensitive records, such as library patron information or system credentials.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated attacker to execute arbitrary SQL commands against the backend database. This can lead to full unauthorized access to all data stored within the SLiMS database, potential privilege escalation, and significant data loss. Given the nature of library management systems, this could compromise private data associated with library users and administrative staff.

## Recommendation

* Monitor web server logs for suspicious URL parameters containing SQL syntax or characters commonly associated with injection attacks (e.g., single quotes, comment indicators, or keywords like 'UNION', 'SELECT') directed at 'dl_detail.php'.
* Identify and patch instances of SLiMS Bulian 9.8.0 to a secure version once released by the maintainers.
* Implement Web Application Firewall (WAF) rules to inspect incoming requests to the 'admin/modules/reporting/customs/' path for common SQL injection patterns targeting the 'fileID' parameter.
