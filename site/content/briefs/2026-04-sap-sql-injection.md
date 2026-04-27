---
title: Critical SQL Injection Vulnerability in SAP Products (CVE-2026-27681)
slug: 2026-04-sap-sql-injection
description: A critical SQL injection vulnerability, CVE-2026-27681, affects SAP Business Planning and Consolidation (BPC) and SAP Business Warehouse (BW), potentially allowing attackers to execute arbitrary SQL commands and fully compromise affected systems.
date: "2026-04-15T12:00:00Z"
severities:
  - critical
tags:
  - sap
  - sql-injection
  - cve-2026-27681
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-27681
    cvss: 9.9
  - id: CVE-2026-34256
    cvss: 7.1
    epss: 0.00036
  - id: CVE-2025-64775
    cvss: 7.5
    epss: 0.00193
  - id: CVE-2026-27674
    cvss: 6.1
    epss: 0.00054
  - id: CVE-2026-0512
    cvss: 6.1
    epss: 0.00069
references:
  - https://ccb.belgium.be/advisories/warning-critical-sql-injection-vulnerability-sap-products-cve-2026-27681-patch
  - https://nvd.nist.gov/vuln/detail/CVE-2026-27681
  - https://support.sap.com/en/my-support/knowledge-base/security-notes-news/april-2026.html
  - https://me.sap.com/notes/3719353
rules:
  - title: Generic SQL Injection Attempt - URI Query
    description: Detects potential SQL injection attempts in URI queries based on common SQL keywords.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Generic SQL Injection Attempt - POST Body
    description: Detects potential SQL injection attempts in HTTP POST requests based on common SQL keywords.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

On April 14, 2026, SAP released security patches addressing multiple vulnerabilities in its products, including a critical SQL injection vulnerability identified as CVE-2026-27681. This vulnerability affects SAP Business Planning and Consolidation (BPC) and SAP Business Warehouse (BW). The flaw stems from insufficient authorization checks, allowing a low-privilege authenticated user to execute arbitrary SQL commands. Successful exploitation could lead to unauthorized access to sensitive…
