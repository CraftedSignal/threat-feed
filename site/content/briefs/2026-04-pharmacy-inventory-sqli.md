---
title: SourceCodester Pharmacy Sales and Inventory System SQL Injection Vulnerability (CVE-2026-7199)
slug: 2026-04-pharmacy-inventory-sqli
description: A SQL injection vulnerability (CVE-2026-7199) exists in SourceCodester Pharmacy Sales and Inventory System 1.0, allowing remote attackers to execute arbitrary SQL commands by manipulating the 'ID' parameter in the `/ajax.php?action=delete_product` endpoint, potentially leading to data breach or system compromise.
date: "2026-04-28T00:16:26Z"
severities:
  - high
tags:
  - sql-injection
  - cve-2026-7199
  - web-application
vendors:
  - SourceCodester
products:
  - Pharmacy Sales and Inventory System 1.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7199
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7199
  - https://github.com/3436567162/vlun/issues/2
  - https://vuldb.com/submit/801109
  - https://vuldb.com/vuln/359800
  - https://vuldb.com/vuln/359800/cti
  - https://www.sourcecodester.com/
rules:
  - title: Detecting SQL Injection Attempts via URI
    description: Detects potential SQL injection attempts by identifying requests containing common SQL injection payloads in the URI.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detecting SQL Injection in Pharmacy System
    description: Detects SQL injection attempts targeting the /ajax.php?action=delete_product endpoint.
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

A SQL injection vulnerability has been identified in SourceCodester Pharmacy Sales and Inventory System version 1.0. This vulnerability, assigned CVE-2026-7199, affects the `/ajax.php?action=delete_product` endpoint. Attackers can remotely exploit this vulnerability by manipulating the `ID` parameter. The vulnerability was published on April 27, 2026, and the exploit is now publicly available. Successful exploitation allows attackers to execute arbitrary SQL commands, potentially leading to…
