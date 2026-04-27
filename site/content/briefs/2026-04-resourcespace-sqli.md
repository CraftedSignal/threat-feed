---
title: ResourceSpace 8.6 SQL Injection Vulnerability (CVE-2019-25693)
slug: 2026-04-resourcespace-sqli
description: ResourceSpace 8.6 is vulnerable to SQL injection, allowing authenticated attackers to execute arbitrary SQL queries and extract sensitive data by injecting malicious code through the keywords parameter in collection_edit.php.
date: "2026-04-12T13:16:32Z"
severities:
  - high
tags:
  - sqli
  - cve-2019-25693
  - resourcespace
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2019-25693
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25693
  - https://www.exploit-db.com/exploits/46274
  - https://www.vulncheck.com/advisories/resourcespace-sql-injection-via-collection-edit-php
rules:
  - title: Detect ResourceSpace SQL Injection Attempt
    description: Detects potential SQL injection attempts against the ResourceSpace application by monitoring POST requests to collection_edit.php with SQL keywords in the keywords parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect ResourceSpace SQL Injection via Error Messages
    description: Detects potential SQL injection exploitation by identifying error messages in web server logs associated with collection_edit.php.
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

ResourceSpace 8.6 is susceptible to an SQL injection vulnerability (CVE-2019-25693) that can be exploited by authenticated attackers. The vulnerability resides in the `collection_edit.php` script, specifically within the handling of the `keywords` parameter. By crafting malicious SQL payloads within a POST request to this script, an attacker can inject arbitrary SQL queries into the application's database interactions. Successful exploitation enables the attacker to extract sensitive…
