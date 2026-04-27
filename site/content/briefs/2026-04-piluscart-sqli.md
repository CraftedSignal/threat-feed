---
title: PilusCart 1.4.1 SQL Injection Vulnerability
slug: 2026-04-piluscart-sqli
description: PilusCart 1.4.1 is vulnerable to SQL injection, allowing unauthenticated attackers to manipulate database queries by injecting SQL code through the 'send' parameter to extract sensitive database information.
date: "2026-04-05T21:16:44Z"
severities:
  - high
tags:
  - sqli
  - vulnerability
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2019-25672
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25672
  - https://sourceforge.net/projects/pilus/
  - https://www.exploit-db.com/exploits/46368
  - https://www.vulncheck.com/advisories/piluscart-sql-injection-via-send-parameter
rules:
  - title: Detect PilusCart SQL Injection Attempt via Send Parameter
    description: Detects potential SQL injection attempts in PilusCart 1.4.1 via the 'send' parameter in POST requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect PilusCart Exploitation Attempts via Exploit-DB Payload
    description: Detects potential exploitation attempts against PilusCart by identifying specific payloads found in Exploit-DB.
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

PilusCart 1.4.1 is susceptible to a SQL injection vulnerability (CVE-2019-25672) that allows unauthenticated attackers to inject malicious SQL code via the 'send' parameter. This vulnerability enables attackers to manipulate database queries, potentially leading to the extraction of sensitive information. The attack involves crafting malicious POST requests to the comment submission endpoint using RLIKE-based boolean SQL injection techniques. Successful exploitation grants attackers…
