---
title: OpenCart Core SQL Injection Vulnerability (CVE-2024-58341)
slug: 2026-03-opencart-sqli
description: OpenCart Core 4.0.2.3 is vulnerable to SQL injection via the 'search' parameter, enabling unauthenticated attackers to manipulate database queries and extract sensitive information through boolean-based or time-based blind SQL injection.
date: "2026-03-25T16:16:07Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve-2024-58341
  - sql-injection
  - opencart
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2024-58341
  - https://github.com/opencart/opencart/releases
  - https://www.exploit-db.com/exploits/51940
  - https://www.opencart.com/
  - https://www.vulncheck.com/advisories/opencart-core-sql-injection-via-search-parameter
rules:
  - title: OpenCart SQL Injection Attempt via Search Parameter
    description: Detects potential SQL injection attempts in the OpenCart 'search' parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: OpenCart SQL Injection - Time Based Blind SQLi
    description: Detects potential Time Based Blind SQL injection attempts in the OpenCart 'search' parameter by looking for SLEEP function calls.
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

OpenCart Core 4.0.2.3 is susceptible to a SQL injection vulnerability that allows unauthenticated remote attackers to inject arbitrary SQL commands through the 'search' parameter. The vulnerability, identified as CVE-2024-58341, allows attackers to craft malicious GET requests to the product search endpoint, potentially leading to the extraction of sensitive database information. The attack relies on the injection of SQL code within the 'search' parameter, exploiting the lack of proper input…
