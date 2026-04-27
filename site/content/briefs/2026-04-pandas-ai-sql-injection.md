---
title: pandas-ai SQL Injection Vulnerability (CVE-2026-30273)
slug: 2026-04-pandas-ai-sql-injection
description: pandas-ai v3.0.0 is vulnerable to SQL injection via the pandasai.agent.base._execute_sql_query component, potentially allowing unauthorized database access and modification.
date: "2026-04-01T17:28:38Z"
severities:
  - high
tags:
  - sql-injection
  - vulnerability
  - pandas-ai
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
cves:
  - id: CVE-2026-30273
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-30273
  - https://github.com/sinaptik-ai/pandas-ai
  - https://gist.github.com/CafeD1/21c32edbf1b63fd88a79c290ed2a8059
rules:
  - title: Detecting Potential PandasAI SQL Injection Attempts
    description: Detects potential SQL injection attempts targeting the pandas-ai application by looking for common SQL injection syntax in HTTP requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detecting PandasAI SQL Injection via Error Messages
    description: Detects potential SQL injection attempts by identifying SQL error messages in web server responses after requests to the pandas-ai application.
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

pandas-ai v3.0.0 contains a SQL injection vulnerability in the `pandasai.agent.base._execute_sql_query` component. This flaw, identified as CVE-2026-30273, could allow an attacker to inject malicious SQL code into queries executed by the application. Successful exploitation can lead to unauthorized data access, modification, or deletion within the underlying database. Given the nature of pandas-ai as a tool intended to work with data, this vulnerability poses a significant risk to data…
