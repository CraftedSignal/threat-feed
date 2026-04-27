---
title: PraisonAI SQL Injection Vulnerability (CVE-2026-34934)
slug: 2026-04-praisonai-sqli
description: A SQL Injection vulnerability exists in PraisonAI versions prior to 4.5.90, where an attacker can inject malicious SQL code via thread IDs, leading to arbitrary code execution and full database access.
date: "2026-04-04T12:00:00Z"
severities:
  - critical
tags:
  - cve-2026-34934
  - sql-injection
  - praisonai
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-34934
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34934
  - https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-9cq8-3v94-434g
rules:
  - title: Detect SQL Injection Attempts via User Agent
    description: Detects potential SQL injection attempts in HTTP requests by analyzing the User-Agent header for common SQL keywords.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect SQL Injection in HTTP Query Parameters
    description: Detects potential SQL injection attempts in HTTP requests by analyzing the query parameters for common SQL keywords.
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

PraisonAI, a multi-agent teams system, is vulnerable to SQL Injection in versions prior to 4.5.90 (CVE-2026-34934). The vulnerability lies within the `get_all_user_threads` function, which constructs raw SQL queries using f-strings with unescaped thread IDs fetched directly from the database. This allows an attacker to inject malicious code into the thread ID via the `update_thread` function. When the application subsequently loads the thread list, the injected SQL payload executes, potentially…
