---
title: Digiwin EasyFlow .NET SQL Injection Vulnerability (CVE-2026-5963)
slug: 2026-04-digiwin-easyflow-sqli
description: Digiwin EasyFlow .NET is vulnerable to SQL Injection, allowing unauthenticated remote attackers to inject arbitrary SQL commands to read, modify, and delete database contents.
date: "2026-04-20T08:16:10Z"
severities:
  - critical
tags:
  - sql-injection
  - cve-2026-5963
  - easyflow
  - digiwin
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5963
  - https://www.twcert.org.tw/en/cp-139-10832-05f3a-2.html
  - https://www.twcert.org.tw/tw/cp-132-10831-a734d-1.html
rules:
  - title: Detect Suspicious SQL Injection Attempts in Web Logs
    description: Detects potential SQL injection attempts by looking for common SQL keywords in web server logs. Tune the rule to your environment to reduce false positives.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1595.002
    data_sources:
      - webserver
      - windows
  - title: Detect Suspicious SQL Injection Attempts in Web Logs POST
    description: Detects potential SQL injection attempts by looking for common SQL keywords in web server logs using POST requests. Tune the rule to your environment to reduce false positives.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1595.002
    data_sources:
      - webserver
      - windows
rules_count: 2
---

Digiwin EasyFlow .NET is susceptible to a critical SQL Injection vulnerability (CVE-2026-5963). This flaw allows unauthenticated remote attackers to inject arbitrary SQL commands directly into the application's database queries. The vulnerability allows attackers to read, modify, or delete sensitive data within the EasyFlow .NET database, potentially leading to complete compromise of the application and its underlying data. Given the nature of SQL injection, this vulnerability could be…
