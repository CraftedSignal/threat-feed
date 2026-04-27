---
title: PowerJob SQL Injection Vulnerability (CVE-2026-5736)
slug: 2026-04-powerjob-sqli
description: A remote SQL injection vulnerability, CVE-2026-5736, exists in PowerJob versions 5.1.0 through 5.1.2 within the detailPlus Endpoint, potentially allowing unauthenticated attackers to execute arbitrary SQL queries.
date: "2026-04-07T19:16:48Z"
severities:
  - high
tags:
  - sql-injection
  - vulnerability
  - powerjob
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5736
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5736
  - https://github.com/PowerJob/PowerJob/
  - https://github.com/PowerJob/PowerJob/issues/1167
rules:
  - title: Detect Suspicious PowerJob customQuery Parameter
    description: Detects suspicious requests to the /detailPlus endpoint in PowerJob with potentially malicious SQL injection payloads in the customQuery parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: PowerJob detailPlus Endpoint Access
    description: Detects access to the PowerJob detailPlus endpoint, which may indicate vulnerability scanning or exploitation attempts.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-5736 is a SQL injection vulnerability affecting PowerJob, an open-source distributed job scheduling and management platform. The vulnerability resides in the `InstanceController.java` file within the `powerjob-server` component, specifically in versions 5.1.0, 5.1.1, and 5.1.2. An attacker can remotely exploit this vulnerability by manipulating the `customQuery` argument of the `detailPlus` endpoint, injecting malicious SQL code that is then executed by the application's database. This…
