---
title: Grafana Enterprise Plugin SQL Expression RCE via CVE-2026-27876
slug: 2026-03-grafana-rce
description: A chained attack leveraging SQL Expressions and a Grafana Enterprise plugin, tracked as CVE-2026-27876, can lead to remote arbitrary code execution on vulnerable Grafana instances with the sqlExpressions feature enabled.
date: "2026-03-27T15:16:50Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - grafana
  - rce
  - sqlexpression
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Indirect Command Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server-Side Component
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-27876
  - https://grafana.com/security/security-advisories/cve-2026-27876
ioc_counts:
  email: 1
  url: 1
rules:
  - title: Detect Suspicious Grafana SQL Expression Usage
    description: Detects potential exploitation attempts leveraging SQL Expressions in Grafana by identifying unusual SQL queries within Grafana logs.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - webserver
      - linux
  - title: Detect Grafana Enterprise Plugin SQL Injection Attempts
    description: Detects potential SQL injection attempts targeting Grafana Enterprise plugins by monitoring for suspicious SQL syntax in HTTP requests.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1505.003
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-27876 describes a critical vulnerability in Grafana that allows for remote arbitrary code execution (RCE). The vulnerability stems from a chained attack involving SQL Expressions and a Grafana Enterprise plugin. Successful exploitation requires the `sqlExpressions` feature toggle to be enabled on the Grafana instance. Grafana Labs strongly recommends that all users update their Grafana instances to the latest version to mitigate the risk of exploitation, even if the `sqlExpressions`…
