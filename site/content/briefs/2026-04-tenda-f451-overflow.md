---
title: Tenda F451 Remote Stack-Based Buffer Overflow Vulnerability
slug: 2026-04-tenda-f451-overflow
description: A remote stack-based buffer overflow vulnerability (CVE-2026-5991) exists in the Tenda F451 router version 1.0.0.7, allowing unauthenticated attackers to potentially execute arbitrary code via a crafted request to the `/goform/WrlExtraSet` endpoint.
date: "2026-04-10T00:16:36Z"
severities:
  - critical
tags:
  - cve-2026-5991
  - tenda
  - buffer-overflow
  - router
  - webserver
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5991
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5991
  - https://github.com/Jimi-Lab/cve/issues/9
  - https://vuldb.com/vuln/356545
rules:
  - title: Detect Tenda F451 Buffer Overflow Attempt
    description: Detects potential buffer overflow attempts against Tenda F451 routers by monitoring for abnormally long GO parameters in requests to the /goform/WrlExtraSet endpoint.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect High Volume of Requests to Tenda Configuration Page
    description: Detects a high volume of requests to /goform/WrlExtraSet, potentially indicating a brute-force or automated exploitation attempt targeting CVE-2026-5991.
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

A stack-based buffer overflow vulnerability has been identified in Tenda F451 version 1.0.0.7. The vulnerability resides within the `formWrlExtraSet` function in the `/goform/WrlExtraSet` file. An attacker can trigger the overflow by manipulating the `GO` argument in a crafted HTTP request. This vulnerability is remotely exploitable and could allow an attacker to execute arbitrary code on the device. Publicly available exploits exist, increasing the risk of exploitation. Given the widespread…
