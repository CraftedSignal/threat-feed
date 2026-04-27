---
title: Tenda F451 Stack-Based Buffer Overflow Vulnerability
slug: 2026-04-tenda-stack-overflow
description: A stack-based buffer overflow vulnerability in Tenda F451 version 1.0.0.7 allows remote attackers to execute arbitrary code by manipulating the 'page/menufacturer' argument in the fromSafeMacFilter function.
date: "2026-04-12T09:16:18Z"
severities:
  - critical
tags:
  - cve-2026-6124
  - buffer-overflow
  - router
  - tenda
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-6124
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6124
  - https://github.com/Jimi-Lab/cve/issues/16
  - https://vuldb.com/vuln/356987
rules:
  - title: Detect Tenda F451 Stack Overflow Attempt via URI
    description: Detects attempts to exploit the Tenda F451 stack-based buffer overflow vulnerability (CVE-2026-6124) by monitoring for abnormally long 'page' or 'menufacturer' parameters in requests to '/goform/SafeMacFilter'.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect CVE-2026-6124 Exploitation attempt
    description: Detects requests to the affected /goform/SafeMacFilter endpoint
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

A stack-based buffer overflow vulnerability has been identified in Tenda F451 version 1.0.0.7. This flaw resides in the `fromSafeMacFilter` function of the `/goform/SafeMacFilter` file within the `httpd` component. Successful exploitation allows a remote attacker to execute arbitrary code on the affected device. The vulnerability is triggered by manipulating the `page/menufacturer` argument. Publicly available exploits exist, increasing the risk of widespread exploitation. Routers are often…
