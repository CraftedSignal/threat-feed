---
title: Tenda F456 Router Buffer Overflow Vulnerability
slug: 2026-04-tenda-buffer-overflow
description: A buffer overflow vulnerability in Tenda F456 router version 1.0.0.5 allows a remote attacker to execute arbitrary code by exploiting the fromSafeClientFilter function in the /goform/SafeClientFilter endpoint through manipulation of the 'menufacturer/Go' argument.
date: "2026-04-26T11:16:06Z"
severities:
  - critical
tags:
  - buffer-overflow
  - remote-code-execution
  - cve-2026-7033
  - router
vendors:
  - Tenda
products:
  - F456 1.0.0.5
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-7033
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7033
  - https://github.com/Litengzheng/vuldb_new/blob/main/F456/vul_123/README.md
  - https://vuldb.com/vuln/359613
rules:
  - title: Detect Tenda F456 Buffer Overflow Attempt via URI
    description: Detects potential buffer overflow attempts on Tenda F456 routers by monitoring HTTP requests to the /goform/SafeClientFilter endpoint with excessively long menufacturer/Go parameters.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1210
    data_sources:
      - webserver
      - linux
  - title: Detect Tenda F456 POST to vulnerable endpoint
    description: Detects POST requests to the /goform/SafeClientFilter endpoint on Tenda devices, which is associated with CVE-2026-7033.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1210
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A buffer overflow vulnerability has been identified in Tenda F456 router, specifically version 1.0.0.5. The vulnerability resides within the `fromSafeClientFilter` function located in the `/goform/SafeClientFilter` file. Successful exploitation allows a remote attacker to inject and execute arbitrary code. Publicly available exploit code exists, increasing the risk of widespread exploitation targeting vulnerable Tenda F456 devices. This issue poses a significant threat to network security, as a…
