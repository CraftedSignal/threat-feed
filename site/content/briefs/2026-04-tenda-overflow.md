---
title: Tenda F456 Stack-Based Buffer Overflow Vulnerability (CVE-2026-6200)
slug: 2026-04-tenda-overflow
description: A stack-based buffer overflow vulnerability in the formwebtypelibrary function of Tenda F456 router version 1.0.0.5 allows a remote attacker to execute arbitrary code by manipulating the menufacturer/Go argument in a request to /goform/webtypelibrary.
date: "2026-04-13T19:16:58Z"
severities:
  - critical
tags:
  - cve-2026-6200
  - tenda
  - router
  - buffer-overflow
  - webserver
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0006
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-6200
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6200
  - https://github.com/Litengzheng/vuldb_new/blob/main/F456/vul_117/README.md
  - https://vuldb.com/vuln/357122
rules:
  - title: Detect Tenda F456 Webtype Library Buffer Overflow Attempt
    description: Detects potential attempts to exploit the CVE-2026-6200 vulnerability by identifying HTTP POST requests to the /goform/webtypelibrary endpoint with excessively long 'menufacturer/Go' parameters.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Tenda Router Web Interface Access
    description: Detects access to the Tenda router web interface, which may indicate reconnaissance activity.
    platform: sigma
    severity: low
    tactics:
      - reconnaissance
    techniques:
      - T1595
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical stack-based buffer overflow vulnerability, tracked as CVE-2026-6200, affects Tenda F456 routers running firmware version 1.0.0.5. The vulnerability resides within the `formwebtypelibrary` function located in the `/goform/webtypelibrary` file. An attacker can exploit this flaw by crafting a malicious request that manipulates the `menufacturer/Go` argument, leading to a buffer overflow. The vulnerability is remotely exploitable, meaning an attacker does not need local access to the…
