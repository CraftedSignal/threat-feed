---
title: Tenda CH22 Stack-Based Buffer Overflow Vulnerability
slug: 2026-03-tenda-ch22-buffer-overflow
description: A stack-based buffer overflow vulnerability exists in Tenda CH22 1.0.0.1/1.If allowing remote attackers to execute arbitrary code by manipulating the `funcname` argument in the `/goform/setcfm` endpoint.
date: "2026-03-30T23:17:04Z"
severities:
  - critical
tags:
  - cve-2026-5154
  - tenda
  - buffer-overflow
  - router
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0006
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2026-5154
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5154
  - https://github.com/Litengzheng/vuldb_new/blob/main/CH22/vul_48/README.md
  - https://vuldb.com/vuln/354186
rules:
  - title: Detect Exploitation Attempts of Tenda CH22 CVE-2026-5154
    description: Detects suspicious POST requests to /goform/setcfm with long funcname parameters indicative of a stack-based buffer overflow attempt.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1190
      - T1203
    data_sources:
      - webserver
      - linux
  - title: Tenda CH22 - Suspicious POST Request to /goform/setcfm
    description: Detects POST requests to /goform/setcfm which might indicate command execution
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical stack-based buffer overflow vulnerability, identified as CVE-2026-5154, has been discovered in Tenda CH22 firmware version 1.0.0.1/1.If. The vulnerability resides within the `fromSetCfm` function in the `/goform/setcfm` file, a component of the Parameter Handler. Successful exploitation allows remote attackers to execute arbitrary code on the device. Publicly available exploits exist, increasing the risk of widespread exploitation. This vulnerability poses a significant threat to…
