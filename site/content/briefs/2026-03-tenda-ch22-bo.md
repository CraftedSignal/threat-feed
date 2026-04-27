---
title: Tenda CH22 Stack-Based Buffer Overflow Vulnerability
slug: 2026-03-tenda-ch22-bo
description: A stack-based buffer overflow vulnerability (CVE-2026-5152) exists in the formCreateFileName function of the /goform/createFileName endpoint in Tenda CH22 version 1.0.0.1, allowing remote attackers to execute arbitrary code by manipulating the fileNameMit argument.
date: "2026-03-30T21:17:11Z"
severities:
  - critical
tags:
  - cve-2026-5152
  - buffer-overflow
  - tenda
  - router
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0006
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1210
    technique_name: Exploitation of Remote Services
cves:
  - id: CVE-2026-5152
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5152
  - https://github.com/Litengzheng/vuldb_new/blob/main/CH22/vul_50/README.md
  - https://vuldb.com/submit/780203
  - https://vuldb.com/vuln/354184
  - https://vuldb.com/vuln/354184/cti
  - https://www.tenda.com.cn/
rules:
  - title: Tenda CH22 Buffer Overflow Attempt via Filename
    description: Detects attempts to exploit the Tenda CH22 buffer overflow vulnerability (CVE-2026-5152) by monitoring for abnormally long filename parameters in HTTP POST requests to the /goform/createFileName endpoint.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1210
    data_sources:
      - webserver
      - linux
  - title: Tenda CH22 Unauthorized Access Attempt
    description: Detects attempts to access the /goform/createFileName endpoint, which may indicate a vulnerability scan or exploit attempt.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical stack-based buffer overflow vulnerability has been identified in Tenda CH22 router version 1.0.0.1. The vulnerability, identified as CVE-2026-5152, resides within the `formCreateFileName` function located in the `/goform/createFileName` file. An attacker can exploit this vulnerability by crafting a malicious request that manipulates the `fileNameMit` argument, leading to arbitrary code execution on the device. This vulnerability is remotely exploitable and has a public exploit…
