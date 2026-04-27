---
title: Tenda F456 Stack-Based Buffer Overflow Vulnerability
slug: 2026-04-tenda-stack-overflow
description: A stack-based buffer overflow vulnerability (CVE-2026-6197) exists in Tenda F456 version 1.0.0.5, allowing remote attackers to execute arbitrary code by manipulating the 'mit_ssid' argument in the '/goform/AdvSetWrlsafeset' file.
date: "2026-04-13T19:16:57Z"
severities:
  - critical
tags:
  - cve-2026-6197
  - buffer-overflow
  - router
  - tenda
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
cves:
  - id: CVE-2026-6197
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6197
  - https://github.com/Litengzheng/vuldb_new/blob/main/F456/vul_114/README.md
  - https://vuldb.com/vuln/357119
rules:
  - title: Tenda F456 Buffer Overflow Attempt
    description: Detects attempts to exploit the stack-based buffer overflow in Tenda F456 via a long mit_ssid parameter
    platform: sigma
    severity: high
    tactics:
      - exploitation
    techniques:
      - T1210
    data_sources:
      - webserver
      - linux
  - title: Tenda F456 Buffer Overflow Exploit
    description: Detects shellcode execution following exploitation of the stack-based buffer overflow in Tenda F456
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A stack-based buffer overflow vulnerability, identified as CVE-2026-6197, has been discovered in Tenda F456 router firmware version 1.0.0.5. The vulnerability resides within the `formWrlsafeset` function of the `/goform/AdvSetWrlsafeset` file. Attackers can exploit this flaw by sending a specially crafted request to the router, specifically manipulating the `mit_ssid` argument. Successful exploitation allows a remote attacker to potentially execute arbitrary code on the device. Publicly…
