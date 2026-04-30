---
title: Belkin F9K1122 Router Stack-Based Buffer Overflow Vulnerability
slug: 2026-03-belkin-buffer-overflow
description: A stack-based buffer overflow vulnerability (CVE-2026-5042) exists in the Belkin F9K1122 router version 1.00.33, allowing remote attackers to execute arbitrary code by manipulating the webpage argument in the formCrossBandSwitch function.
date: "2026-03-29T11:16:34Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - cve-2026-5042
  - buffer-overflow
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
    technique_id: T1203
    technique_name: Exploitation for Client Execution
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5042
  - https://github.com/Litengzheng/vul_db/blob/main/Belkin/vul_153/README.md
  - https://vuldb.com/submit/779123
  - https://vuldb.com/vuln/353965
  - https://vuldb.com/vuln/353965/cti
ioc_counts:
  url: 4
rules:
  - title: Detect Suspiciously Long GET Request to formCrossBandSwitch
    description: Detects unusually long GET requests to the /goform/formCrossBandSwitch endpoint, indicative of a buffer overflow attempt.
    platform: sigma
    severity: high
    tactics:
      - exploitation
    techniques:
      - T1210
    data_sources:
      - webserver
      - linux
  - title: Detect POST Request to formCrossBandSwitch with Long webpage Parameter
    description: Detects unusually long POST requests to /goform/formCrossBandSwitch, indicative of CVE-2026-5042 exploitation.
    platform: sigma
    severity: high
    tactics:
      - exploitation
    techniques:
      - T1210
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical stack-based buffer overflow vulnerability, identified as CVE-2026-5042, has been discovered in Belkin F9K1122 routers running firmware version 1.00.33. The vulnerability resides within the `formCrossBandSwitch` function of the `/goform/formCrossBandSwitch` file, a component of the Parameter Handler. Successful exploitation could allow a remote, unauthenticated attacker to execute arbitrary code on the device. Publicly available exploit code increases the risk of widespread…
