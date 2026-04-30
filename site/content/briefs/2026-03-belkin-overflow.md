---
title: Belkin F9K1122 Stack-Based Buffer Overflow Vulnerability
slug: 2026-03-belkin-overflow
description: A stack-based buffer overflow vulnerability (CVE-2026-5044) in Belkin F9K1122 version 1.00.33 allows remote attackers to execute arbitrary code by manipulating the 'webpage' argument in the formSetSystemSettings function, potentially leading to complete system compromise.
date: "2026-03-29T13:17:03Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - cve-2026-5044
  - buffer-overflow
  - belkin
  - router
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5044
  - https://github.com/Litengzheng/vul_db/blob/main/Belkin/vul_155/README.md
  - https://vuldb.com/vuln/353967
rules:
  - title: Detect Belkin F9K1122 Buffer Overflow Attempt
    description: Detects attempts to exploit CVE-2026-5044 by monitoring HTTP POST requests to the vulnerable endpoint with overly long webpage parameters.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1210
    data_sources:
      - webserver
      - linux
  - title: Detect Belkin F9K1122 Buffer Overflow Traffic Volume
    description: Detects abnormally high network traffic to the vulnerable endpoint, indicating potential scanning or exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1046
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

A critical security vulnerability, CVE-2026-5044, has been identified in Belkin F9K1122 router version 1.00.33. The vulnerability resides within the `formSetSystemSettings` function of the `/goform/formSetSystemSettings` file, which is part of the Setting Handler component. Successful exploitation allows a remote attacker to trigger a stack-based buffer overflow by manipulating the `webpage` argument. This could result in arbitrary code execution on the device. Publicly available exploit code…
