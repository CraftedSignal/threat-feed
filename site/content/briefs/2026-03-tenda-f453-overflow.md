---
title: Tenda F453 Stack-Based Buffer Overflow Vulnerability (CVE-2026-5021)
slug: 2026-03-tenda-f453-overflow
description: A stack-based buffer overflow vulnerability in Tenda F453 1.0.0.3 allows a remote attacker to execute arbitrary code by manipulating the 'delno' argument in the fromPPTPUserSetting function of the /goform/PPTPUserSetting component's httpd process.
date: "2026-03-29T02:16:17Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - cve-2026-5021
  - buffer-overflow
  - router
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5021
  - https://github.com/Litengzheng/vul_db/blob/main/F453/vul_92/README.md
  - https://vuldb.com/vuln/353906
rules:
  - title: Detect Tenda F453 PPTPUserSetting Buffer Overflow Attempt
    description: Detects attempts to exploit CVE-2026-5021 by identifying unusually long 'delno' parameters in requests to /goform/PPTPUserSetting.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect HTTP POST to PPTPUserSetting
    description: Detects HTTP POST requests to /goform/PPTPUserSetting, which could be indicative of exploit activity.
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

A stack-based buffer overflow vulnerability, identified as CVE-2026-5021, has been discovered in Tenda F453 router version 1.0.0.3. This vulnerability resides within the `fromPPTPUserSetting` function of the `/goform/PPTPUserSetting` component, specifically in the `httpd` process. The vulnerability can be triggered by manipulating the `delno` argument. Successful exploitation allows remote attackers to potentially execute arbitrary code on the affected device. Publicly available exploit code…
