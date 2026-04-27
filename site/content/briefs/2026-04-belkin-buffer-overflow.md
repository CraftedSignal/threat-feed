---
title: Belkin F9K1122 Stack-Based Buffer Overflow Vulnerability
slug: 2026-04-belkin-buffer-overflow
description: A stack-based buffer overflow vulnerability (CVE-2026-5608) exists in the formWlanSetup function of Belkin F9K1122 version 1.00.33, allowing remote attackers to execute arbitrary code by manipulating the 'webpage' argument in the /goform/formWlanSetup file.
date: "2026-04-06T01:16:40Z"
severities:
  - critical
tags:
  - buffer-overflow
  - belkin
  - cve-2026-5608
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5608
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5608
  - https://github.com/Litengzheng/vul_db/blob/main/Belkin/vul_80/README.md
  - https://vuldb.com/vuln/355399
rules:
  - title: Detect Belkin F9K1122 Buffer Overflow Attempt
    description: Detects potential exploitation attempts of CVE-2026-5608 by monitoring for overly long webpage parameters in POST requests to the vulnerable endpoint.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1078
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious POST Requests to Belkin Configuration Pages
    description: Detects POST requests to common Belkin router configuration pages. May indicate unauthorized access or exploitation attempts.
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

A stack-based buffer overflow vulnerability, identified as CVE-2026-5608, affects Belkin F9K1122 router version 1.00.33. The vulnerability resides within the `formWlanSetup` function of the `/goform/formWlanSetup` file. A remote attacker can exploit this vulnerability by manipulating the `webpage` argument, leading to arbitrary code execution on the device. This vulnerability is particularly critical because a public exploit is available, increasing the likelihood of widespread exploitation…
