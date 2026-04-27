---
title: Belkin F9K1122 Router Stack-Based Buffer Overflow
slug: 2026-03-belkin-rce
description: A stack-based buffer overflow vulnerability exists in Belkin F9K1122 version 1.00.33, allowing remote attackers to execute arbitrary code by manipulating the 'webpage' argument in the 'formWISP5G' function.
date: "2026-03-23T03:16:00Z"
severities:
  - critical
tags:
  - cve-2026-4566
  - buffer-overflow
  - router
  - rce
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4566
  - https://github.com/Litengzheng/vul_db/blob/main/Belkin/vul_151/README.md
rules:
  - title: Belkin Router RCE Attempt
    description: Detects attempts to exploit the stack-based buffer overflow in Belkin F9K1122 routers via a long webpage parameter.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Belkin F9K1122 Router User Agent
    description: Detects connections using the Belkin F9K1122 Router's default User Agent string.
    platform: sigma
    severity: informational
    tactics:
      - reconnaissance
    techniques:
      - T1595.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A stack-based buffer overflow vulnerability has been discovered in the Belkin F9K1122 router, specifically version 1.00.33. The vulnerability resides within the `formWISP5G` function located in the `/goform/formWISP5G` file. Successful exploitation involves manipulating the `webpage` argument, leading to arbitrary code execution. This vulnerability is remotely exploitable, making it a significant threat. Publicly available exploit code exists, increasing the likelihood of exploitation. The…
