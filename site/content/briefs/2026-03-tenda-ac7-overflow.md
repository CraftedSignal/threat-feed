---
title: Tenda AC7 Stack-Based Buffer Overflow in SetSysTimeCfg
slug: 2026-03-tenda-ac7-overflow
description: A stack-based buffer overflow vulnerability exists in Tenda AC7 version 15.03.06.44 within the fromSetSysTime function of the /goform/SetSysTimeCfg component's POST Request Handler, allowing a remote attacker to potentially execute arbitrary code by manipulating the 'Time' argument.
date: "2026-03-27T20:16:38Z"
severities:
  - critical
tags:
  - cve
  - buffer-overflow
  - router
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4974
  - https://lavender-bicycle-a5a.notion.site/Tenda-AC7-fromSetSysTime-32153a41781f801c95b0f8a53eaa9a1f?source=copy_link
  - https://vuldb.com/?id.353861
rules:
  - title: Detect Suspiciously Long Time Parameter in Tenda AC7 SetSysTimeCfg
    description: Detects POST requests to /goform/SetSysTimeCfg with an unusually long Time parameter, indicative of a potential buffer overflow attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Processes Spawned by Webserver After Potential Tenda AC7 Overflow
    description: Detects processes spawned by the webserver after a potential buffer overflow exploit, indicating code execution.
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

A stack-based buffer overflow vulnerability has been identified in Tenda AC7 router firmware, specifically version 15.03.06.44. The vulnerability resides in the `fromSetSysTime` function within the `/goform/SetSysTimeCfg` component, which handles POST requests. A remote attacker can exploit this flaw by crafting a malicious POST request with an overly long `Time` argument, causing a buffer overflow on the stack. Publicly available exploits exist, increasing the risk of exploitation. Successful…
