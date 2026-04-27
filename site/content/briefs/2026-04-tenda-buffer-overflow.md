---
title: Tenda F451 Router Stack-Based Buffer Overflow Vulnerability
slug: 2026-04-tenda-buffer-overflow
description: A stack-based buffer overflow vulnerability exists in Tenda F451 version 1.0.0.7, allowing remote attackers to execute arbitrary code by manipulating the `mit_ssid` argument in the `/goform/AdvSetWrlsafeset` file.
date: "2026-04-09T23:17:02Z"
severities:
  - critical
tags:
  - cve-2026-5988
  - buffer-overflow
  - tenda
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5988
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5988
  - https://github.com/Jimi-Lab/cve/issues/4
  - https://vuldb.com/vuln/356542
rules:
  - title: Detect Suspicious AdvSetWrlsafeset Request
    description: Detects HTTP requests to /goform/AdvSetWrlsafeset with an unusually long mit_ssid parameter, indicative of a buffer overflow attempt.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Large POST Request to AdvSetWrlsafeset
    description: Detects abnormally large POST requests to the /goform/AdvSetWrlsafeset endpoint, potentially indicating a buffer overflow attack.
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

A stack-based buffer overflow vulnerability has been identified in Tenda F451 router version 1.0.0.7. The vulnerability resides within the `formWrlsafeset` function of the `/goform/AdvSetWrlsafeset` file. A remote attacker can exploit this flaw by crafting a malicious request with an overly long `mit_ssid` argument, leading to potential arbitrary code execution on the device. Public exploits for this vulnerability are available, making it imperative for users of affected Tenda devices to take…
