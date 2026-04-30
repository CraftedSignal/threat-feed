---
title: Tenda AC5 Stack-Based Buffer Overflow Vulnerability (CVE-2026-4903)
slug: 2026-03-tenda-ac5-bo
description: A stack-based buffer overflow vulnerability exists in Tenda AC5 version 15.03.06.47, allowing remote attackers to execute arbitrary code by manipulating the `PPPOEPassword` argument in the `formQuickIndex` function of the `/goform/QuickIndex` component.
date: "2026-03-27T12:00:00Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - cve-2026-4903
  - buffer-overflow
  - tenda
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4903
rules:
  - title: Detect Tenda AC5 PPPOEPassword Buffer Overflow Attempt
    description: Detects potential exploitation attempts of the Tenda AC5 buffer overflow vulnerability (CVE-2026-4903) based on suspicious HTTP POST requests to /goform/QuickIndex with an overly long PPPOEPassword parameter.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Large POST Request to Tenda AC5 QuickIndex
    description: Detects unusually large POST requests to the /goform/QuickIndex endpoint, potentially indicating a buffer overflow attempt.
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

CVE-2026-4903 describes a critical stack-based buffer overflow vulnerability affecting Tenda AC5 routers, specifically version 15.03.06.47. The vulnerability resides within the `formQuickIndex` function of the `/goform/QuickIndex` component, which handles POST requests. An attacker can remotely exploit this vulnerability by crafting a malicious POST request to `/goform/QuickIndex` with an overly long `PPPOEPassword` argument. This overflow allows the attacker to potentially overwrite adjacent…
