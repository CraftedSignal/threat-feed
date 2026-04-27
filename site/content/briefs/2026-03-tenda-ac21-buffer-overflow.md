---
title: Tenda AC21 Router Buffer Overflow Vulnerability
slug: 2026-03-tenda-ac21-buffer-overflow
description: A buffer overflow vulnerability exists in Tenda AC21 firmware version 16.03.08.16, allowing remote attackers to execute arbitrary code by manipulating arguments to the formSetQosBand function.
date: "2026-03-23T01:16:43Z"
severities:
  - critical
tags:
  - tenda
  - ac21
  - buffer_overflow
  - cve-2026-4565
  - router
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4565
  - https://github.com/hellonestor/killallbug/issues/14
  - https://github.com/hellonestor/killallbug/releases/tag/poc
rules:
  - title: Detect Suspicious POST Requests to SetNetControlList
    description: Detects suspicious POST requests to the /goform/SetNetControlList endpoint, potentially indicating an exploitation attempt.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Tenda AC21 Buffer Overflow Attempt
    description: Detects attempts to exploit the buffer overflow vulnerability in Tenda AC21 routers by identifying overly long arguments in the query string.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical buffer overflow vulnerability, CVE-2026-4565, affects Tenda AC21 routers running firmware version 16.03.08.16. The flaw resides in the `formSetQosBand` function within the `/goform/SetNetControlList` file. Attackers can exploit this vulnerability by crafting malicious argument lists in HTTP requests, leading to arbitrary code execution on the device. The vulnerability can be exploited remotely and a proof-of-concept exploit is publicly available, increasing the risk of widespread…
