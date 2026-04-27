---
title: Belkin F9K1015 Stack-Based Buffer Overflow Vulnerability (CVE-2026-5612)
slug: 2026-04-belkin-overflow
description: A stack-based buffer overflow vulnerability (CVE-2026-5612) exists in Belkin F9K1015 1.00.10, allowing remote attackers to execute arbitrary code by manipulating the 'webpage' argument in the 'formWlEncrypt' function of the '/goform/formWlEncrypt' file.
date: "2026-04-06T03:16:07Z"
severities:
  - critical
tags:
  - cve-2026-5612
  - buffer-overflow
  - belkin
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5612
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5612
  - https://github.com/Litengzheng/vuldb_new/blob/main/Belkin%20F9K1015/vul_7/README.md
  - https://vuldb.com/submit/785551
  - https://vuldb.com/vuln/355403
  - https://vuldb.com/vuln/355403/cti
rules:
  - title: Detect Belkin F9K1015 Buffer Overflow Attempt via Long Webpage Parameter
    description: Detects potential exploitation of CVE-2026-5612 by monitoring for abnormally long 'webpage' parameters in POST requests to /goform/formWlEncrypt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Belkin F9K1015 Buffer Overflow Attempt via POST to goformWlEncrypt
    description: Detects potential exploitation of CVE-2026-5612 by monitoring for POST requests to /goform/formWlEncrypt with any webpage parameter.
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

CVE-2026-5612 is a critical vulnerability affecting Belkin F9K1015 router firmware version 1.00.10. Specifically, a stack-based buffer overflow can be triggered in the `formWlEncrypt` function located within the `/goform/formWlEncrypt` file. This vulnerability allows a remote attacker to inject arbitrary code by sending a specially crafted request to the router, manipulating the `webpage` argument. This exploit has been publicly disclosed, increasing the risk of widespread exploitation…
