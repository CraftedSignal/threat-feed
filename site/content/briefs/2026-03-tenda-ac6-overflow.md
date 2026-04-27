---
title: Tenda AC6 Stack-Based Buffer Overflow Vulnerability
slug: 2026-03-tenda-ac6-overflow
description: A stack-based buffer overflow vulnerability in Tenda AC6 version 15.03.05.16 allows remote attackers to execute arbitrary code by manipulating the WANT/WANS argument in the /goform/WizardHandle POST request handler.
date: "2026-03-27T17:16:30Z"
severities:
  - critical
tags:
  - cve-2026-4960
  - buffer-overflow
  - tenda
  - router
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4960
  - https://lavender-bicycle-a5a.notion.site/Tenda-AC6-WizardHandle-32053a41781f800eb05feb16885747f7?source=copy_link
  - https://vuldb.com/?ctiid.353837
  - https://vuldb.com/?id.353837
  - https://vuldb.com/?submit.777616
  - https://www.tenda.com.cn/
rules:
  - title: Detect Tenda AC6 WizardHandle Buffer Overflow Attempt
    description: Detects suspicious POST requests to /goform/WizardHandle with excessively long WANT or WANS parameters, indicative of a buffer overflow attempt (CVE-2026-4960).
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Exploitation Attempt via HTTP POST Request to /goform/WizardHandle
    description: Detects attempts to exploit a vulnerability by sending a POST request to /goform/WizardHandle.
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

A critical stack-based buffer overflow vulnerability has been identified in Tenda AC6 router firmware version 15.03.05.16. The vulnerability, tracked as CVE-2026-4960, resides within the `fromWizardHandle` function of the `/goform/WizardHandle` component, which handles POST requests. A remote attacker can exploit this vulnerability by sending a crafted POST request with a manipulated `WANT` or `WANS` argument, leading to arbitrary code execution on the device. Public exploit code is available…
