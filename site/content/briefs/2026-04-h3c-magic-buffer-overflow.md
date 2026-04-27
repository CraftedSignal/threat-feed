---
title: H3C Magic B0 Router Buffer Overflow Vulnerability (CVE-2026-6560)
slug: 2026-04-h3c-magic-buffer-overflow
description: A buffer overflow vulnerability (CVE-2026-6560) in H3C Magic B0 up to 100R002 allows remote attackers to execute arbitrary code by manipulating the 'param' argument in the Edit_BasicSSID function of the /goform/aspForm file.
date: "2026-04-19T07:16:05Z"
severities:
  - critical
tags:
  - buffer overflow
  - cve-2026-6560
  - h3c
  - router
  - network device
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
cves:
  - id: CVE-2026-6560
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6560
  - https://github.com/xiaohaiyang-ai/CVE-Reports/blob/main/Vulnerability-Report.md
  - https://vuldb.com/submit/788021
  - https://vuldb.com/vuln/358197
  - https://vuldb.com/vuln/358197/cti
rules:
  - title: Detect H3C Magic B0 Buffer Overflow Attempt via Long Parameter
    description: Detects potential buffer overflow exploitation attempts on H3C Magic B0 routers by identifying abnormally long 'param' values in POST requests to /goform/aspForm
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1189
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect H3C Magic B0 Router Accessing Public Exploit URL
    description: Detects H3C Magic B0 router accessing URL hosting exploit code.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1592
    data_sources:
      - network_connection
      - firewall
rules_count: 2
---

A critical buffer overflow vulnerability (CVE-2026-6560) has been identified in H3C Magic B0 routers, specifically in versions up to 100R002. The vulnerability resides within the `Edit_BasicSSID` function of the `/goform/aspForm` file. An attacker can remotely exploit this flaw by crafting malicious input to the `param` argument, leading to arbitrary code execution on the device. Public exploits are reportedly available, increasing the risk of widespread exploitation. The vendor was notified…
