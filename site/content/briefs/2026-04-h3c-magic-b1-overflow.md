---
title: H3C Magic B1 Router Buffer Overflow Vulnerability
slug: 2026-04-h3c-magic-b1-overflow
description: A buffer overflow vulnerability (CVE-2026-6581) in H3C Magic B1 routers allows remote attackers to execute arbitrary code by manipulating the 'param' argument in the SetMobileAPInfoById function.
date: "2026-04-19T23:16:33Z"
severities:
  - critical
tags:
  - cve-2026-6581
  - buffer-overflow
  - router
  - h3c
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-6581
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6581
  - https://github.com/hmKunlun/H3Cc/blob/main/h3c.md
  - https://vuldb.com/vuln/358216
rules:
  - title: Detect H3C Magic B1 Buffer Overflow Attempt
    description: Detects potential exploitation attempts of CVE-2026-6581 on H3C Magic B1 routers by identifying suspicious HTTP POST requests to /goform/aspForm with overly long parameters.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Large POST Request to H3C Management Interface
    description: Detects unusually large POST requests, potentially indicative of buffer overflow attempts, to the H3C router management interface.
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

A critical buffer overflow vulnerability, identified as CVE-2026-6581, affects H3C Magic B1 routers up to version 100R004. The vulnerability resides in the `SetMobileAPInfoById` function within the `/goform/aspForm` file. An attacker can exploit this flaw by crafting a malicious request that manipulates the `param` argument, leading to a buffer overflow and potential remote code execution. This vulnerability is particularly concerning because a public exploit is available, increasing the risk…
