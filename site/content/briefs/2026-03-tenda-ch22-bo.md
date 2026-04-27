---
title: Tenda CH22 Stack-Based Buffer Overflow Vulnerability (CVE-2026-5204)
slug: 2026-03-tenda-ch22-bo
description: A stack-based buffer overflow vulnerability (CVE-2026-5204) exists in the Tenda CH22 1.0.0.1 router, allowing remote attackers to execute arbitrary code by manipulating the webSiteId argument in the formWebTypeLibrary function.
date: "2026-03-31T16:16:35Z"
severities:
  - critical
tags:
  - cve-2026-5204
  - tenda
  - buffer-overflow
  - router
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5204
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5204
  - https://github.com/Litengzheng/vuldb_new/blob/main/CH22/vul_49/README.md
  - https://vuldb.com/vuln/354332
rules:
  - title: Tenda CH22 WebSiteId Buffer Overflow Attempt
    description: Detects attempts to exploit the CVE-2026-5204 vulnerability in Tenda CH22 routers by overflowing the webSiteId parameter.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: WebSiteId Length Detection in Tenda CH22
    description: Detects unusually long webSiteId parameters, potentially indicating a buffer overflow attempt.
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

CVE-2026-5204 describes a critical stack-based buffer overflow vulnerability affecting Tenda CH22 router version 1.0.0.1. The vulnerability resides within the `formWebTypeLibrary` function in the `/goform/webtypelibrary` file, which handles web-based parameter input. An attacker can exploit this vulnerability by sending a specially crafted HTTP request to the router, manipulating the `webSiteId` argument to overwrite the stack buffer. This allows for arbitrary code execution on the device…
