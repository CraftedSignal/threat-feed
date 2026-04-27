---
title: D-Link DIR-513 Router Buffer Overflow Vulnerability (CVE-2026-6014)
slug: 2026-04-dlink-buffer-overflow
description: CVE-2026-6014 is a buffer overflow vulnerability in the D-Link DIR-513 router that allows a remote attacker to execute arbitrary code by manipulating the webpage argument in the formAdvanceSetup function, affecting devices that are no longer supported.
date: "2026-04-10T05:16:07Z"
severities:
  - critical
tags:
  - d-link
  - buffer-overflow
  - cve-2026-6014
  - router
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-6014
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6014
  - https://lavender-bicycle-a5a.notion.site/D-Link-DIR-513-formAdvanceSetup-33153a41781f80829d47ec9b86dd8abf?source=copy_link
  - https://vuldb.com/submit/791860
  - https://vuldb.com/vuln/356570
  - https://vuldb.com/vuln/356570/cti
  - https://www.dlink.com/
ioc_counts:
  email: 1
  url: 5
rules:
  - title: Detect D-Link DIR-513 Buffer Overflow Attempt
    description: Detects potential exploitation attempts of the D-Link DIR-513 buffer overflow vulnerability by monitoring POST requests to the /goform/formAdvanceSetup endpoint with unusually long webpage parameters.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1071.001
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Access to D-Link Default CGI Endpoint
    description: Detects requests to the vulnerable endpoint associated with D-Link devices, which could indicate vulnerability scanning or exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A buffer overflow vulnerability, tracked as CVE-2026-6014, has been identified in D-Link DIR-513 version 1.10. The vulnerability resides within the `formAdvanceSetup` function of the `/goform/formAdvanceSetup` component, specifically in the POST Request Handler. An attacker can exploit this flaw by manipulating the `webpage` argument, leading to arbitrary code execution. The vulnerability is remotely exploitable, and public exploits are available, increasing the risk of exploitation. This…
