---
title: Tenda CH22 Router Stack-Based Buffer Overflow Vulnerability
slug: 2026-03-tenda-ch22-overflow
description: A stack-based buffer overflow vulnerability exists in Tenda CH22 1.0.0.1 via manipulation of the `mit_linktype` argument in the `/goform/QuickIndex` endpoint, potentially enabling remote code execution.
date: "2026-03-31T00:16:15Z"
severities:
  - critical
tags:
  - cve-2026-5156
  - buffer-overflow
  - tenda
  - router
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5156
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5156
  - https://github.com/Litengzheng/vuldb_new/blob/main/CH22/vul_46/README.md
  - https://vuldb.com/vuln/354188
rules:
  - title: Detect Tenda CH22 mit_linktype Buffer Overflow Attempt
    description: Detects potential buffer overflow attempts on Tenda CH22 routers by monitoring the length of the `mit_linktype` parameter in POST requests to `/goform/QuickIndex`.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Tenda CH22 Exploitation Attempt via HTTP Request
    description: Detects a potential exploitation attempt against Tenda CH22 routers by looking for a specific URI and request method combination.
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

A stack-based buffer overflow vulnerability has been identified in Tenda CH22 router version 1.0.0.1. The vulnerability resides within the `formQuickIndex` function of the `/goform/QuickIndex` file, which is a component of the Parameter Handler. This flaw can be triggered by manipulating the `mit_linktype` argument, leading to a buffer overflow on the stack. The vulnerability is remotely exploitable, meaning an attacker can trigger the flaw over the network without needing local access to the…
