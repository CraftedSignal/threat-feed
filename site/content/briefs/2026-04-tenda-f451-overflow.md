---
title: Tenda F451 Router Stack-Based Buffer Overflow Vulnerability
slug: 2026-04-tenda-f451-overflow
description: Tenda F451 router version 1.0.0.7 is vulnerable to a stack-based buffer overflow in the frmL7ProtForm function, enabling remote attackers to execute arbitrary code by manipulating the 'page' argument.
date: "2026-04-12T08:16:37Z"
severities:
  - critical
tags:
  - cve-2026-6122
  - buffer-overflow
  - router
  - tenda
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-6122
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6122
rules:
  - title: Detect Tenda F451 Buffer Overflow Attempt
    description: Detects attempts to exploit the stack-based buffer overflow vulnerability (CVE-2026-6122) in Tenda F451 routers by monitoring for requests to the /goform/L7Prot endpoint with excessively long 'page' parameters.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1068
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Tenda F451 POST Request to L7Prot
    description: Detects POST requests to the /goform/L7Prot endpoint which may indicate command execution or exploitation attempts.
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

A critical stack-based buffer overflow vulnerability has been identified in Tenda F451 router version 1.0.0.7. The vulnerability resides within the `frmL7ProtForm` function of the `/goform/L7Prot` component, specifically within the `httpd` service. A remote attacker can exploit this flaw by crafting a malicious request targeting the `page` argument. Successful exploitation allows the attacker to execute arbitrary code on the device. Publicly available exploit code exists, increasing the risk of…
