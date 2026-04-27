---
title: Tenda HG3 v2.0 Stack-Based Buffer Overflow in formUploadConfig
slug: 2026-04-tenda-hg3-overflow
description: A stack-based buffer overflow vulnerability in the formUploadConfig function of Tenda HG3 v2.0's /boaform/formIPv6Routing file allows remote attackers to execute arbitrary code by manipulating the destNet argument.
date: "2026-04-28T12:00:00Z"
severities:
  - critical
tags:
  - cve-2026-7151
  - buffer-overflow
  - tenda
  - router
vendors:
  - Tenda
products:
  - HG3
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1210
    technique_name: Exploitation of Remote Services
cves:
  - id: CVE-2026-7151
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7151
  - https://vuldb.com/vuln/359750
  - https://vuldb.com/submit/802058
  - https://www.notion.so/33e0c75766a88041bd86d3810994a541
rules:
  - title: Detect Tenda HG3 formUploadConfig Buffer Overflow Attempt
    description: Detects attempts to exploit the stack-based buffer overflow in Tenda HG3's formUploadConfig function by monitoring for abnormally long destNet parameters.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Tenda HG3 formUploadConfig POST Request
    description: Detects POST requests to Tenda HG3's formUploadConfig function. Monitor for unusual IPs or request patterns.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A stack-based buffer overflow vulnerability has been identified in Tenda HG3 version 2.0. The vulnerability exists within the `formUploadConfig` function of the `/boaform/formIPv6Routing` file. A remote attacker can exploit this by manipulating the `destNet` argument, potentially leading to arbitrary code execution on the device. The vulnerability, identified as CVE-2026-7151, has a publicly available exploit, increasing the risk of exploitation. This poses a significant threat to users of…
