---
title: Tenda AC15 Router Stack-Based Buffer Overflow (CVE-2026-5830)
slug: 2026-04-tenda-ac15-overflow
description: A stack-based buffer overflow vulnerability (CVE-2026-5830) in Tenda AC15 firmware version 15.03.05.18 allows remote attackers to execute arbitrary code by manipulating password change parameters, potentially leading to complete device compromise.
date: "2026-04-09T02:16:17Z"
severities:
  - critical
tags:
  - cve-2026-5830
  - tenda
  - router
  - buffer-overflow
  - stack-overflow
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5830
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5830
  - https://files.catbox.moe/xrk8jb.zip
  - https://vuldb.com/vuln/356277
rules:
  - title: Detect Tenda AC15 Password Change Overflow
    description: Detects suspicious POST requests to the Tenda AC15 password change endpoint with overly long password parameters, indicative of a buffer overflow attempt.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
  - title: Detect Tenda AC15 SysToolChangePwd Access
    description: Detects access to the SysToolChangePwd page which might indicate a password change attempt. Potentially malicious when combined with other suspicious network activity.
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

A critical stack-based buffer overflow vulnerability, tracked as CVE-2026-5830, has been identified in Tenda AC15 routers running firmware version 15.03.05.18. The vulnerability resides in the `websGetVar` function within the `/goform/SysToolChangePwd` file, which handles password change requests. By crafting malicious requests and manipulating the `oldPwd`, `newPwd`, or `cfmPwd` arguments, an attacker can overwrite the stack, potentially leading to arbitrary code execution. The vulnerability…
