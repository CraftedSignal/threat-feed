---
title: UTT HiPER 1250GW Stack-Based Buffer Overflow Vulnerability
slug: 2026-04-utt-hiper-overflow
description: A stack-based buffer overflow vulnerability in UTT HiPER 1250GW devices allows remote attackers to execute arbitrary code by manipulating the 'Profile' argument in the /goform/formRemoteControl file.
date: "2026-04-05T06:16:01Z"
severities:
  - critical
exploited: true
tags:
  - cve-2026-5544
  - buffer-overflow
  - webserver
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5544
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5544
  - https://github.com/jinxjinxboom/cve/issues/1
  - https://vuldb.com/vuln/355297
rules:
  - title: Detect UTT HiPER Buffer Overflow Attempt
    description: Detects potential attempts to exploit the buffer overflow vulnerability (CVE-2026-5544) in UTT HiPER devices by monitoring the length of the Profile argument in requests to /goform/formRemoteControl.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect UTT HiPER 1250GW CVE-2026-5544 Exploitation Attempt
    description: Detects potential exploitation attempts of CVE-2026-5544 in UTT HiPER 1250GW devices based on HTTP requests to the /goform/formRemoteControl endpoint.
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

A critical security vulnerability, CVE-2026-5544, affects UTT HiPER 1250GW devices with firmware versions up to 3.2.7-210907-180535. The vulnerability resides in the `/goform/formRemoteControl` file, where manipulation of the `Profile` argument results in a stack-based buffer overflow. This flaw allows unauthenticated remote attackers to potentially execute arbitrary code on the affected device. The vulnerability has a CVSS v3.1 score of 8.8 (HIGH). Publicly available exploits exist, increasing…
