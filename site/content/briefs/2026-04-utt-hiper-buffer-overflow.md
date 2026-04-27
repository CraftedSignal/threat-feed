---
title: UTT HiPER 1250GW Buffer Overflow Vulnerability
slug: 2026-04-utt-hiper-buffer-overflow
description: A buffer overflow vulnerability exists in UTT HiPER 1250GW devices, allowing remote attackers to execute arbitrary code by manipulating the NatBind argument in the /goform/formNatStaticMap endpoint.
date: "2026-04-05T13:17:14Z"
severities:
  - critical
tags:
  - cve-2026-5566
  - buffer-overflow
  - remote-code-execution
  - utt-hiper
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5566
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5566
  - https://github.com/Moxxkidd/CVE/issues/1
  - https://vuldb.com/vuln/355336
rules:
  - title: Detect Suspicious NatBind Parameter Length
    description: Detects suspicious POST requests to /goform/formNatStaticMap with unusually long NatBind parameters, indicating a potential buffer overflow attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Access to formNatStaticMap
    description: Detects access to the formNatStaticMap endpoint, which could be related to exploitation attempts.
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

A critical buffer overflow vulnerability, tracked as CVE-2026-5566, affects UTT HiPER 1250GW devices with firmware versions up to 3.2.7-210907-180535. The vulnerability resides in the `strcpy` function within the `/goform/formNatStaticMap` endpoint. A remote attacker can exploit this vulnerability by crafting a malicious request that overflows the buffer when processing the `NatBind` argument. Publicly available exploits exist, increasing the risk of widespread exploitation. Successful…
