---
title: Tenda F451 Stack-Based Buffer Overflow Vulnerability
slug: 2026-04-tenda-buffer-overflow
description: A stack-based buffer overflow vulnerability (CVE-2026-6134) exists in Tenda F451 version 1.0.0.7_cn_svn7958, affecting the fromqossetting function of the /goform/qossetting file, allowing remote attackers to execute arbitrary code by manipulating the qos argument, with a public exploit available.
date: "2026-04-12T23:19:54Z"
severities:
  - critical
tags:
  - cve-2026-6134
  - buffer-overflow
  - tenda
  - router
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Software Discovery
cves:
  - id: CVE-2026-6134
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6134
  - https://github.com/Jimi-Lab/cve/issues/18
  - https://vuldb.com/vuln/356998
rules:
  - title: Tenda F451 QoS Buffer Overflow Attempt
    description: Detects attempts to exploit the CVE-2026-6134 buffer overflow vulnerability in Tenda F451 via a long 'qos' parameter in a POST request to /goform/qossetting.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1210
    data_sources:
      - webserver
      - linux
  - title: Tenda F451 Goform Access
    description: Detects access to the goform page which is a common attack vector on Tenda F451 routers.
    platform: sigma
    severity: low
    tactics:
      - reconnaissance
    techniques:
      - T1595
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical stack-based buffer overflow vulnerability, CVE-2026-6134, has been identified in Tenda F451 router firmware version 1.0.0.7_cn_svn7958. This flaw resides within the `fromqossetting` function of the `/goform/qossetting` file. Successful exploitation allows remote attackers to execute arbitrary code on the affected device. The vulnerability is triggered by manipulating the `qos` argument. Given the public availability of a functional exploit, Tenda F451 devices running the vulnerable…
