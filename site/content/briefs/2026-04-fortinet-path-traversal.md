---
title: Fortinet FortiSandbox Path Traversal Vulnerability (CVE-2026-39813)
slug: 2026-04-fortinet-path-traversal
description: A path traversal vulnerability (CVE-2026-39813) in Fortinet FortiSandbox versions 5.0.0 through 5.0.5 and 4.4.0 through 4.4.8 may allow an unauthenticated attacker to escalate privileges via '../filedir'.
date: "2026-04-14T16:16:45Z"
severities:
  - critical
tags:
  - path-traversal
  - vulnerability
  - privilege-escalation
  - fortinet
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-39813
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-39813
  - https://fortiguard.fortinet.com/psirt/FG-IR-26-112
ioc_counts:
  email: 2
rules:
  - title: Detect Fortinet FortiSandbox Path Traversal Attempt
    description: Detects path traversal attempts targeting Fortinet FortiSandbox using '../filedir' in web server logs, indicating potential CVE-2026-39813 exploitation.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Fortinet FortiSandbox Path Traversal Attempt (URI)
    description: Detects path traversal attempts targeting Fortinet FortiSandbox using '../filedir' in the URI path.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A path traversal vulnerability, identified as CVE-2026-39813, affects Fortinet FortiSandbox appliances. Specifically, versions 5.0.0 through 5.0.5 and 4.4.0 through 4.4.8 are susceptible. The vulnerability stems from insufficient path validation, potentially allowing an unauthenticated attacker to manipulate file paths and gain elevated privileges on the system. The specific attack vector is not detailed in the source document, but the use of '../filedir' suggests the possibility of reading or…
