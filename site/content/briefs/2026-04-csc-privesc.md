---
title: CVE-2026-26176 Windows CSC Driver Privilege Escalation
slug: 2026-04-csc-privesc
description: CVE-2026-26176 is a heap-based buffer overflow vulnerability in the Windows Client Side Caching driver (csc.sys), which allows an authorized attacker to elevate privileges locally.
date: "2026-04-14T18:16:53Z"
severities:
  - high
tags:
  - privilege-escalation
  - buffer-overflow
  - windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-26176
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-26176
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-26176
ioc_counts:
  email: 1
rules:
  - title: Detect Suspicious Csc.exe Process Creation
    description: Detects suspicious process creations involving csc.exe, which could indicate exploitation of CVE-2026-26176.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect Csc.exe Making Network Connections
    description: Detects csc.exe making outbound network connections, which is unusual and could indicate compromised system activity.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CVE-2026-26176 is a critical security vulnerability affecting the Windows Client Side Caching driver (csc.sys). The vulnerability is a heap-based buffer overflow that can be exploited by an authorized, local attacker to gain elevated privileges on the system. The specific version of the driver affected is not detailed, but the vulnerability was disclosed and patched in April 2026. A successful exploit could allow an attacker to perform actions with elevated privileges, potentially leading to…
