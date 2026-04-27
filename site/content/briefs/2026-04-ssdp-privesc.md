---
title: Windows SSDP Service Race Condition Privilege Escalation (CVE-2026-32068)
slug: 2026-04-ssdp-privesc
description: CVE-2026-32068 is a race condition vulnerability in the Windows SSDP Service that allows an authorized attacker to elevate privileges locally.
date: "2026-04-15T12:00:00Z"
severities:
  - high
exploited: true
tags:
  - cve-2026-32068
  - privilege-escalation
  - windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-32068
    cvss: 7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32068
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32068
rules:
  - title: Detect SSDP Service Hosting Svchost with Anomalous Child Processes
    description: Detects unusual child processes spawned from the svchost.exe process hosting the SSDP service, which could indicate exploitation attempts related to CVE-2026-32068.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect SSDP Service Svchost with Modified CommandLine
    description: Detects changes to the command line of the svchost.exe process hosting the SSDP service, potentially indicating an attempt to exploit CVE-2026-32068.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-32068 describes a race condition vulnerability within the Windows SSDP (Simple Service Discovery Protocol) service. This vulnerability allows a locally authenticated attacker with low privileges to potentially escalate their privileges to SYSTEM. The vulnerability stems from improper synchronization when the SSDP service handles concurrent requests. Exploitation requires careful timing to manipulate shared resources. While the vulnerability was published on 2026-04-14, active…
