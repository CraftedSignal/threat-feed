---
title: CVE-2026-32087 Function Discovery Service Privilege Escalation
slug: 2026-04-fdwsd-privesc
description: CVE-2026-32087 is a heap-based buffer overflow vulnerability in the Function Discovery Service (fdwsd.dll) that allows an authorized local attacker to elevate privileges on a Windows system.
date: "2026-04-14T18:17:12Z"
severities:
  - high
tags:
  - privilege-escalation
  - heap-overflow
  - cve
  - windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-32087
    cvss: 7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32087
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32087
rules:
  - title: Detect Suspicious Process Creation from FDWSD
    description: Detects potential exploitation of CVE-2026-32087 by monitoring for unusual processes spawned by fdwsd.dll.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect FDWSD Service Anomalous Network Connection
    description: Detects potential exploitation of CVE-2026-32087 by monitoring for unusual network connections originating from fdwsd.dll.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - privilege_escalation
    techniques:
      - T1068
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CVE-2026-32087 describes a heap-based buffer overflow vulnerability affecting the Function Discovery Service, specifically the `fdwsd.dll` module. This vulnerability allows a locally authenticated attacker with low privileges to escalate their privileges to a higher level on the targeted Windows system. The vulnerability exists within the handling of specific data structures or function calls within `fdwsd.dll`, leading to memory corruption when processing malformed input. Successful…
