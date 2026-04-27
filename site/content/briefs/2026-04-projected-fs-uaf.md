---
title: 'CVE-2026-32078: Windows Projected File System Use-After-Free Elevation of Privilege'
slug: 2026-04-projected-fs-uaf
description: A use-after-free vulnerability, CVE-2026-32078, exists in the Windows Projected File System, allowing a locally authenticated attacker to escalate privileges.
date: "2026-04-15T12:00:00Z"
severities:
  - high
tags:
  - cve-2026-32078
  - privilege-escalation
  - windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-32078
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32078
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32078
rules:
  - title: Detect Potential CVE-2026-32078 Exploitation via Unusual ProjFS Child Processes
    description: Detects potential exploitation attempts of CVE-2026-32078 by monitoring for unusual child processes spawned by ProjFS.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
      - T1611
    data_sources:
      - process_creation
      - windows
  - title: Detect Potential CVE-2026-32078 Exploitation via Unexpected Network Connections from ProjFS
    description: Detects potential exploitation attempts of CVE-2026-32078 by monitoring for network connections initiated by ProjFS.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
      - T1611
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CVE-2026-32078 is a use-after-free vulnerability affecting the Windows Projected File System. This vulnerability allows a locally authenticated attacker to elevate their privileges on a vulnerable system. The vulnerability exists because the Projected File System improperly handles memory operations. Exploitation of this flaw allows an attacker to execute arbitrary code with elevated privileges. Successful exploitation requires an attacker to have valid credentials on the local system and the…
