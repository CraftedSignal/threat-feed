---
title: Barracuda RMM Privilege Escalation via Filesystem ACLs
slug: 2024-01-barracuda-privesc
description: Barracuda RMM versions prior to 2025.2.2 are vulnerable to local privilege escalation, allowing attackers to gain SYSTEM privileges by exploiting overly permissive filesystem ACLs on the C:\Windows\Automation directory.
date: "2026-04-15T21:17:04Z"
severities:
  - critical
tags:
  - privilege-escalation
  - rmm
  - windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-22676
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-22676
rules:
  - title: Detect File Modification in Barracuda Automation Directory
    description: Detects file modifications within the C:\Windows\Automation directory, indicative of potential privilege escalation attempts targeting Barracuda RMM.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - file_event
      - windows
  - title: Detect Execution from Barracuda Automation Directory
    description: Detects process execution from the C:\Windows\Automation directory, which may indicate exploitation of the Barracuda RMM privilege escalation.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1059.001
      - T1068
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Barracuda RMM versions prior to 2025.2.2 contain a critical privilege escalation vulnerability (CVE-2026-22676). A local attacker can exploit overly permissive filesystem ACLs on the C:\\Windows\\Automation directory to achieve SYSTEM-level privileges. By modifying existing automation content or placing malicious, attacker-controlled files within this directory, the attacker can leverage the built-in automation functionality of Barracuda RMM. These files are then executed with NT…
