---
title: Payouts King Ransomware Abusing QEMU VMs for Defense Evasion
slug: 2026-04-payouts-king-qemu
description: The Payouts King ransomware is leveraging QEMU VMs as a reverse SSH backdoor to execute payloads, store malicious files, and establish covert remote access tunnels, bypassing endpoint security measures.
date: "2026-04-18T12:00:00Z"
severities:
  - critical
actors:
  - GOLD ENCOUNTER
tags:
  - payouts-king
  - ransomware
  - qemu
  - vm
  - defense-evasion
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053.005
    technique_name: 'Scheduled Task/Job: Scheduled Task'
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1622
    technique_name: Masquerade Task or Service
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003.001
    technique_name: 'OS Credential Dumping: LSASS Memory'
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1574.002
    technique_name: 'Hijack Execution Flow: DLL Side-Loading'
cves:
  - id: CVE-2025-26399
    cvss: 9.8
    epss: 0.26563
references:
  - https://www.bleepingcomputer.com/news/security/payouts-king-ransomware-uses-qemu-vms-to-bypass-endpoint-security/
ioc_counts:
  cve: 1
rules:
  - title: Detect QEMU Process Creation
    description: Detects the execution of QEMU processes, which may indicate malicious use of virtualization for defense evasion.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1622
    data_sources:
      - process_creation
      - windows
  - title: Detect ADNotificationManager Sideloading Havoc C2
    description: Detects the use of ADNotificationManager.exe to sideload the Havoc C2 payload (vcruntime140_1.dll).
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1574.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The Payouts King ransomware, associated with the GOLD ENCOUNTER threat group, is utilizing QEMU, an open-source CPU emulator, to run hidden Alpine Linux virtual machines (VMs) on compromised Windows systems, effectively bypassing endpoint security solutions. This technique allows attackers to execute malicious payloads, store sensitive data, and create covert remote access tunnels over SSH without being detected by host-based security tools. Observed since November 2025 (tracked as STAC4713)…
