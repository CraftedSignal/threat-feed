---
title: UAT-4356 FIRESTARTER Backdoor Targeting Cisco Firepower Devices
slug: 2026-04-uat-4356-firestarter
description: UAT-4356 is actively targeting Cisco Firepower devices running FXOS, exploiting CVE-2025-20333 and CVE-2025-20362 to deploy the FIRESTARTER backdoor which allows remote access and control by injecting malicious shellcode into the LINA process.
date: "2026-04-23T15:11:53Z"
severities:
  - critical
actors:
  - UAT-4356
tags:
  - uat-4356
  - firestarter
  - cisco
  - backdoor
  - network
  - espionage
vendors:
  - Cisco
products:
  - Firepower eXtensible Operating System (FXOS)
  - ASA
  - FTD
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2025-20333
    cvss: 9.9
    epss: 0.24776
  - id: CVE-2025-20362
    cvss: 6.5
    epss: 0.43635
references:
  - https://blog.talosintelligence.com/uat-4356-firestarter/
ioc_counts:
  filename: 2
rules:
  - title: File Creation in Suspicious Directory
    description: Detects the creation of suspicious files often associated with the FIRESTARTER backdoor in directories commonly used by the malware.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1105
    data_sources:
      - file_event
      - linux
  - title: LINA Process Execution
    description: Detects the execution of the lina_cs process, which may indicate the presence of the FIRESTARTER backdoor.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Cisco Talos reported that UAT-4356 continues to actively target Cisco Firepower devices running the Firepower eXtensible Operating System (FXOS). In early 2024, Cisco Talos attributed the ArcaneDoor campaign to UAT-4356, a state-sponsored actor focused on gaining access to network perimeter devices for espionage. The actor exploits n-day vulnerabilities CVE-2025-20333 and CVE-2025-20362 to gain unauthorized access to vulnerable devices. Upon successful exploitation, UAT-4356 deploys a…
