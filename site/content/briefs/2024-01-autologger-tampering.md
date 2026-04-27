---
title: Windows AutoLogger Session Tampering Detection
slug: 2024-01-autologger-tampering
description: Attackers may disable AutoLogger sessions by modifying specific registry values to evade detection and prevent security monitoring of early boot activities and system events, a technique observed in intrusions involving IcedID and XingLocker ransomware.
date: "2024-01-03T15:00:00Z"
severities:
  - high
exploited: true
tags:
  - attack.defense-evasion
  - attack.t1562.002
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows 10
  - Windows 11
  - Windows Server 2016
  - Windows Server 2019
  - Windows Server 2022
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://twitter.com/MichalKoczwara/status/1553634816016498688
  - https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/
  - https://i.blackhat.com/EU-21/Wednesday/EU-21-Teodorescu-Veni-No-Vidi-No-Vici-Attacks-On-ETW-Blind-EDRs.pdf
  - https://learn.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-an-autologger-session
  - https://blog.palantir.com/tampering-with-windows-event-tracing-background-offense-and-defense-4be7ac62ac63
rules:
  - title: Potential AutoLogger Sessions Tampering
    description: Detects tampering with autologger trace sessions which is a technique used by attackers to disable logging.
    platform: sigma
    severity: high
    tactics:
      - defense-evasion
    techniques:
      - T1562.002
    data_sources:
      - registry_set
      - windows
  - title: Suspicious Wevtutil Usage to Disable Autologger
    description: Detects suspicious usage of wevtutil.exe to disable autologger sessions
    platform: sigma
    severity: medium
    tactics:
      - defense-evasion
    techniques:
      - T1562.002
    data_sources:
      - process_creation
      - windows
  - title: Tampering of Defender Autologger via Registry
    description: Detects tampering with Defender Autologger sessions through registry modifications.
    platform: sigma
    severity: high
    tactics:
      - defense-evasion
    techniques:
      - T1562.002
    data_sources:
      - registry_set
      - windows
rules_count: 3
---

Attackers are increasingly targeting Windows Event Tracing (ETW) and AutoLogger sessions to evade detection. The AutoLogger session is crucial as it records events early in the operating system boot process, providing security solutions with essential telemetry. This technique involves tampering with registry keys associated with AutoLogger sessions, specifically disabling or stopping them by setting DWORD values to 0. This is done to blind security solutions, preventing them from monitoring…
