---
title: Service Reconnaissance via WMIC.exe
slug: 2024-01-30-wmic-service-recon
description: Adversaries use WMIC.exe to enumerate running services on remote devices, potentially identifying valuable targets or misconfigured systems.
date: "2024-01-30T12:00:00Z"
severities:
  - medium
tags:
  - attack.execution
  - attack.t1047
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows 10
  - Windows 11
  - Windows Server 2019
  - Windows Server 2022
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1047
    technique_name: Windows Management Instrumentation
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1047/T1047.md
  - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wmic
  - https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-service
rules:
  - title: Detect Suspicious WMIC Service Enumeration
    description: Detects the execution of wmic.exe to enumerate services on remote hosts
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1047
    data_sources:
      - process_creation
      - windows
  - title: WMIC Reconnaissance with Specific Service Query
    description: Detects wmic.exe being used to specifically query for a service.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1047
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers may leverage the Windows Management Instrumentation Command-line (WMIC) tool for reconnaissance activities within a network. Specifically, WMIC can be used to query and retrieve information about services running on remote systems. By executing WMIC commands with the 'service' parameter, adversaries can identify the presence and status of specific services, potentially revealing vulnerable or misconfigured systems. This information can then be used to guide further exploitation…
