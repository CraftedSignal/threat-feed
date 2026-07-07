---
title: Abuse of Microsoft Sysinternals PsSuspend Utility
slug: 2026-07-sysinternals-pssuspend
description: Unidentified threat actors may leverage the legitimate Microsoft Sysinternals PsSuspend utility to suspend critical processes on Windows systems, enabling evasion of security controls or disruption of operations.
date: "2026-07-03T14:28:11Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - sysinternals
  - living-off-the-land
  - process-manipulation
  - windows
  - tool-abuse
vendors:
  - Microsoft
products:
  - Sysinternals PsSuspend
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1055
    technique_name: Process Injection
    evidence: Detects usage of Sysinternals PsSuspend which can be abused to suspend critical processes
    confidence_band: med
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1046
    technique_name: Network Service Discovery
    evidence: Detects usage of Sysinternals PsSuspend which can be abused to suspend critical processes
    confidence_band: med
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Detects usage of Sysinternals PsSuspend which can be abused to suspend critical processes
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Impact
    technique_id: T1499
    technique_name: Service Stop
    evidence: Detects usage of Sysinternals PsSuspend which can be abused to suspend critical processes
    confidence_band: med
references:
  - https://learn.microsoft.com/en-us/sysinternals/downloads/pssuspend
  - https://twitter.com/0gtweet/status/1638069413717975046
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_sysinternals_pssuspend_execution.yml
rules:
  - title: Sysinternals PsSuspend Execution
    description: Detects usage of Sysinternals PsSuspend, which can be abused to suspend critical processes, leading to evasion or disruption.
    platform: sigma
    severity: medium
    tactics:
      - discovery
      - evasion
      - persistence
      - privilege_escalation
    techniques:
      - T1036
      - T1046
      - T1055
      - T1543.003
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

The Microsoft Sysinternals PsSuspend utility, a legitimate command-line tool, allows administrators to suspend and resume processes on local or remote Windows systems. While designed for troubleshooting and system management, its capabilities can be abused by threat actors to halt critical security software, database services, or other essential applications, thereby disrupting operations or facilitating malicious activities like data exfiltration or ransomware deployment. This brief focuses on the detection of PsSuspend's execution as an indicator of potential abuse. The source material does not detail a specific attack campaign or actor, but highlights the tool's potential for misuse within a broader attack chain to achieve objectives like evasion, persistence, or denial of service.

## Impact

The successful abuse of PsSuspend can lead to significant operational disruption and security breaches. By suspending essential processes, attackers can disable endpoint detection and response (EDR) agents, anti-virus software, and other security controls, allowing them to operate undetected. It can also be used to pause critical business applications, leading to denial of service, data inconsistencies, or creating windows of opportunity for data exfiltration before legitimate processes can react. The impact could range from temporary service outages to complete system compromise if security tools are effectively bypassed.

## Recommendation

*   Enable process creation logging (e.g., via Sysmon) on all Windows endpoints to ensure the `process_creation` log source is available.
*   Deploy the "Sysinternals PsSuspend Execution" Sigma rule to your SIEM for detecting PsSuspend usage.
*   Monitor for process suspensions that are not part of approved administrative tasks.
*   Implement application whitelisting or strict controls over the execution of Sysinternals tools on sensitive systems.
