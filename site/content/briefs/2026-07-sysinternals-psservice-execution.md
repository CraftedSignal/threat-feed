---
title: Detection of Sysinternals PsService Execution
slug: 2026-07-sysinternals-psservice-execution
description: This brief details the detection of Sysinternals PsService, a legitimate utility that can be abused by threat actors for service reconnaissance, manipulation, and persistence on Windows systems, potentially leading to privilege escalation or system disruption.
date: "2026-07-03T14:27:18Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - sysinternals
  - process-execution
  - service-manipulation
  - windows
vendors:
  - Microsoft
products:
  - Sysinternals PsService
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1543
    technique_name: Create or Modify System Process
    evidence: Detects usage of Sysinternals PsService which can be abused for service reconnaissance and tampering. PsService can be used to modify Windows services, a common method for privilege escalation.
    confidence_band: med
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
    evidence: Detects usage of Sysinternals PsService which can be abused for service reconnaissance. PsService can query services to understand the environment.
    confidence_band: med
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
    evidence: Detects usage of Sysinternals PsService which can be abused for service tampering. PsService can be used to create or modify services to maintain persistence.
    confidence_band: med
references:
  - https://learn.microsoft.com/en-us/sysinternals/downloads/psservice
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_sysinternals_psservice.yml
rules:
  - title: Sysinternals PsService Execution
    description: Detects usage of Sysinternals PsService which can be abused for service reconnaissance, persistence, and tampering, potentially leading to privilege escalation.
    platform: sigma
    severity: medium
    tactics:
      - discovery
      - persistence
      - privilege_escalation
    techniques:
      - T1543.003
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

Sysinternals PsService is a command-line utility for Windows systems that allows users, typically administrators, to view and control services. While a legitimate tool for system management, it can be leveraged by malicious actors post-compromise for various nefarious activities. Threat actors can use PsService to enumerate running services for discovery (TA0007), stop critical services to disrupt operations, start malicious services for persistence (TA0003), or modify service configurations to achieve privilege escalation (TA0004). The execution of this tool, especially from unusual directories or by non-administrative accounts, is a strong indicator of potential malicious activity. Defenders should be aware of its legitimate uses versus its potential for abuse in the hands of an attacker to identify anomalous behavior.

## Attack Chain

This detection brief focuses on the execution of a specific tool, Sysinternals PsService, which can be used at various stages of an attack. The source material does not provide a full, observed attack chain from initial access to impact. Therefore, this section is omitted as per quality requirements.

## Impact

The abuse of Sysinternals PsService can lead to significant impact depending on how an attacker utilizes it. If used for reconnaissance, it facilitates further lateral movement or targeting of critical systems. If used to stop or disable essential services, it can cause severe disruption to business operations, leading to downtime and data loss. Modifying services can grant attackers elevated privileges, allowing them to install persistent backdoors or execute arbitrary code with SYSTEM rights, compromising the integrity and confidentiality of the affected system and potentially the entire network.

## Recommendation

*   Deploy the provided "Sysinternals PsService Execution" Sigma rule to your SIEM solution to detect instances of `PsService.exe` execution.
*   Enable process creation logging, such as via Sysmon, to ensure the necessary `Image` and `OriginalFileName` fields are captured for the Sigma rule.
*   Investigate alerts from the "Sysinternals PsService Execution" rule, paying close attention to the parent process, command-line arguments, and the user context of the execution.
*   Review legitimate uses of PsService within your environment and consider whitelisting known legitimate execution paths or users if false positives occur, as highlighted in the rule's `falsepositives` field.
