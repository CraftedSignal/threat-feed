---
title: Abuse of CreateDump Utility for Credential Access
slug: 2026-09-createdump-lolbin
description: Adversaries are utilizing the legitimate Windows utility createdump.exe to perform unauthorized memory dumping, facilitating credential theft.
date: "2026-09-01T12:19:38Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - lolbin
  - credential-access
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003.001
    technique_name: 'OS Credential Dumping: LSASS Memory'
    evidence: The utility is used to dump process memory which typically includes LSASS to obtain credentials.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_createdump_lolbin_execution.yml
  - https://www.crowdstrike.com/blog/overwatch-exposes-aquatic-panda-in-possession-of-log-4-shell-exploit-tools/
rules:
  - title: Detect Suspicious createdump.exe Memory Dumping
    description: Detects the use of createdump.exe to dump process memory by checking for specific command-line flags used to trigger dump operations.
    platform: sigma
    severity: high
    tactics:
      - credential-access
    techniques:
      - T1003.001
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the provided Sigma rule to SIEM/EDR platforms.
      owner: Detection Engineering
      due: 48h
  hunt_leads:
    - lead: Search historical logs for execution of createdump.exe with flags matching the detection logic.
      technique_id: T1003.001
      data_needed:
        - Process creation logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Utility is a documented LOLBIN used for memory dumping.
---

The Windows utility createdump.exe, typically associated with the .NET runtime, is being leveraged by threat actors as a living-off-the-land binary (LOLBIN) to facilitate credential access. By invoking this utility, attackers can capture the memory contents of sensitive processes, such as lsass.exe, without triggering traditional file-based malware detections. The utility provides command-line arguments to specify the target process and output file, allowing for stealthy exfiltration of credentials. This technique is particularly effective in environments where .NET components are prevalent, as the binary is often present and trusted by security controls. Defenders should focus on process execution patterns associated with command-line flags that indicate memory dumping, rather than relying on binary reputation alone.

## Impact

Successful abuse of createdump.exe results in the unauthorized dumping of sensitive process memory, leading to the potential theft of credentials, tokens, or secret keys stored in volatile memory. This enables subsequent lateral movement, privilege escalation, and persistent access within a compromised Windows environment.

## Recommendation

Deploy the provided Sigma rule to identify suspicious executions of createdump.exe with dump-specific command-line arguments. Monitor for processes spawning createdump.exe where the target is a security-sensitive process like lsass.exe, and restrict the use of this utility to verified administrative or diagnostic workflows using application control solutions.
