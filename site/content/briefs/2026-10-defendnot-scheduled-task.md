---
title: Defendnot HackTool Scheduled Task Persistence and Defense Impairment
slug: 2026-10-defendnot-scheduled-task
description: The Defendnot hacktool utilizes a custom scheduled task for persistence and abuses the Windows Security Center API to register itself as a fake antivirus product to disable Windows Defender.
date: "2026-10-19T08:54:06Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - hacktool
  - persistence
  - defense-impairment
  - security-center
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: During installation, Defendnot creates a scheduled task named 'defendnot' with the argument '--from-autorun' for persistence.
    confidence_band: high
rules:
  - title: Detect Defendnot Scheduled Task Creation
    description: Detects the creation or update of the 'defendnot' scheduled task used by the Defendnot hacktool for persistence.
    platform: sigma
    severity: high
    tactics:
      - defense-impairment
      - execution
      - persistence
    techniques:
      - T1053.005
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection rule to SIEM and tune for environment.
      owner: Detection Engineering
      due: 24h
      evidence: Source provides specific task name and EIDs for detection.
  hunt_leads:
    - lead: Search for TaskName 'defendnot' in system logs.
      technique_id: T1053.005
      data_needed:
        - Security Event Logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Tool uses a hardcoded task name 'defendnot'.
---

Defendnot is a hacktool designed to facilitate the impairment of Windows Defender by abusing undocumented Windows Security Center (WSC) APIs. By masquerading as an installed antivirus security provider, the tool tricks the operating system into disabling the legitimate Windows Defender service. This capability significantly lowers the security posture of compromised hosts. To maintain its foothold, the tool utilizes a persistent scheduled task configuration. Security operations teams should prioritize monitoring for the creation of this specific scheduled task, as it serves as a reliable indicator of Defendnot deployment and potential unauthorized security configuration changes on Windows endpoints.

## Attack Chain

1. An attacker gains initial access to a Windows system and drops the Defendnot binary.
2. The binary executes and invokes undocumented WSC APIs to register itself as a security provider.
3. The registration process identifies the tool as an active antivirus engine, prompting Windows to disable Windows Defender.
4. The tool executes a schtasks command or API call to create a scheduled task named 'defendnot'.
5. The scheduled task is configured with the argument '--from-autorun' to ensure persistence across reboots.
6. The system schedules the task to run the binary repeatedly, ensuring the malicious security provider registration remains active.
7. Windows Defender remains incapacitated, allowing subsequent stages of the attack or unauthorized activity to proceed without interference.

## Impact

Successful execution of Defendnot leads to the disabling of Windows Defender, leaving the affected system vulnerable to further exploitation, malware infection, and data exfiltration. The tool directly impairs the host's primary defense-in-depth mechanism. While specific victim counts are not reported, this tool is categorized as a high-risk security impairment utility suitable for post-exploitation persistence and stealth.

## Recommendation

* Deploy the provided Sigma rule to detect the creation of the 'defendnot' scheduled task via Security event logs (EID 4698/4702).
* Use EDR or forensic tooling to hunt for the presence of the 'defendnot' binary and any associated task registrations.
* Audit security provider registrations using the Windows Security Center API to identify unauthorized or rogue antivirus entries.
* Block the execution of unsigned or unrecognized security-related utilities that interact with the WSC service.
