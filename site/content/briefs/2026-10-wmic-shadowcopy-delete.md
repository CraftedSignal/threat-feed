---
title: Detection of WMIC Shadow Copy Deletion
slug: 2026-10-wmic-shadowcopy-delete
description: Ransomware actors, including the Cactus group, utilize the Windows Management Instrumentation Command-line (WMIC) utility to delete volume shadow copies to prevent system recovery.
date: "2026-10-12T18:25:39Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - ransomware
  - impact
  - wmic
  - windows
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1490
    technique_name: Inhibit System Recovery
    evidence: This analytic detects the use of WMIC to delete volume shadow copies, which is a common technique used by ransomware actors to prevent system recovery.
    confidence_band: high
rules:
  - title: Detect WMIC Shadow Copy Deletion
    description: Detects the use of WMIC to delete volume shadow copies, a technique commonly associated with ransomware.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1490
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
    - action: Deploy the Sigma rule provided in this brief.
      owner: Detection Engineering
      due: 24h
      evidence: This rule provides detection coverage for technique T1490.
  hunt_leads:
    - lead: Search for historical execution of wmic.exe with arguments 'shadowcopy' and 'delete' in the past 30 days.
      technique_id: T1490
      data_needed:
        - Endpoint process creation logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Ransomware actors often use this technique as a precursor to file encryption.
---

Ransomware actors frequently employ the Windows Management Instrumentation Command-line (WMIC) utility as a component of their post-exploitation operations to hinder incident response and recovery. Specifically, actors target Volume Shadow Copies, which are snapshots of system files, to ensure that victims cannot restore their data after encryption occurs. This behavior has been observed in campaigns attributed to groups such as Cactus and is categorized under MITRE ATT&CK technique T1490. Defenders should monitor for process execution of 'wmic.exe' utilizing specific command-line arguments that indicate the intent to delete shadow copies. While legitimate system maintenance may occasionally involve these commands, such activity is typically infrequent and performed via standardized administrative workflows, making this a high-fidelity signal for detecting potential ransomware preparation or malicious activity.

## Attack Chain

1. Initial access is established via compromised credentials or vulnerability exploitation.
2. The attacker performs internal reconnaissance to identify the environment and storage structures.
3. The attacker gains elevated privileges to execute administrative commands.
4. The attacker locates the WMIC utility at C:\Windows\System32\wbem\wmic.exe.
5. The attacker executes the command 'wmic shadowcopy delete' to destroy recovery snapshots.
6. The attacker may further disable Windows Defender or other security tools.
7. Encryption processes are initiated to lock files and exfiltrate sensitive data.
8. The final objective is reached: successful data encryption and impact on organizational operations.

## Impact

Successful deletion of volume shadow copies prevents the immediate recovery of encrypted files using built-in Windows functionality. This forces victims to rely on offline backups or pay the ransom demand. This technique is a hallmark of sophisticated ransomware groups targeting various enterprise sectors to maximize operational disruption.

## Recommendation

* Deploy the provided Sigma rule to monitor for suspicious process creation of 'wmic.exe' using command-line arguments related to shadow copy deletion.
* Ensure that Sysmon Event ID 1 (Process Create) is enabled across all Windows endpoints and that command-line logging is active.
* Investigate instances of this command triggered by non-administrative user accounts or unexpected parent processes.
* Prioritize the monitoring of this technique for servers housing critical infrastructure and sensitive data, as these are primary targets for ransomware actors.
* Audit administrative scripts that perform backup operations to establish a baseline and reduce false positives for the detection rule.
