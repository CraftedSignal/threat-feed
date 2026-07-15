---
title: Suspicious File Renaming via SMB Indicating Remote Ransomware Activity
slug: 2026-07-ransomware-file-rename-smb
description: This threat brief details a high-severity detection rule that identifies remote ransomware activity on Windows systems, leveraging SMB to initiate rapid, high-entropy file renames by the System process (PID 4) on user-owned files, which often signifies data encryption for impact.
date: "2026-07-15T10:57:01Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ransomware
  - impact
  - lateral-movement
  - windows
  - endpoint
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: Identifies suspicious file rename operation by the virtual System process. This may indicate a remote ransomware attack via the SMB protocol. Do rename artifacts look like encryption instead of content conversion? Escalate when common documents or images move to one unfamiliar high-entropy extension family across many paths.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1486
    technique_name: Data Encrypted for Impact
    evidence: Identifies suspicious file rename operation by the virtual System process. This may indicate a remote ransomware attack via the SMB protocol. Do rename artifacts look like encryption instead of content conversion? Escalate when common documents or images move to one unfamiliar high-entropy extension family across many paths.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1490
    technique_name: Inhibit System Recovery
    evidence: Did recovery inhibition or destructive behavior align with the rename burst? Escalate and prioritize containment when these alerts align.
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
    evidence: Identifies suspicious file rename operation by the virtual System process. This may indicate a remote ransomware attack via the SMB protocol.
    confidence_band: high
references:
  - https://news.sophos.com/en-us/2023/12/21/akira-again-the-ransomware-that-keeps-on-taking/
rules:
  - title: Detect Suspicious File Renames via SMB Indicating Ransomware
    description: 'Detects suspicious file rename operations by the virtual System process (PID 4) on Windows, particularly when targeting user files via SMB with high-entropy extensions, indicative of remote ransomware activity. Note: This rule identifies individual suspicious events; full ransomware detection benefits from correlating multiple such events in quick succession.'
    platform: sigma
    severity: high
    tactics:
      - impact
      - lateral_movement
    techniques:
      - T1021.002
      - T1485
      - T1486
      - T1490
    data_sources:
      - file_event
      - windows
rules_count: 1
---

This detection rule, developed by Elastic, targets suspicious file rename operations on Windows systems that are highly indicative of remote ransomware attacks. The threat involves an attacker leveraging the Server Message Block (SMB) protocol to interact with a target host, initiating rapid file renaming activities. A key characteristic of this activity is the use of the virtual System process (PID 4) to perform these renames, often targeting common user-owned file types (e.g., .jpg, .pdf, .doc) located within `C:\Users\` directories. The files are renamed with new, high-entropy extensions within a very short timeframe (e.g., 3 renames in 1 second), signaling data encryption for impact or data destruction. While the rule itself is generic, such behavior has been observed in ransomware campaigns like Akira, as referenced by Sophos. This activity poses a critical risk by directly leading to data unavailability and operational disruption.

## Attack Chain

1. Attacker gains initial access to a network environment, potentially through compromised credentials or vulnerable services.
2. Attacker moves laterally, establishing remote access to a system with accessible SMB shares (e.g., SMB/Windows Admin Shares, T1021.002).
3. Ransomware payload (running on an attacker-controlled or compromised remote system) initiates commands to interact with the target host's file system via the SMB protocol.
4. The ransomware causes the target host's virtual System process (PID 4) to rapidly rename user-owned files within `C:\Users\` directories.
5. Common document and image file types (e.g., `*.jpg`, `*.pdf`, `*.doc`) are renamed, acquiring new, uncommon file extensions with high entropy.
6. This mass renaming and modification of file extensions effectively renders the data inaccessible, serving as data encryption for impact (T1486) or data destruction (T1485).
7. The final objective is to disrupt operations and potentially inhibit system recovery (T1490), leading to a ransom demand.

## Impact

The primary impact of this attack is the widespread encryption or destruction of user data on compromised Windows systems, leading to significant data loss and operational disruption. Affected organizations face critical downtime, potential financial losses from ransom payments, and costs associated with recovery and remediation efforts. The attack targets common file types in user directories, ensuring a broad impact on productivity. The rapid nature of the file renames makes detection and containment challenging, increasing the likelihood of extensive damage across the affected hosts. Successful attacks can also lead to reputational harm and potential regulatory fines if sensitive data is compromised or made unavailable.

## Recommendation

* Deploy the Sigma rule "Detect Suspicious File Renames via SMB Indicating Ransomware" to your SIEM and tune for your environment.
* Ensure endpoint logging for file rename events (category `file_event` on `windows` products) is enabled and comprehensive, including process PID, user IDs, file paths, and file hashes, to activate the rule.
* Investigate alerts from the Sigma rule, focusing on the `process.pid` of 4 and `user.id` to identify the source of the suspicious SMB activity.
* Review the `file.Ext.entropy` and `file.path` fields for patterns consistent with mass encryption, as described in the rule, and correlate with SMB `source.ip` and `user.id` to understand the attack's origin.
* Reference the Sophos article linked in the `references` section for additional insights into Akira ransomware tactics, which exhibit similar behaviors.
