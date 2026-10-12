---
title: Detection of Shadow Copy Deletion via System Utilities
slug: 2026-10-shadow-copy-deletion
description: Detection of unauthorized deletion of Volume Shadow Copies using native Windows utilities vssadmin.exe or wmic.exe, a common technique employed by ransomware actors to prevent system recovery.
date: "2026-10-12T17:38:57Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - impact
  - ransomware
  - windows
  - e-crime
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1490
    technique_name: Inhibit System Recovery
    evidence: The analytic detects the deletion of shadow copies using the vssadmin.exe or wmic.exe utilities.
    confidence_band: high
rules:
  - title: Detect Shadow Copy Deletion
    description: Detects the deletion of volume shadow copies using vssadmin.exe or wmic.exe as part of an attempt to prevent system recovery
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
    - action: Deploy Sigma rule to SIEM to detect shadow copy deletion commands
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific command-line indicators for T1490
  hunt_leads:
    - lead: Search for past executions of vssadmin or wmic with 'delete shadow' in command-line arguments
      technique_id: T1490
      data_needed:
        - Process creation logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: This activity is a common indicator of ransomware activity
  mitigation_plan:
    - priority: short_term
      action: Restrict access to administrative utilities to authorized service accounts
      owner: IT Operations
      addresses: T1490
      evidence: Restricting utility access prevents unauthorized use of vssadmin for impact
---

The unauthorized deletion of Volume Shadow Copies is a prevalent technique used by ransomware operators and advanced persistent threat (APT) actors to hinder incident response and system restoration efforts. By leveraging legitimate, pre-installed Windows utilities such as vssadmin.exe and wmic.exe, attackers can effectively destroy local backups of files. This behavior is a hallmark of numerous ransomware families, including LockBit, Clop, Black Basta, Rhysida, and others. Security teams should monitor for the execution of these utilities with specific command-line arguments involving the deletion of shadow storage. Because these tools are also used by system administrators for legitimate maintenance, it is essential to baseline environment-specific behaviors to differentiate malicious activity from standard management tasks.

## Attack Chain

1. Initial access is established on the Windows host via spearphishing, exploit, or credential abuse.
2. The attacker gains sufficient privileges to interact with system management utilities.
3. The attacker executes a discovery phase to locate existing volume shadow copies.
4. The attacker invokes vssadmin.exe or wmic.exe with specific parameters to target the shadow storage.
5. The utility processes the deletion command, effectively purging backup snapshots from the disk.
6. The attacker may then proceed to encrypt files, overwrite data, or deploy secondary payloads.
7. The final objective is reached when the victim is unable to restore data from local snapshots, increasing pressure to pay a ransom.

## Impact

Successful deletion of shadow copies eliminates the ability for victims to perform simple, local restoration of encrypted or stolen data. This activity is frequently the precursor to a broader ransomware event, leading to significant operational disruption, data loss, and exfiltration. This TTP has been observed across various sectors and is a standard component of major ransomware operations, often occurring just before the encryption phase of an attack.

## Recommendation

* Deploy the Sigma rule provided in this brief to detect the usage of vssadmin.exe and wmic.exe for shadow copy deletion.
* Enable Sysmon process-creation logging (Event ID 1) or Windows Security event logging (Event ID 4688) to capture complete command-line arguments.
* Configure SIEM alerts to trigger specifically on process executions where the command line contains both 'delete' and 'shadow' keywords.
* Investigate occurrences of this activity to determine if the deletion was performed by a known administrator or an unauthorized process, especially if the parent process is unexpected.
