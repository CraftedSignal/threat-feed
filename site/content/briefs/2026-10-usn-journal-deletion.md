---
title: Detection of USN Journal Deletion via FSUtil
slug: 2026-10-usn-journal-deletion
description: Detection of the deletion of the Windows Update Sequence Number (USN) Journal using the fsutil.exe utility to identify attempts by adversaries to hinder forensic investigations.
date: "2026-10-12T18:00:21Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - windows
  - forensics-tampering
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal
    evidence: The following analytic detects the deletion of the USN Journal using the fsutil.exe utility.
    confidence_band: high
rules:
  - title: Detect USN Journal Deletion via FSUtil
    description: Detects the deletion of the USN Journal using the fsutil.exe utility, a technique often used for defense evasion.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1070
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
    - action: Deploy detection rule for USN journal deletion.
      owner: Detection Engineering
      due: 48h
      evidence: Source provided logic for identifying this TTP.
  hunt_leads:
    - lead: Search for historical logs of fsutil process executions containing 'deletejournal' string.
      technique_id: T1070
      data_needed:
        - Process creation logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Technique is frequently used by attackers to hide tracks.
---

This threat brief focuses on the detection of the Windows Update Sequence Number (USN) Journal deletion, a technique frequently employed by threat actors to obfuscate malicious activity. The USN Journal is a critical NTFS feature that records changes made to files on a disk volume. By using the built-in Windows utility 'fsutil.exe' to delete the journal, attackers can effectively wipe historical file-modification logs, thereby complicating forensic analysis and incident response. This behavior is commonly associated with ransomware operations and general log manipulation tactics aimed at defense evasion. Detecting this activity is vital for identifying attackers attempting to cover their tracks during the post-exploitation phase of an intrusion.

## Attack Chain

1. An attacker gains administrative or SYSTEM-level access to a Windows endpoint.
2. The attacker identifies the need to clear forensic artifacts from the system.
3. The attacker opens a command shell (e.g., cmd.exe or PowerShell) with elevated privileges.
4. The attacker executes the 'fsutil' binary with the 'usn' and 'deletejournal' arguments against a target volume.
5. The Windows system processes the command, causing the NTFS driver to purge the USN Journal data.
6. The USN Journal is effectively deleted or reset, removing records of recent file system activity.
7. The attacker proceeds with additional malicious operations, such as data exfiltration or ransomware deployment, with a reduced footprint.

## Impact

Successful deletion of the USN Journal hinders the ability of security teams to perform accurate forensic reconstructions. This action prevents investigators from identifying the scope of file modifications, detecting unauthorized file access, or mapping the timeline of attacker activity. This technique is observed across various intrusion scenarios, particularly in ransomware campaigns where attackers aim to slow down detection and remediation efforts.

## Recommendation

* Deploy the Sigma rule provided below to your SIEM to monitor for 'fsutil.exe' command-line execution targeting the USN journal.
* Enable Sysmon Event ID 1 (Process Creation) to capture detailed command-line arguments, which is critical for identifying the 'deletejournal' flag.
* Monitor for any use of 'fsutil.exe' in an administrative context, as this utility is rarely used by standard system processes or typical users in a production environment.
