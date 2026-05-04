---
title: Windows USN Journal Deletion via Fsutil
slug: 2024-01-usn-journal-deletion
description: Adversaries may delete the volume USN Journal on Windows systems using `fsutil.exe` to eliminate evidence of post-exploitation file activity.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - defense-evasion
  - windows
  - fsutil
  - usn journal
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal
references:
  - https://attack.mitre.org/techniques/T1070/
  - https://attack.mitre.org/techniques/T1070/004/
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_delete_volume_usn_journal_with_fsutil.toml
rules:
  - title: Detect USN Journal Deletion via Fsutil
    description: Detects the execution of fsutil.exe with arguments to delete the USN journal.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1070.004
    data_sources:
      - process_creation
      - windows
  - title: Detect USN Journal Deletion via Fsutil (PE Metadata)
    description: Detects the execution of fsutil.exe with arguments to delete the USN journal by checking PE metadata.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1070.004
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers can use the `fsutil.exe` utility to delete the volume USN Journal in Windows. The USN Journal tracks changes made to files and directories on a disk volume, including metadata for file creation, deletion, modification, and permission changes. Deleting this journal can hinder forensic analysis by removing evidence of file operations. This technique is used to cover tracks and evade detection after an initial compromise. This activity is often observed during the post-exploitation phase of an attack, where adversaries attempt to remove traces of their presence and actions on the compromised system.

## Attack Chain

1. An attacker gains initial access to a Windows system.
2. The attacker executes `fsutil.exe` via command line.
3. The command `fsutil usn deletejournal /D [volume]` is used to delete the USN Journal on the specified volume.
4. The operating system processes the command, removing the USN Journal.
5. Subsequent file system activity is no longer recorded in the USN Journal.
6. The attacker performs further actions on the system, such as lateral movement or data exfiltration.
7. Forensic analysis is hampered due to the missing USN Journal entries.

## Impact

Successful deletion of the USN Journal impairs forensic investigations and incident response efforts. Without the USN Journal, analysts may struggle to determine the full scope of an intrusion, including files created, modified, or deleted by the attacker. This can lead to incomplete remediation and a higher risk of reinfection.

## Recommendation

*   Deploy the Sigma rule "Detect USN Journal Deletion via Fsutil" to your SIEM to identify this specific behavior.
*   Monitor process execution events for `fsutil.exe` with arguments related to "deletejournal" and "usn" to detect potential attempts to delete the USN Journal.
*   Enable Sysmon process creation logging to capture the execution of `fsutil.exe` with the relevant arguments.
