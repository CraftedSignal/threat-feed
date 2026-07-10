---
title: Windows USN Journal Deletion via fsutil.exe
slug: 2024-01-30-usn-journal-deletion
description: Adversaries may delete the USN journal on Windows systems using `fsutil.exe` to remove evidence of file modifications and other activities, hindering forensic investigations and incident response.
date: "2024-01-30T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - defense-evasion
  - anti-forensics
  - windows
  - fsutil
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
    description: Detects the execution of fsutil.exe to delete the USN journal, a common anti-forensic technique.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1070.004
    data_sources:
      - process_creation
      - windows
  - title: Detect USN Journal Deletion via Fsutil (Alternate Location)
    description: Detects the execution of fsutil.exe from an unusual location to delete the USN journal.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1070.004
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers often attempt to cover their tracks after gaining access to a system. Deleting the USN Journal is one way to achieve this. The USN Journal, or Update Sequence Number Journal, is a feature in NTFS file systems that logs changes made to files and directories. This includes file creation, deletion, modifications, and permission changes. By deleting the USN Journal, attackers can remove a valuable source of forensic information that incident responders might use to reconstruct their actions. This brief focuses on the use of `fsutil.exe`, a legitimate Windows utility, to delete the USN Journal. While this activity alone is not necessarily indicative of compromise, it raises suspicion, especially when coupled with other anomalous behaviors.

## Attack Chain

1. An attacker gains initial access to a Windows system (e.g., via compromised credentials or exploiting a vulnerability).
2. The attacker elevates privileges to gain administrative access.
3. The attacker uses `fsutil.exe` with the `deletejournal` and `usn` parameters to delete the USN Journal on a specific volume. For example: `fsutil usn deletejournal /D C:`
4. The operating system processes the command, deleting the USN Journal metadata file for the specified volume.
5. The attacker continues post-exploitation activities, knowing that file system changes will not be recorded in the USN Journal.
6. The attacker may use other anti-forensic techniques to further conceal their activity, such as timestomping or file wiping.
7. The attacker achieves their final objective, such as data exfiltration, deploying ransomware, or establishing persistence.

## Impact

Successful deletion of the USN Journal hinders forensic investigations by removing a key source of information about file system changes. While the provided source does not indicate specific victim counts or sectors targeted, the impact of this activity is a reduced ability to track attacker actions on a compromised system. Incident responders may struggle to identify the full scope of the breach, the files accessed or modified, and the timeline of events. This can increase the time and resources required for incident response and remediation.

## Recommendation

*   Deploy the Sigma rule `Detect USN Journal Deletion via Fsutil` to your SIEM and tune for your environment to detect the use of `fsutil.exe` to delete the USN Journal.
*   Investigate any endpoint generating event ID 11 related to USN Journal deletion found in "Windows Security Event Logs".
*   Correlate detections of USN journal deletion with other suspicious behaviors on the endpoint.
*   Consider using a host-based intrusion detection system (HIDS) or endpoint detection and response (EDR) solution to monitor file system activity and detect suspicious behavior that may indicate an attempt to evade detection.
