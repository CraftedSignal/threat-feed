---
title: Windows Data Destruction via Recursive Executable File Deletion
slug: 2024-01-recursive-exec-deletion
description: A suspicious process recursively deleting executable files (e.g., .exe, .sys, .dll) indicates potential data destruction activity, detected via high-volume file deletion/overwrite events associated with destructive malware families like CaddyWiper and SwiftSlicer.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - data-destruction
  - wiper
  - sysmon
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
references:
  - https://www.welivesecurity.com/2023/01/27/swiftslicer-new-destructive-wiper-malware-ukraine/
rules:
  - title: Detect Recursive Executable File Deletion via Sysmon Events
    description: Detects a process rapidly deleting executable files based on Sysmon Event Codes 23 and 26, indicative of data destruction attempts.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - file_event
      - windows
  - title: Detect High-Volume Executable File Deletion within a Short Timespan
    description: Identifies a process deleting a high number of executable files within a short timeframe (2 minutes), suggesting malicious data destruction activity.
    platform: sigma
    severity: critical
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - file_event
      - windows
rules_count: 2
---

This brief addresses a critical threat involving the rapid and recursive deletion of executable files on Windows systems, a tactic often employed by destructive malware to render systems inoperable and hinder recovery efforts. The activity is detected by monitoring for a high volume of file deletion or overwrite events targeting files with extensions like .exe, .sys, and .dll. This technique is associated with malware families such as CaddyWiper, DoubleZero, and SwiftSlicer. The detection relies on Sysmon Event Codes 23 (FileDelete) and 26 (FileDeleteDetected), triggered by processes rapidly deleting or overwriting executable files. Defenders should prioritize investigations into processes exhibiting this behavior, as it often precedes or accompanies other malicious activities, potentially leading to significant data loss and system instability. The provided Sigma rules are designed to detect this behavior based on process activity and can be deployed to identify potentially compromised hosts.

## Attack Chain

1.  The attacker gains initial access to the target system through an unkown means.
2.  The attacker deploys a wiper malware such as SwiftSlicer onto the compromised host.
3.  The wiper malware executes, initiating a process that begins recursively deleting files.
4.  The malware targets executable files with extensions .exe, .sys, and .dll to cause maximum system damage and prevent recovery.
5.  Sysmon Event Code 23 (FileDelete) logs each file deletion event.
6.  Sysmon Event Code 26 (FileDeleteDetected) logs the event if file deletion is detected.
7.  A high volume of these events within a short timeframe indicates suspicious data destruction activity.
8.  The system becomes unstable and potentially inoperable, leading to significant disruption.

## Impact

Successful execution of this attack can lead to severe consequences, including data loss, system instability, and complete system inoperability. Confirmed infections involving similar wipers have resulted in significant disruption to victim organizations. While the number of victims and specific sectors targeted varies depending on the wiper campaign, the potential for widespread damage is high. Organizations that fall victim to such attacks face extended downtime, costly recovery efforts, and potential reputational damage.

## Recommendation

*   Enable Sysmon Event ID 23 (FileDelete) and 26 (FileDeleteDetected) logging to detect file deletion events on endpoints.
*   Deploy the provided Sigma rules to your SIEM to detect suspicious recursive deletion of executable files. Tune the threshold (count >= 100) based on your environment to minimize false positives.
*   Investigate any alerts triggered by the Sigma rules, focusing on the process name and path involved in the file deletion activity.
*   Implement application control policies to restrict the execution of unauthorized or unknown applications that may be used for malicious file deletion.
*   Review and harden file access permissions to prevent unauthorized modification or deletion of critical system files.
*   Monitor for uninstallation of large software or use of `cleanmgr.exe`, as these actions can trigger false positives, and implement appropriate filtering based on observed benign activity.
