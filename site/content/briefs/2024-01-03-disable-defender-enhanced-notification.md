---
title: Windows Defender Enhanced Notification Disabled via Registry Modification
slug: 2024-01-03-disable-defender-enhanced-notification
description: An attacker modifies the Windows Registry to disable Windows Defender's Enhanced Notification feature, preventing users from receiving security alerts and potentially allowing malicious activities to go unnoticed, ultimately enabling persistence and evasion.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - registry-modification
  - windows-defender
  - persistence
  - evasion
vendors:
  - Microsoft
  - Splunk
products:
  - Windows Defender
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/disable_defender_enhanced_notification.yml
rules:
  - title: Registry Modification to Disable Defender Enhanced Notifications
    description: Detects modification of the registry to disable Windows Defender's Enhanced Notification feature.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - registry_set
      - windows
  - title: Process Modifying Defender Reporting Registry Key
    description: Detects a process modifying the Windows Defender reporting registry key.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This brief focuses on the technique of disabling Windows Defender's Enhanced Notifications through registry modification. Attackers may target this feature to suppress security alerts, allowing malicious activities to proceed without user or administrator awareness. The observed behavior involves modifying the registry key `HKLM\SOFTWARE\Microsoft\Windows Defender\Reporting` and setting the `DisableEnhancedNotifications` value to `0x00000001`. This technique has been observed in conjunction with malware campaigns such as IcedID and XingLocker ransomware, documented in reports like TheDFIRReport's analysis of IcedID leading to XingLocker ransomware within 24 hours. This allows threat actors to bypass detection mechanisms and escalate their activities within a compromised environment.

## Attack Chain

1.  Initial compromise of the system, potentially through phishing or exploit of a vulnerability.
2.  Establish persistence, possibly through registry modifications or scheduled tasks.
3.  The attacker executes a process with sufficient privileges to modify the Windows Registry.
4.  The process modifies the registry key `HKLM\SOFTWARE\Microsoft\Windows Defender\Reporting`.
5.  The value `DisableEnhancedNotifications` is set to `0x00000001`, disabling enhanced notifications.
6.  Windows Defender no longer displays enhanced notifications, hiding security alerts from the user.
7.  The attacker performs malicious activities, such as lateral movement or data exfiltration, without triggering user alerts.
8.  The attacker achieves their final objective, such as deploying ransomware or stealing sensitive data.

## Impact

Disabling Windows Defender Enhanced Notifications can significantly reduce the visibility of malicious activities on a compromised system. This can lead to delayed detection and increased dwell time for attackers. In scenarios like the IcedID and XingLocker ransomware attacks, this delayed detection can enable rapid ransomware deployment, resulting in data encryption, system downtime, and potential financial losses. This technique undermines the effectiveness of Windows Defender as a primary security control, leading to a greater risk of successful attacks.

## Recommendation

*   Enable Sysmon Event ID 13 logging to monitor registry modifications.
*   Deploy the Sigma rule "Registry Modification to Disable Defender Enhanced Notifications" to your SIEM and tune for your environment.
*   Investigate any endpoint registry modifications to `*Microsoft\\Windows Defender\\Reporting*` and `DisableEnhancedNotifications` using endpoint detection and response (EDR) logs.
*   Correlate detections of disabled Defender notifications with other suspicious activities, such as lateral movement or credential dumping, to identify potential compromises.
