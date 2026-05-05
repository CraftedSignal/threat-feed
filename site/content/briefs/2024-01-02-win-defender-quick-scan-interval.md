---
title: Windows Defender Quick Scan Interval Modification
slug: 2024-01-02-win-defender-quick-scan-interval
description: Detection of modifications to the Windows registry that change the Windows Defender Quick Scan Interval, potentially impairing its ability to detect malware promptly.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - windows-registry
  - windows-defender
  - endpoint
vendors:
  - Microsoft
  - Splunk
products:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Windows Defender
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://x.com/malmoeb/status/1742604217989415386?s=20
  - https://github.com/undergroundwires/privacy.sexy
rules:
  - title: Detect Windows Defender Quick Scan Interval Modification via Registry
    description: Detects modifications to the Windows Defender Quick Scan Interval by monitoring registry changes.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - registry_set
      - windows
  - title: Detect Windows Defender Quick Scan Interval Modification via PowerShell
    description: Detects modifications to the Windows Defender Quick Scan Interval using PowerShell.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This threat brief focuses on the modification of the Windows Defender Quick Scan Interval, a critical setting that dictates how frequently quick scans are performed. Attackers may attempt to modify this interval to significantly reduce the frequency of scans, creating a window of opportunity to deploy malware or conduct malicious activities without being detected by Windows Defender's default quick scans. This technique is a form of defense evasion, allowing threats to persist undetected on compromised systems. The activity is detected through monitoring of registry modifications related to the "QuickScanInterval" path within the Windows registry. Disabling or significantly increasing this interval can have severe consequences, potentially leading to widespread infection and data compromise.

## Attack Chain

1.  **Initial Access:** An attacker gains initial access to the system through various means, such as exploiting a software vulnerability, or social engineering.
2.  **Privilege Escalation:** The attacker escalates privileges to gain the necessary permissions to modify the Windows Registry, often using techniques like exploiting system vulnerabilities or leveraging misconfigured access controls.
3.  **Defense Evasion:** The attacker attempts to disable or modify the Windows Defender Quick Scan Interval to prevent detection of malicious activities.
4.  **Registry Modification:** The attacker modifies the "QuickScanInterval" registry value using tools such as `reg.exe` or PowerShell. The specific registry path targeted is `*\Windows Defender\Scan\QuickScanInterval`.
5.  **Persistence:** By disabling or extending the quick scan interval, the attacker ensures their malware or malicious activities can persist on the system without being detected by regular quick scans.
6.  **Malware Deployment:** With Windows Defender's quick scans effectively neutered, the attacker deploys additional malware or executes malicious scripts on the compromised system.
7.  **Lateral Movement:** The attacker leverages the compromised system to move laterally within the network, infecting other systems and expanding their foothold.

## Impact

Successful modification of the Windows Defender Quick Scan Interval can lead to a significant reduction in the system's ability to detect malware promptly. This can result in widespread infection, data breaches, and system compromise. The consequences include potential financial losses, reputational damage, and disruption of business operations. While the exact number of victims is difficult to quantify, the potential impact is significant, especially within organizations heavily reliant on Windows Defender as their primary security solution.

## Recommendation

*   Enable Sysmon Event ID 13 logging to monitor registry modifications as described in the data source of the detection search.
*   Deploy the provided Splunk search to identify modifications to the Windows Defender Quick Scan Interval.
*   Investigate any detected modifications to the `QuickScanInterval` registry path to determine if they are legitimate or malicious.
*   Tune the provided filter macro `windows_impair_defense_change_win_defender_quick_scan_interval_filter` to reduce false positives in your environment.
*   Monitor for processes modifying the registry key `*\Windows Defender\Scan\QuickScanInterval` using tools like `reg.exe` or PowerShell.
