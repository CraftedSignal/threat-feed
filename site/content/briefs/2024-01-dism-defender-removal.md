---
title: Windows DISM Used to Remove Windows Defender
slug: 2024-01-dism-defender-removal
description: The analytic detects the use of `dism.exe` to remove Windows Defender, potentially allowing adversaries to evade detection and carry out further malicious actions.
date: "2024-01-03T14:22:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - endpoint
  - windows
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
  - https://thedfirreport.com/2020/11/23/pysa-mespinoza-ransomware/
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_dism_remove_defender.yml
rules:
  - title: Detect DISM Usage to Remove Windows Defender
    description: Detects the execution of dism.exe with parameters used to remove Windows Defender.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - windows
  - title: Detect DISM Usage by Non-System Account
    description: Detects the execution of dism.exe with parameters used to remove Windows Defender by user account instead of system account.
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

This threat brief addresses the use of Deployment Image Servicing and Management (DISM) to remove Windows Defender. Adversaries may attempt to disable or remove Windows Defender to evade detection and carry out further malicious actions undetected. This activity is significant because a disabled Defender can lead to persistent access, execution of additional payloads, and exfiltration of sensitive data without interruption. The original Splunk ES/CU analytic was published in May 2026, highlighting the continued relevance of this technique. This brief provides updated detection guidance for security teams.

## Attack Chain

1.  An attacker gains initial access to the target system (e.g., via compromised credentials or exploiting a vulnerability).
2.  The attacker executes `dism.exe` with specific parameters to disable features.
3.  The command includes the `/online` parameter to operate on the running operating system.
4.  The command includes `/disable-feature` to disable a specific feature.
5.  The `featurename:Windows-Defender` parameter targets the Windows Defender feature for removal.
6.  The command includes the `/remove` parameter to completely remove the targeted feature.
7.  With Windows Defender removed, the attacker executes malicious payloads without immediate detection.
8.  The attacker achieves their objective, such as data exfiltration, lateral movement, or ransomware deployment.

## Impact

Successful removal of Windows Defender can lead to complete compromise of the affected endpoint.  An attacker gains the ability to execute any malicious code without triggering antivirus alerts, leading to data theft, system compromise, or ransomware deployment.  The referenced DFIR Report (2020) describes a similar technique used in Pysa/Mespinoza ransomware attacks, indicating that real-world actors employ this evasion strategy.

## Recommendation

*   Deploy the Sigma rule `Detect DISM Usage to Remove Windows Defender` to your SIEM and tune for your environment to detect the execution of `dism.exe` with parameters used to remove Windows Defender.
*   Enable Sysmon process-creation logging (Event ID 1) to provide the necessary data for the Sigma rule.
*   Investigate any instances of `dism.exe` executing with command-line arguments containing `/online`, `/disable-feature`, `Windows-Defender`, and `/remove` to identify potential malicious activity.
