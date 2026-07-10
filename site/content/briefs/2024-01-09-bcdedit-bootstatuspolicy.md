---
title: Ransomware Attempting to Disable Windows Recovery via Bcdedit
slug: 2024-01-09-bcdedit-bootstatuspolicy
description: This brief details the detection of ransomware actors using bcdedit.exe to modify boot settings, specifically disabling automatic repair mode to hinder system recovery.
date: "2024-01-09T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ransomware
  - bootkit
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1490
    technique_name: Inhibit System Recovery
references:
  - https://jsac.jpcert.or.jp/archive/2020/pdf/JSAC2020_1_tamada-yamazaki-nakatsuru_en.pdf
rules:
  - title: Detect Bcdedit Modification of Boot Status Policy
    description: Detects the execution of bcdedit.exe to modify the boot status policy, potentially disabling automatic repair mode.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1490
    data_sources:
      - process_creation
      - windows
  - title: Detect Bcdedit Setting Recovery Enabled to No
    description: Detects the execution of bcdedit.exe to disable recovery environment.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1490
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This analytic detects the execution of `bcdedit.exe` with parameters to set the boot status policy to ignore all failures. This technique is often employed by ransomware actors to prevent compromised machines from booting into automatic repair mode, which would otherwise aid in recovery efforts. By disabling automatic repair, attackers aim to maintain persistent control over the infected system, complicating remediation and potentially leading to further data exfiltration, lateral movement, or other malicious activities. The detection focuses on identifying command-line arguments used with `bcdedit.exe` that modify the boot status policy to ignore all failures. This behavior, while potentially legitimate in certain administrative contexts, is a strong indicator of ransomware activity when observed in conjunction with other suspicious events.

## Attack Chain

1. Initial compromise of the system through an unknown vector (e.g., spear phishing, exploitation of a vulnerability).
2. Execution of a malicious payload on the compromised system.
3. The malicious payload gains elevated privileges (if necessary) on the system.
4. The payload executes `bcdedit.exe` with specific parameters to disable automatic repair mode using the `bootstatuspolicy` and `ignoreallfailures` flags. For example, `bcdedit /set {default} bootstatuspolicy ignoreallfailures`.
5. The system is then either encrypted directly by the ransomware or prepared for encryption in a later stage.
6. If encryption is successful, the ransomware may delete shadow copies or other backups to further hinder recovery, often using `vssadmin.exe`.
7. The system is rendered unusable, and a ransom note is displayed, demanding payment for decryption.
8. The attacker maintains persistence on the system by preventing automatic repair, ensuring continued access if the system is rebooted without remediation.

## Impact

Successful execution of this attack results in the compromised system being rendered unbootable into recovery mode, significantly hindering restoration efforts. Victims are forced to rely on external backups or professional data recovery services, leading to potential data loss, significant downtime, and financial repercussions. The disruption can impact individual users, businesses, and critical infrastructure, depending on the scope of the ransomware campaign. Prevention of automatic repair mode increases the likelihood of ransom payment.

## Recommendation

*   Deploy the Sigma rule "Detect Bcdedit Modification of Boot Status Policy" to your SIEM and tune for your environment.
*   Enable Sysmon process-creation logging (Event ID 1) to capture the necessary command-line arguments for the detection rule.
*   Investigate any instances of `bcdedit.exe` being executed with parameters related to `bootstatuspolicy` and `ignoreallfailures`.
*   Correlate detections with other endpoint telemetry to identify potential ransomware activity.
*   Implement application control policies to restrict the execution of `bcdedit.exe` to authorized users and processes.
*   Review and harden boot configuration security policies to prevent unauthorized modifications.
