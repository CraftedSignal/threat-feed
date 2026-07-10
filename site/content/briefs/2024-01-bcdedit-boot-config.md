---
title: Modification of Boot Configuration using Bcdedit
slug: 2024-01-bcdedit-boot-config
description: Adversaries may modify the Boot Configuration Data (BCD) store using bcdedit.exe to disable recovery options, which is often associated with ransomware or destructive attacks, preventing system recovery.
date: "2024-01-03T14:27:00Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - impact
  - boot-configuration
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
  - https://attack.mitre.org/techniques/T1490/
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/impact_modification_of_boot_config.toml
rules:
  - title: Modification of Boot Configuration with Bcdedit
    description: Detects the use of bcdedit.exe to modify boot configuration to disable recovery options.
    platform: sigma
    severity: low
    tactics:
      - impact
    techniques:
      - T1490
    data_sources:
      - process_creation
      - windows
  - title: Bcdedit Execution from Suspicious Location
    description: Detects bcdedit.exe execution from unusual directories.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - impact
    techniques:
      - T1490
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers or malware may use `bcdedit.exe` to modify the boot configuration data (BCD) to disable Windows Error Recovery or to ignore boot failures. This action is often seen in destructive attacks, specifically associated with ransomware campaigns, to prevent the system from properly recovering after encryption or other malicious activity. By modifying the BCD, attackers aim to inhibit system recovery, making remediation more difficult and increasing the impact of their attack. The rule `69c251fb-a5d6-4035-b5ec-40438bd829ff` aims to identify this behavior.

## Attack Chain

1. Initial Access: The attacker gains access to the system through various methods, such as exploiting a vulnerability or using stolen credentials.
2. Privilege Escalation: The attacker escalates their privileges to administrator level to execute commands like `bcdedit.exe`.
3. Command Execution: The attacker executes `bcdedit.exe` with specific arguments to modify the boot configuration.
4. Disabling Recovery: The command `bcdedit.exe /set {default} recoveryenabled No` disables Windows Error Recovery.
5. Ignoring Boot Failures: The command `bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures` configures the system to ignore boot failures.
6. System Compromise: The attacker deploys ransomware or executes other destructive actions.
7. System Reboot: The system is rebooted, and the modified boot configuration prevents normal recovery processes.

## Impact

Successful modification of the boot configuration can lead to the inability to recover the system using standard recovery options. This can result in data loss, extended downtime, and increased costs associated with system restoration. This technique is often associated with ransomware attacks and can amplify their impact. The risk score associated with this activity is 21, as it severely hinders the ability to restore an impacted system.

## Recommendation

*   Enable Sysmon process creation logging to capture the execution of `bcdedit.exe` (Data Source: Sysmon).
*   Deploy the Sigma rule "Modification of Boot Configuration with Bcdedit" to your SIEM and tune for your environment.
*   Investigate any instance of `bcdedit.exe` being used to modify `bootstatuspolicy` or `recoveryenabled` (query).
*   Monitor Windows Security Event Logs for process creation events related to `bcdedit.exe` with the specified arguments (Data Source: Windows Security Event Logs).
*   Consider isolating any host where this activity is detected to prevent further destructive actions.
