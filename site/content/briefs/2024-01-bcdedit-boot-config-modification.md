---
title: Detection of Bcdedit Boot Configuration Modification
slug: 2024-01-bcdedit-boot-config-modification
description: This rule identifies the use of bcdedit.exe to modify boot configuration data, which may be indicative of a destructive attack or ransomware activity aimed at inhibiting system recovery by disabling error recovery or ignoring boot failures.
date: "2024-01-03T15:30:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - boot-configuration
  - bcdedit
  - impact
  - windows
vendors:
  - Microsoft
  - Crowdstrike
  - SentinelOne
  - Elastic
products:
  - Microsoft Defender XDR
  - SentinelOne Cloud Funnel
  - Elastic Defend
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1490
    technique_name: Inhibit System Recovery
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/impact_modification_of_boot_config.toml
  - https://attack.mitre.org/techniques/T1490/
rules:
  - title: Detect Bcdedit Disable Recovery
    description: Detects the use of bcdedit.exe to disable Windows Error Recovery.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1490
    data_sources:
      - process_creation
      - windows
  - title: Detect Bcdedit Ignore All Failures
    description: Detects the use of bcdedit.exe to ignore all boot failures.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1490
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection rule identifies the execution of `bcdedit.exe` with specific arguments that modify the boot configuration data (BCD) store in Windows systems. Attackers or malware may use this technique to disable Windows Error Recovery (`recoveryenabled`) or to ignore errors during the boot process (`bootstatuspolicy ignoreallfailures`). These modifications are often performed to prevent systems from recovering properly after an attack, particularly in ransomware scenarios. The rule is designed to work with data from Elastic Defend, CrowdStrike, Microsoft Defender XDR, SentinelOne Cloud Funnel, and Sysmon. The detection logic focuses on process execution events that include the relevant `bcdedit.exe` command-line arguments. Defenders should be aware of legitimate uses of `bcdedit.exe` by administrators for troubleshooting or data recovery purposes, so context is crucial.

## Attack Chain

1. Initial Access: The attacker gains initial access to the system through various means, such as phishing or exploiting a vulnerability.
2. Privilege Escalation: The attacker escalates privileges to gain administrative access, required to modify boot configuration settings.
3. Reconnaissance: The attacker performs reconnaissance to identify the system's configuration and identify appropriate targets for modification.
4. Disable Recovery: The attacker uses `bcdedit.exe` to disable Windows Error Recovery using the `/set {default} recoveryenabled No` command.
5. Ignore Boot Failures: The attacker uses `bcdedit.exe` to set the boot status policy to ignore all failures using the `/set {default} bootstatuspolicy ignoreallfailures` command.
6. System Impact: By modifying the boot configuration, the attacker inhibits system recovery, making it harder for the system to recover from errors or malicious activity.
7. Payload Execution: The attacker deploys and executes the primary malicious payload, such as ransomware, leveraging the modified boot configuration to maximize impact.
8. Final Objective: The attacker achieves their final objective, which could include data encryption, data theft, or system disruption.

## Impact

Successful modification of boot configuration data can lead to significant system instability and data loss. In ransomware attacks, this technique prevents the system from recovering, increasing the likelihood of the victim paying the ransom. While the exact number of affected organizations is unknown, this technique is widely used in ransomware campaigns and can affect any Windows system if successfully executed.

## Recommendation

*   Deploy the "Modification of Boot Configuration" Sigma rule to your SIEM and tune for your environment to detect the malicious use of `bcdedit.exe` described in this brief.
*   Enable Sysmon process creation logging to capture `bcdedit.exe` executions and their command-line arguments (Sysmon Event ID 1).
*   Investigate any detected instances of `bcdedit.exe` modifying boot configuration settings to determine legitimacy, as described in the rule's "Triage and analysis" section.
*   Monitor process execution logs for unexpected processes running `bcdedit.exe` with arguments related to disabling recovery or ignoring boot failures.
