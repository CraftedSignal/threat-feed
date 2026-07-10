---
title: Detection of PowerShell Execution Policy Changes to Unrestricted or Bypass
slug: 2024-01-powershell-execution-policy
description: Detection of modifications to the PowerShell execution policy to 'Unrestricted' or use of the 'Bypass' flag indicates a potential attempt to execute unsigned or malicious scripts, bypassing security controls.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - powershell
  - execution_policy
  - bypass
  - security_controls
vendors:
  - Microsoft
products:
  - PowerShell
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/set_default_powershell_execution_policy_to_unrestricted_or_bypass.yml
rules:
  - title: Detect PowerShell Execution Policy Changes
    description: Detects changes to the PowerShell execution policy, specifically when set to 'Unrestricted'.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - registry_set
      - windows
  - title: Detect PowerShell Bypass Execution Policy Flag
    description: Detects the use of the '-ExecutionPolicy Bypass' flag in PowerShell commands.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers often modify the PowerShell execution policy to bypass security restrictions and execute malicious scripts. The default execution policy in PowerShell restricts the execution of unsigned scripts. However, an attacker can change the execution policy to `Unrestricted`, allowing all scripts to run, or use the `Bypass` flag to bypass all security checks for a single command. This modification is a common tactic used by attackers to execute malware, perform reconnaissance, or establish persistence on a compromised system. Detecting these changes is crucial for identifying potential malicious activity within an environment.

## Attack Chain

1.  The attacker gains initial access to the system (e.g., through phishing or exploiting a vulnerability).
2.  The attacker executes a command to modify the PowerShell execution policy. This can be done using the `Set-ExecutionPolicy` cmdlet with the `Unrestricted` parameter, or using the `-ExecutionPolicy Bypass` flag when invoking PowerShell.
3.  The `Set-ExecutionPolicy` command modifies the registry key responsible for storing the PowerShell execution policy: `HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell`.
4.  Alternatively, the attacker could invoke a single PowerShell command bypassing the current execution policy using `powershell.exe -ExecutionPolicy Bypass -Command "malicious_command"`.
5.  The system’s PowerShell configuration is altered, enabling the execution of unsigned or malicious scripts.
6.  The attacker then executes malicious PowerShell scripts for various purposes, such as downloading malware, performing lateral movement, or exfiltrating data.
7.  The scripts leverage the now-unrestricted environment to perform actions that would normally be blocked, such as accessing sensitive files or making unauthorized network connections.
8.  The attacker achieves their final objective, such as data theft, system compromise, or ransomware deployment.

## Impact

A successful modification of the PowerShell execution policy can lead to a complete compromise of the affected system. Attackers can use the unrestricted PowerShell environment to execute arbitrary code, bypass security controls, and perform malicious activities without being detected. This can result in data breaches, financial losses, reputational damage, and disruption of business operations.

## Recommendation

*   Deploy the Sigma rule `Detect PowerShell Execution Policy Changes` to your SIEM to identify suspicious modifications to the PowerShell execution policy.
*   Enable PowerShell script block logging and transcript logging to capture the commands executed and scripts run within PowerShell sessions, which can be used to further investigate detected anomalies.
*   Monitor for the use of the `-ExecutionPolicy Bypass` flag in PowerShell commands using the `Detect PowerShell Bypass Execution Policy Flag` Sigma rule.
*   Implement application control policies to restrict the execution of unsigned or untrusted PowerShell scripts.
*   Review and audit PowerShell execution policy settings regularly to ensure they align with security best practices.
