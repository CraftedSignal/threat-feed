---
title: Detection of PowerShell Execution Policy Weakening
slug: 2026-09-powershell-policy-weakening
description: Adversaries often downgrade PowerShell execution policies to execute unauthorized scripts, bypassing security controls by invoking the Set-ExecutionPolicy cmdlet with 'Unrestricted' or 'Bypass' parameters.
date: "2026-09-01T11:05:58Z"
type: advisory
types:
  - advisory
severities:
  - medium
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Detects changing the PowerShell script execution policy to a potentially insecure level using the Set-ExecutionPolicy cmdlet.
    confidence_band: high
references:
  - https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-executionpolicy?view=powershell-7.4
  - https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-7.4
  - https://adsecurity.org/?p=2604
rules:
  - title: Detect PowerShell Execution Policy Weakening
    description: Detects changing the PowerShell script execution policy to a potentially insecure level using the Set-ExecutionPolicy cmdlet.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - ps_script
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Enable PowerShell Script Block Logging (Event ID 4104) across all Windows endpoints
      owner: IT Operations
      due: 72h
      evidence: Log source requirements specified in rule
  hunt_leads:
    - lead: Identify historical usage of Set-ExecutionPolicy in logs
      technique_id: T1059.001
      data_needed:
        - Event ID 4104 (Script Block Logging)
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: General prevalence of T1059.001 in post-exploitation
  mitigation_plan:
    - priority: short_term
      action: Enforce Execution Policy via Group Policy (GPO) to prevent local user modification
      owner: IT Security
      addresses: T1059.001
      evidence: Standard security hardening practice
---

Attackers frequently attempt to bypass PowerShell's built-in security features, specifically the Execution Policy, to facilitate the execution of malicious scripts or payloads. The Set-ExecutionPolicy cmdlet is a common target for modification to lower security standards, specifically moving from default constrained settings to 'Unrestricted' or 'Bypass' states. This behavior is a common precursor to deploying lateral movement tools, credential harvesters, or secondary backdoors within a compromised Windows environment. Defensive teams should be aware that while some legitimate administrative tasks or automated installers (such as Chocolatey) may require such modifications, unauthorized execution of these commands by user-level processes or unexpected service accounts represents a significant indicator of malicious activity during the post-exploitation phase.

## Attack Chain

1. Initial access is established through phishing or exploit delivery to a workstation.
2. The attacker executes a primary stager or drops a malicious script to disk.
3. The attacker determines that the current PowerShell execution policy prevents the execution of the unsigned or remote-origin script.
4. The attacker executes "Set-ExecutionPolicy -ExecutionPolicy Bypass" or "Unrestricted" via an interactive shell or automated script block.
5. The system policy is downgraded, allowing the subsequent execution of the malicious script or payload without further prompt.
6. The malicious payload executes, performing objectives such as credential dumping, discovery, or C2 beaconing.

## Impact

Successful execution policy downgrades enable attackers to bypass security restrictions designed to prevent unauthorized script execution. This facilitates the deployment of malware, administrative tools, or weaponized scripts that would otherwise be blocked, increasing the likelihood of successful lateral movement and data exfiltration.

## Recommendation

- Enable PowerShell Script Block Logging (Event ID 4104) across the environment to capture the command line content necessary to identify this activity.
- Deploy the Sigma rule below to monitor for unauthorized execution policy modifications.
- Audit administrative usage of execution policy changes and establish a baseline of legitimate deployment processes to reduce noise from installers like Chocolatey.
