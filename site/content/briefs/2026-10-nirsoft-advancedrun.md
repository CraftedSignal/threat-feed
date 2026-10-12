---
title: Abuse of NirSoft AdvancedRun Utility
slug: 2026-10-nirsoft-advancedrun
description: Threat actors leverage the legitimate NirSoft AdvancedRun utility to perform remote code execution, privilege escalation, and persistence on Windows systems.
date: "2026-10-12T18:16:50Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - privilege-escalation
  - execution
  - ransomware
  - malware
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1588.002
    technique_name: 'Obtain Capabilities: Tool'
    evidence: The utility allows for the execution of programs with specific configurations, such as elevated privileges or modified window states.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: If malicious, this could allow attackers to execute arbitrary commands, escalate privileges, or maintain persistence within the environment.
    confidence_band: high
rules:
  - title: Detect NirSoft AdvancedRun Execution
    description: Detects the execution of AdvancedRun.exe, a tool used for privilege escalation and arbitrary command execution, by monitoring process names and common command-line parameters.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - persistence
      - privilege_escalation
    techniques:
      - T1588.002
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy Sigma rule and monitor for AdvancedRun.exe execution.
      owner: Detection Engineering
      due: 48h
      evidence: Analytic identified as TTP-based detection for unauthorized utility usage.
  hunt_leads:
    - lead: Search for AdvancedRun.exe in non-standard execution paths (e.g., C:\Users\Public\, C:\Temp\).
      technique_id: T1588.002
      data_needed:
        - Endpoint process creation logs (EID 1)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: NirSoft tools are frequently staged in temporary directories by attackers.
  mitigation_plan:
    - priority: short_term
      action: Implement AppLocker or Windows Defender Application Control (WDAC) to block unauthorized execution of NirSoft utilities.
      owner: IT Operations
      addresses: T1588.002
      evidence: Tool abuse can be mitigated by application allowlisting.
---

NirSoft AdvancedRun is a legitimate administration utility designed to execute programs with specific configurations, such as elevated privileges or modified window states. Despite its benign intent, threat actors frequently weaponize this tool to facilitate malicious activities including remote code execution, privilege escalation, and maintaining persistence within compromised environments. Attackers deploy this utility to automate tasks or execute arbitrary commands under elevated tokens, often using it as a precursor for data destruction or ransomware deployment. This activity has been observed in high-impact campaigns, including those involving WhisperGate malware. Defenders should prioritize monitoring for the execution of this utility, as its presence in an enterprise environment - outside of authorized administrative use cases - is a strong indicator of compromise or unauthorized reconnaissance.

## Attack Chain

1. Attacker gains initial access to the Windows host through phishing or exploit.
2. AdvancedRun.exe is dropped onto the filesystem, often in directories such as C:\Windows\Temp or user AppData.
3. Attacker executes AdvancedRun.exe using command-line arguments to specify the target binary, configuration files (/cfg), or elevated execution context (/RunAs).
4. AdvancedRun.exe manipulates process token permissions or window visibility states.
5. The target application (e.g., cmd.exe, powershell.exe) is spawned as a child process of AdvancedRun.exe with the specified elevated privileges.
6. Attacker utilizes the elevated shell to execute follow-on payloads, move laterally, or deploy ransomware modules.

## Impact

Abuse of AdvancedRun enables attackers to achieve persistent elevated access on infected systems. If successful, this can lead to full system compromise, exfiltration of sensitive organizational data, or large-scale data destruction and ransomware deployment. Historically, this technique has been linked to campaigns targeting major organizations across various sectors, resulting in significant operational disruption and data loss.

## Recommendation

* Deploy the Sigma rule below to detect unauthorized execution of AdvancedRun.exe using Sysmon or EDR process creation logs.
* Establish an allowlist for authorized administrative use of AdvancedRun and investigate all other executions by non-administrator users or at unexpected paths.
* Audit environment-wide deployments of the NirSoft toolset to ensure they are constrained to authorized IT and security administrative workstations.
