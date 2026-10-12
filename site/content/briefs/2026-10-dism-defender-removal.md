---
title: Abuse of DISM to Disable Windows Defender
slug: 2026-10-dism-defender-removal
description: Adversaries leverage the Deployment Image Servicing and Management (DISM) tool to disable or remove Windows Defender components as a defense evasion technique.
date: "2026-10-12T18:04:50Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - windows
  - endpoint-security
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562.001
    technique_name: 'Impair Defenses: Disable or Modify Tools'
    evidence: Adversaries may disable Defender to evade detection and carry out further malicious actions undetected.
    confidence_band: high
references:
  - https://thedfirreport.com/2020/11/23/pysa-mespinoza-ransomware/
  - https://github.com/redcanaryco/atomic-red-team/blob/388942adbd9641f4dfdcf079d7efe9a75ec0ac43/atomics/T1685/T1685.yaml
rules:
  - title: Detect DISM Windows Defender Removal
    description: Detects the use of dism.exe to remove or disable Windows Defender features via command line.
    platform: sigma
    severity: high
    tactics:
      - defense-evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to SIEM
      owner: Detection Engineering
      due: 48h
      evidence: Analytic provided by source
  hunt_leads:
    - lead: Search for historical execution of dism.exe with Defender flags
      technique_id: T1685
      data_needed:
        - Endpoint process logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source analytic
  mitigation_plan:
    - priority: medium_term
      action: Restrict administrative usage of DISM
      owner: IT Operations
      addresses: T1685
      evidence: General security hardening
---

Adversaries are known to abuse the built-in Windows Deployment Image Servicing and Management (DISM) tool to undermine host-based security by removing or disabling Windows Defender. This technique allows attackers to eliminate a critical layer of endpoint protection, facilitating subsequent malicious activities such as malware installation, persistent access, and data exfiltration without detection. This activity typically occurs post-compromise, where the attacker has already obtained high-privilege access, often executing commands via a shell or administrative script. By targeting the 'Windows-Defender' feature specifically, adversaries can effectively neuter the built-in security stack of the operating system. Security teams should monitor for the execution of dism.exe with parameters indicating feature removal, as legitimate administrative usage of DISM for feature management in production environments is relatively rare and often controlled by centralized deployment tools.

## Attack Chain

1. Attacker gains initial access to a Windows host through techniques such as phishing or exploitation of a service vulnerability.
2. Attacker escalates privileges to local administrator or SYSTEM to gain the necessary permissions for system feature modification.
3. Attacker identifies the Windows Defender feature name for removal via DISM capabilities.
4. Attacker invokes `dism.exe` with administrative flags and specific command-line arguments.
5. The command line includes `/online` to target the running OS, `/disable-feature` and `/remove` to modify the feature set.
6. DISM processes the request, modifying the Windows component store and disabling Windows Defender services.
7. Windows Defender is removed or disabled, leaving the system vulnerable to further malicious activities.
8. Attacker proceeds with payload execution or data exfiltration, now undetected by the disabled security software.

## Impact

Successful execution of this technique results in the complete loss of Windows Defender protection on the targeted host. This significantly increases the risk of successful ransomware deployment, credential theft, and persistent compromise. While the total number of victims is not publicly quantified, this technique is a documented component of advanced threat actor playbooks, specifically associated with ransomware campaigns and other high-impact post-exploitation scenarios.

## Recommendation

Prioritize monitoring for the misuse of administrative binaries used in defense evasion.

- Deploy the provided Sigma rule to detect the specific combination of command-line arguments used to disable Windows Defender.
- Implement monitoring for all command-line executions of `dism.exe` and investigate any instances initiated by non-administrative users or unexpected parent processes.
- Audit and restrict administrative access to sensitive system tools to prevent unauthorized modification of OS security features.
