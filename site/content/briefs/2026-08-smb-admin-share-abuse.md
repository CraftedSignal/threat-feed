---
title: Detection of Executable Writes to Administrative SMB Shares
slug: 2026-08-smb-admin-share-abuse
description: Adversaries often leverage Windows administrative SMB shares (Admin$, C$, IPC$) to stage binaries for lateral movement and remote code execution using tools like PsExec.
date: "2026-08-05T21:12:03Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - lateral-movement
  - windows
  - smb
  - psexec
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
    evidence: This behavior is significant as it is commonly used by tools like PsExec/PaExec for staging binaries before creating and starting services on remote endpoints.
    confidence_band: high
references:
  - https://attack.mitre.org/techniques/T1021/002/
  - https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5145#table-of-file-access-codes
rules:
  - title: Detect Executable Written to Administrative SMB Share
    description: Detects the creation of executable files (.exe, .dll, .sys, .cpl) within Administrative SMB shares, a common precursor to remote service execution.
    platform: sigma
    severity: medium
    tactics:
      - lateral_movement
    techniques:
      - T1021.002
    data_sources:
      - network_connection
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Enable Windows Security Event ID 5145 auditing on critical infrastructure.
      owner: IT Operations
      due: 72h
      evidence: Source documentation for Event ID 5145.
    - action: Deploy detection rule for SMB share writes.
      owner: Detection Engineering
      due: 48h
      evidence: Source analytic logic.
  mitigation_plan:
    - priority: medium_term
      action: Restrict administrative access to specific jump hosts.
      owner: IT Operations
      addresses: T1021.002
      evidence: General security best practices for reducing lateral movement.
---

This detection focuses on identifying the write activity of potentially malicious executables (.exe, .dll, .sys, .cpl) within Windows administrative SMB shares. Administrative shares are common targets for lateral movement techniques, where attackers stage malicious tools, such as PsExec or PaExec, to facilitate remote service installation and command execution. This behavior is a hallmark of various threat actors and ransomware operations, including Trickbot, BlackSuit, and IcedID, to propagate across compromised enterprise networks. Defenders should monitor for these write events to detect unauthorized binary staging before execution occurs.

## Attack Chain

1. The attacker gains initial access to a compromised workstation within the target network.
2. The attacker uses credential harvesting techniques to obtain administrative credentials.
3. The attacker establishes an SMB connection to a target system using the administrative credentials.
4. The attacker maps to or interacts with an administrative share, such as C$, Admin$, or IPC$.
5. The attacker writes a malicious binary or tool (e.g., PsExec agent) to a directory on the target share.
6. The attacker creates or modifies a remote service on the target system using the staged binary.
7. The attacker starts the service to execute arbitrary code with SYSTEM privileges on the remote host.
8. The attacker achieves full execution and proceeds with further lateral movement or data impact.

## Impact

Successful exploitation of this technique leads to unauthorized remote code execution, privilege escalation, and rapid lateral movement throughout the Windows environment. This activity is frequently the precursor to ransomware deployment or data exfiltration, putting entire enterprise networks at risk of complete compromise.

## Recommendation

Deploy the provided Sigma rule to your SIEM to monitor Event ID 5145. Ensure that Object Access auditing for success and failure is enabled via Group Policy across the domain. Investigate any alerts identifying non-administrative users or non-standard source systems accessing these shares.
