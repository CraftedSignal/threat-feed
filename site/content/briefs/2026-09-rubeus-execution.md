---
title: Detection of Rubeus Kerberos Exploitation Tool
slug: 2026-09-rubeus-execution
description: This brief covers detection strategies for the Rubeus hacktool, which is frequently used by attackers to perform Kerberos-based credential theft and lateral movement.
date: "2026-09-03T12:35:46Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - lateral-movement
  - kerberos
  - hacktool
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    evidence: Rubeus is used to dump credentials from memory and harvest Kerberos tickets.
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1550.003
    technique_name: 'Use Alternate Authentication Material: Pass the Ticket'
    evidence: Rubeus supports ptt (pass-the-ticket) functionality for lateral movement.
    confidence_band: high
references:
  - https://github.com/GhostPack/Rubeus
  - https://blog.harmj0y.net/redteaming/from-kekeo-to-rubeus
  - https://m0chan.github.io/2019/07/31/How-To-Attack-Kerberos-101.html
rules:
  - title: HackTool - Rubeus Execution - ScriptBlock
    description: Detects the execution of the hacktool Rubeus using specific command line flags within PowerShell Script Blocks
    platform: sigma
    severity: high
    tactics:
      - credential-access
      - lateral-movement
    techniques:
      - T1003
      - T1550.003
      - T1558.003
    data_sources:
      - ps_script
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Enable PowerShell Script Block Logging (Event ID 4104) via GPO.
      owner: IT Operations
      due: 48h
      evidence: Required telemetry for the associated Sigma rule.
  hunt_leads:
    - lead: Search for Event ID 4104 logs containing Rubeus command arguments.
      technique_id: T1003
      data_needed:
        - PowerShell Script Block logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Sigma rule strings indicate high-confidence attacker activity.
  mitigation_plan:
    - priority: short_term
      action: Monitor and restrict the execution of unauthorized binaries in user-writable directories.
      owner: Security Operations
      addresses: Credential Access TTPs
      evidence: Rubeus is a binary that must be placed on the disk to execute.
---

Rubeus is a widely used C# toolset designed for interacting with the Kerberos protocol in Windows environments. It serves as a comprehensive suite for credential harvesting, ticket manipulation, and performing advanced Kerberos-based attacks such as AS-REP Roasting, Kerberoasting, and Silver/Golden ticket creation. Threat actors utilize Rubeus to escalate privileges, dump sensitive account information (such as krbtgt hashes), and maintain persistence through pass-the-ticket (PTT) techniques. Given its common use by various offensive security actors to compromise Active Directory environments, defenders should prioritize monitoring for the specific command-line arguments and script blocks associated with its operations. The tool operates primarily by interacting with the Windows security subsystem via PowerShell or direct process execution, making script block logging and process creation telemetry essential for visibility.

## Impact

Successful deployment of Rubeus allows attackers to gain unauthorized access to credentials, bypass multi-factor authentication for service accounts via Kerberoasting, and achieve full domain dominance through Golden Ticket attacks. This poses a critical risk of complete network compromise and large-scale data exfiltration within an Active Directory environment.

## Recommendation

Detection engineering teams should focus on PowerShell Script Block Logging as the primary telemetry source to catch Rubeus activity regardless of the obfuscation technique used by the attacker. 

- Enable PowerShell Script Block Logging (Event ID 4104) across all domain-joined endpoints to capture the specific execution flags identified in the provided Sigma rule.
- Deploy the provided Sigma rule to your SIEM to monitor for Rubeus-specific command-line arguments.
- Audit high-privilege account usage if Rubeus activity is identified, as the tool is often used by actors who have already gained initial administrative access.
