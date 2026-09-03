---
title: Detection of PowerView Enumeration Framework Activity
slug: 2026-09-powerview-cmdlets
description: PowerView is an open-source PowerShell module frequently used by threat actors for domain reconnaissance, user enumeration, and identifying lateral movement opportunities.
date: "2026-09-03T12:36:30Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - reconnaissance
  - discovery
  - post-exploitation
  - powershell
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Detects Cmdlet names from PowerView of the PowerSploit exploitation framework.
    confidence_band: high
rules:
  - title: Detect PowerView PowerShell Cmdlets Execution
    description: Detects the use of PowerView reconnaissance cmdlets within PowerShell Script Block logs, which are commonly associated with domain environment mapping.
    platform: sigma
    severity: high
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
    - action: Enable PowerShell Script Block Logging (Event ID 4104)
      owner: IT Operations
      due: 48h
      evidence: Required for visibility into script-based execution
  hunt_leads:
    - lead: Search for instances of PowerView cmdlet usage in historical logs
      technique_id: T1059.001
      data_needed:
        - Event ID 4104
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Enumeration tool usage is a high-fidelity indicator of discovery
  mitigation_plan:
    - priority: medium_term
      action: Implement Constrained Language Mode (CLM) for non-administrative accounts
      owner: IT Operations
      addresses: T1059.001
      evidence: Reduces the ability of PowerView to execute complex calls
---

PowerView is a component of the PowerSploit framework widely utilized by attackers for Active Directory reconnaissance. It provides a suite of PowerShell cmdlets designed to enumerate domain users, computers, groups, file shares, and GPO configurations. By leveraging these scripts, adversaries can quickly map out network topology, identify privileged accounts, and locate sensitive files or systems suitable for lateral movement. Given its modular nature and the ability to execute these commands in memory, defenders must rely on PowerShell Script Block Logging (Event ID 4104) to capture and inspect the specific commands executed within an environment. Monitoring for these specific cmdlet strings is a high-confidence method for identifying unauthorized discovery activities, as they are not commonly utilized in standard administrative workflows.

## Attack Chain

1. Initial access is established on a domain-joined workstation via phishing or exploit.
2. PowerShell is invoked, typically with obfuscation or via memory-resident script execution.
3. The attacker imports the PowerView module or executes functions directly from memory.
4. The attacker runs `Invoke-UserHunter` or `Find-LocalAdminAccess` to identify high-value targets.
5. The attacker executes `Invoke-Kerberoast` to extract service account tickets for offline cracking.
6. The attacker enumerates domain trusts and group memberships using `Get-NetForest` and `Get-NetGroup`.
7. Information gathered is staged or exfiltrated, or used to facilitate lateral movement to domain controllers or file servers.
8. Final objective is achieved, such as credential theft, data staging, or complete domain compromise.

## Impact

Successful use of PowerView allows an attacker to achieve rapid domain situational awareness, escalating their ability to identify and exploit vulnerabilities within Active Directory. This often leads to privilege escalation, unauthorized access to sensitive files, and broad persistence across the enterprise network.

## Recommendation

- Enable PowerShell Script Block Logging (Event ID 4104) via Group Policy on all domain-joined endpoints to capture the full command syntax.
- Deploy the provided Sigma detection rule to monitor for PowerView cmdlet patterns in SIEM/log management platforms.
- Establish alerting for high-frequency reconnaissance activity originating from non-administrative endpoints or service accounts.
