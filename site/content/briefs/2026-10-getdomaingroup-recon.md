---
title: Detection of PowerView Get-DomainGroup Reconnaissance
slug: 2026-10-getdomaingroup-recon
description: Adversaries utilize the PowerView PowerShell cmdlet 'Get-DomainGroup' to perform Active Directory reconnaissance and map domain structures, facilitating subsequent privilege escalation and lateral movement.
date: "2026-10-12T17:46:27Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - active-directory
  - reconnaissance
  - powershell
  - endpoint
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1069
    technique_name: Permission Groups Discovery
    evidence: This cmdlet, part of the PowerView tool, is used to enumerate domain groups within a Windows domain.
    confidence_band: high
rules:
  - title: Detect Get-DomainGroup PowerShell Execution
    description: Detects the execution of the Get-DomainGroup cmdlet which is used by PowerView for domain group enumeration.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1069.002
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
    - action: Enable PowerShell Script Block Logging (EventID 4104).
      owner: IT Operations
      due: 72h
      evidence: Required for visibility into PowerShell script block execution.
  hunt_leads:
    - lead: Search for EventID 4104 occurrences containing 'Get-DomainGroup'.
      technique_id: T1069.002
      data_needed:
        - Powershell Script Block Logging 4104
      priority: high
      confidence: high
      disposition: convert_to_detection
      evidence: This is a direct indicator of the reconnaissance technique.
---

Adversaries and Red Team operators frequently leverage the PowerView framework during the post-exploitation reconnaissance phase to gain situational awareness within a compromised Windows environment. Specifically, the 'Get-DomainGroup' cmdlet is used to enumerate all security groups within an Active Directory domain. By identifying which users belong to specific privileged or sensitive groups, an attacker can pinpoint targets for credential theft, lateral movement, or privilege escalation. This activity is visible through PowerShell Script Block Logging (EventID 4104), which captures the full command execution strings. Defenders should monitor for this cmdlet as it serves as a critical indicator of internal environment mapping that often precedes more damaging actions.

## Attack Chain

1. Initial access is established on a domain-joined Windows endpoint via phishing, exploit, or credential abuse.
2. The attacker executes a PowerShell process (e.g., powershell.exe or pwsh.exe).
3. The attacker loads the PowerView framework or imports the necessary module containing 'Get-DomainGroup'.
4. The attacker executes the 'Get-DomainGroup' command to enumerate domain-level groups.
5. The PowerShell engine generates EventID 4104 logs containing the command syntax.
6. The adversary parses the output to identify high-value groups (e.g., Domain Admins).
7. The attacker uses the gathered information to plan lateral movement or target specific users for credential harvesting.

## Impact

Successful reconnaissance allows an attacker to map the target network's organizational structure, identifying administrative accounts and critical systems. This intelligence is a necessary prerequisite for sophisticated operations, including lateral movement, domain-wide privilege escalation, and exfiltration of sensitive organizational data. 

## Recommendation

* Enable PowerShell Script Block Logging (EventID 4104) via Group Policy on all domain-joined Windows endpoints.
* Deploy the provided Sigma rule to your SIEM to alert on the execution of 'Get-DomainGroup'.
* Investigate the context of the PowerShell execution to distinguish between authorized administrative troubleshooting and adversary reconnaissance.
