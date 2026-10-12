---
title: Detection of PowerView Domain Group Enumeration via PowerShell
slug: 2026-10-getdomaingroup-powershell
description: Adversaries leverage the PowerView cmdlet 'Get-DomainGroup' via PowerShell to perform Active Directory reconnaissance and identify group memberships for lateral movement.
date: "2026-10-12T17:46:19Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - active-directory
  - discovery
  - powerview
  - reconnaissance
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1069
    technique_name: Permission Groups Discovery
    evidence: The detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions mapped to the Processes node of the Endpoint data model.
    confidence_band: high
rules:
  - title: Detect PowerView Get-DomainGroup Execution
    description: Detects the use of the Get-DomainGroup cmdlet within PowerShell which is indicative of Active Directory reconnaissance.
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
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection rule to environment
      owner: Detection Engineering
      due: 48h
      evidence: Source provides analytic guidance for PowerShell reconnaissance
  hunt_leads:
    - lead: Search for PowerShell execution strings associated with PowerView modules
      technique_id: T1069.002
      data_needed:
        - Process creation events with command-line arguments
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Analytic rule provided in source
---

Adversaries often utilize the PowerView framework, specifically the `Get-DomainGroup` cmdlet, to perform Active Directory reconnaissance during the discovery phase of an attack. By executing this command within a PowerShell environment, attackers can identify domain group structures, memberships, and potentially sensitive organizational units. This information is critical for attackers to map out network privileges and identify high-value targets for lateral movement or privilege escalation. Security operations centers should monitor for the execution of PowerShell processes where command-line arguments contain the string `Get-DomainGroup`, as this activity is frequently associated with unauthorized environment discovery rather than standard administrative tasks.

## Attack Chain

1. Attacker gains initial access to a domain-joined workstation or server via phishing or exploitation.
2. Attacker initiates a PowerShell process to begin environment discovery.
3. Attacker imports or executes PowerView scripts (typically memory-resident) to bypass disk-based detection.
4. Attacker executes `Get-DomainGroup` to query the Active Directory domain controller for group lists.
5. The domain controller returns the requested group membership data to the compromised host.
6. Attacker parses the output to identify privileged groups (e.g., Domain Admins).
7. Attacker uses discovered information to target specific accounts or assets for lateral movement.

## Impact

Successful reconnaissance allows attackers to map the internal Active Directory structure, leading to increased efficiency in targeting specific privileged users and assets. This increases the likelihood of successful lateral movement and eventual domain dominance.

## Recommendation

Deploy the provided Sigma rule to your SIEM to monitor for PowerShell command-line activity containing `Get-DomainGroup`. Ensure that Sysmon Event ID 1 or Windows Security Event ID 4688 is enabled across the workstation and server fleet. Investigate all alerts by reviewing the parent process of the suspicious PowerShell execution to determine the initial point of entry. If the activity is confirmed as unauthorized, trigger incident response procedures for host isolation and account audit.
