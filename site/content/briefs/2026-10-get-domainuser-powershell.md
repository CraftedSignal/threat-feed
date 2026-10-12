---
title: Detection of Active Directory Domain User Enumeration via PowerView
slug: 2026-10-get-domainuser-powershell
description: Adversaries utilize the Get-DomainUser cmdlet within the PowerView framework to perform Active Directory reconnaissance and user enumeration.
date: "2026-10-12T17:45:20Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - reconnaissance
  - active-directory
  - powershell
  - edr
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
    evidence: This activity is significant as it indicates potential reconnaissance efforts by adversaries or Red Teams using PowerView for Active Directory discovery.
    confidence_band: high
rules:
  - title: Detect Get-DomainUser Execution via PowerShell
    description: Detects the execution of PowerShell with command-line arguments used for domain user enumeration via PowerView
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1087.002
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
    - action: Deploy Sigma rule to capture PowerView reconnaissance attempts
      owner: Detection Engineering
      due: 48h
      evidence: Source provides analytic search logic
  hunt_leads:
    - lead: Search for 'Get-DomainUser' or PowerView-related cmdlet strings in historical process logs
      technique_id: T1087.002
      data_needed:
        - Process Command Line
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Command line arguments are observable via EDR telemetry
---

This threat brief focuses on the detection of Active Directory reconnaissance activities performed via the PowerView framework. Threat actors often leverage the `Get-DomainUser` PowerShell cmdlet to identify and enumerate domain users within an environment. This information gathering phase is critical for adversaries aiming to map out organizational structures, identify high-value targets, and prepare for subsequent lateral movement or privilege escalation. The activity typically manifests as execution of PowerShell or CMD processes with command-line arguments containing specific PowerView-related strings. Defenders should prioritize identifying this behavior in high-security zones where internal discovery activities are unlikely to originate from standard endpoints.

## Attack Chain

1. Attacker gains initial access to a domain-joined endpoint.
2. Attacker drops or executes the PowerView script within a PowerShell session.
3. Attacker executes the `Get-DomainUser` cmdlet to query Active Directory.
4. The process (powershell.exe or cmd.exe) calls Active Directory services (LDAP).
5. The Active Directory domain controller returns the list of domain users to the attacker.
6. Attacker processes the returned user objects to identify specific targets or accounts for further exploitation.

## Impact

Successful execution of domain enumeration allows attackers to gain significant situational awareness within the target domain. This intelligence is frequently used to identify administrative accounts, service accounts, or users with specific access rights, facilitating targeted lateral movement and escalating the overall impact of the compromise.

## Recommendation

1. Deploy the provided Sigma rule to detect `Get-DomainUser` command-line execution patterns.
2. Ensure EDR process-creation telemetry is configured to capture full command-line arguments.
3. Establish a baseline of normal administrative activity to reduce noise from legitimate troubleshooting.
4. Integrate the identified detection into existing monitoring for Active Directory reconnaissance, specifically looking for process execution chains involving PowerView.
