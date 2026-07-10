---
title: BloodHound Data Collection Activity
slug: 2024-01-30-bloodhound-collection
description: Adversaries may use the SharpHound tool to collect Active Directory data, saving it into default JSON files for BloodHound analysis, potentially leading to privilege escalation or lateral movement.
date: "2024-01-30T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - bloodhound
  - active-directory
  - reconnaissance
  - privilege-escalation
vendors:
  - Microsoft
products:
  - Active Directory
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1482
    technique_name: Domain Trust Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1069
    technique_name: Permission Groups Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1069
    technique_name: Permission Groups Discovery
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://academy.hackthebox.com/course/preview/active-directory-bloodhound/bloodhound--data-collection
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/file/file_event/file_event_win_bloodhound_collection.yml
rules:
  - title: BloodHound Collection Files
    description: Detects default file names outputted by the BloodHound collection tool SharpHound
    platform: sigma
    severity: high
    tactics:
      - discovery
      - execution
    techniques:
      - T1059.001
      - T1069.001
      - T1069.002
      - T1087.001
      - T1087.002
      - T1482
    data_sources:
      - file_event
      - windows
  - title: BloodHound Collection via PowerShell
    description: Detects execution of SharpHound using PowerShell
    platform: sigma
    severity: medium
    tactics:
      - discovery
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

BloodHound is a popular tool used to map relationships within Active Directory environments, enabling attackers to identify attack paths for privilege escalation. SharpHound is a data collector for BloodHound, written in C#, that gathers information about users, groups, computers, and other objects in the Active Directory domain. Detection of SharpHound's data collection activity is crucial to identify potential reconnaissance attempts by attackers aiming to map out attack vectors within the network. This activity often precedes lateral movement and privilege escalation attempts.

## Attack Chain

1. An attacker gains initial access to a system within the target environment (e.g., via compromised credentials or exploiting a vulnerability).
2. The attacker executes SharpHound.exe on the compromised system. This could be done via command line execution or a script.
3. SharpHound enumerates users, groups, computers, organizational units (OUs), Group Policy Objects (GPOs), and containers within the Active Directory domain.
4. SharpHound writes the collected data to JSON files with default names such as `_users.json`, `_computers.json`, `_groups.json`, `_ous.json`, `_gpos.json`, and `_containers.json`.
5. The attacker may compress these JSON files into a `BloodHound.zip` archive for easier transfer.
6. The attacker exfiltrates the collected data from the compromised system to a location where they can analyze it with BloodHound.
7. Using BloodHound, the attacker analyzes the collected data to identify attack paths and potential privilege escalation opportunities.
8. The attacker leverages identified attack paths to move laterally within the network and escalate privileges.

## Impact

Successful BloodHound data collection allows attackers to map out attack paths within the Active Directory environment. This can lead to privilege escalation, lateral movement, and ultimately, compromise of critical assets. Depending on the targeted environment, this can impact hundreds or thousands of systems and user accounts.

## Recommendation

*   Deploy the Sigma rule "BloodHound Collection Files" to your SIEM to detect the creation of BloodHound data collection files (reference: rules section).
*   Monitor file creation events for files ending with `_computers.json`, `_containers.json`, `_gpos.json`, `_groups.json`, `_ous.json`, `_users.json`, and `BloodHound.zip` (reference: rules section).
*   Implement network segmentation to limit the scope of potential BloodHound data collection activities (reference: attack chain).
*   Restrict the use of tools like SharpHound within the environment to authorized personnel only (reference: overview).
