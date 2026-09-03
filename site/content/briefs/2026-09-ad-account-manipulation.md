---
title: Detection of Active Directory Account Management via PowerShell
slug: 2026-09-ad-account-manipulation
description: Adversaries may use the System.DirectoryServices.AccountManagement namespace in PowerShell to programmatically create or manipulate domain accounts for persistence within Active Directory environments.
date: "2026-09-03T13:38:06Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - powershell
  - active-directory
  - identity-security
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136.002
    technique_name: 'Create Account: Domain Account'
    evidence: Adversaries may create a domain account to maintain access to victim systems.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/powershell/powershell_script/posh_ps_directoryservices_accountmanagement.yml
  - https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.accountmanagement
rules:
  - title: Detect AD Account Management via PowerShell
    description: Detects the use of the System.DirectoryServices.AccountManagement namespace in PowerShell scripts, often used for creating or modifying AD accounts.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1136.002
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
    - action: Enable PowerShell Script Block Logging (Event ID 4104) across all AD-joined endpoints.
      owner: IT Operations
      due: 72h
      evidence: Required telemetry source for the provided detection.
  hunt_leads:
    - lead: Search for script blocks utilizing System.DirectoryServices.AccountManagement not associated with known management tools.
      technique_id: T1136.002
      data_needed:
        - Event ID 4104
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Source explicitly identifies this namespace as a indicator for AD manipulation.
  mitigation_plan:
    - priority: medium
      action: Implement strict access control on who can execute scripts using the System.DirectoryServices.AccountManagement library.
      owner: Identity Team
      addresses: T1136.002
      evidence: Reducing the attack surface for privileged PowerShell execution limits persistence options.
---

Adversaries often attempt to maintain persistent access to compromised environments by creating or modifying domain-level security principals. In Active Directory environments, this can be achieved using the System.DirectoryServices.AccountManagement .NET namespace within PowerShell scripts. This technique allows attackers to bypass standard administrative tools and interact directly with the directory service. Detection of this activity relies on monitoring PowerShell Script Block Logging for the instantiation or usage of these specific .NET classes. While legitimate administrative scripts and infrastructure-as-code automation may utilize these libraries for routine identity management, unauthorized or unexpected usage of these classes by non-standard processes is a significant indicator of potential persistence establishment or account privilege escalation.

## Impact

Successful manipulation of Active Directory security principals allows attackers to create backdoor accounts, modify group memberships for privilege escalation, or reset credentials for existing service accounts. This compromises the integrity of the domain identity infrastructure and grants attackers a durable foothold that survives credential rotations or reboots of individual member servers.

## Recommendation

* Enable PowerShell Script Block Logging (Event ID 4104) across all domain controllers and member servers to capture the necessary script execution telemetry.
* Deploy the provided Sigma rule to detect the invocation of DirectoryServices.AccountManagement classes and tune the output to baseline authorized administrative service accounts.
* Audit Active Directory event logs (specifically Event IDs 4720, 4722, 4728) in conjunction with PowerShell telemetry to verify the legitimacy of account management operations occurring within the network.
