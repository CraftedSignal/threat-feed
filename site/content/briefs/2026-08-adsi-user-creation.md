---
title: ADSI-based User Account Creation Technique
slug: 2026-08-adsi-user-creation
description: Adversaries are leveraging Active Directory Service Interfaces (ADSI) via PowerShell to create local and domain accounts as a method to evade standard process-based monitoring.
date: "2026-08-18T22:51:58Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - powershell
  - adsi
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Create Account
    evidence: The rule identifies attempts to create user accounts via the ADSI WinNT provider which interacts directly with local system account management.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Create Account
    evidence: The rule identifies attempts to create user accounts via the ADSI LDAP provider which interacts directly with domain controllers.
    confidence_band: high
rules:
  - title: Detect ADSI User Account Creation
    description: Detects an attempt to create a new user account via ADSI using WinNT or LDAP providers, bypassing common account creation utilities.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1136.001
      - T1136.002
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Enable PowerShell Script Block Logging (Event ID 4104) across all endpoints
      owner: IT Operations
      due: 72h
      evidence: Required for visibility into script-based account creation
    - action: Deploy the Sigma detection rule to the SIEM
      owner: Detection Engineering
      due: 72h
      evidence: Addresses evasion of process-based account creation monitoring
  hunt_leads:
    - lead: Search historic 4104 logs for ADSI account creation syntax
      technique_id: T1136
      data_needed:
        - ScriptBlockText
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Identifies if the technique was used prior to deploying detection
---

Adversaries may use Active Directory Service Interfaces (ADSI) within PowerShell scripts to bypass traditional monitoring of common account creation commands like "net user" or "New-LocalUser". By interacting directly with the WinNT or LDAP service providers, an attacker can instantiate objects representing computers or organizational units to create, configure, and set passwords for new users. This technique is often employed in the post-exploitation phase to establish persistence or facilitate lateral movement. Because ADSI interactions often occur entirely within memory through the PowerShell script block interpreter, they do not generate the standard process-creation logs associated with traditional command-line utilities. This capability requires detection at the script block level to identify the instantiation of ADSI objects and the subsequent creation method calls.

## Impact

Successful exploitation allows attackers to maintain stealthy persistence or gain unauthorized access to local systems and domain environments. Because the account creation occurs via an API interaction rather than an executable, standard security tooling relying solely on process-creation events may fail to alert on the activity. 

## Recommendation

Prioritized actions for detection engineering teams:
- Enable PowerShell Script Block Logging (Event ID 4104) across the environment to capture full script execution context.
- Deploy the provided Sigma rule to detect the simultaneous usage of [ADSI] type accelerators and .create("user") methods.
- Establish a baseline of administrative scripts that legitimately utilize ADSI to minimize noise during alert triage.
