---
title: Detection of Stealthy User Account Creation via ADSI
slug: 2026-08-adsi-user-creation
description: Adversaries may use Active Directory Service Interfaces (ADSI) within PowerShell to create local or domain accounts, effectively bypassing standard monitoring for typical user-creation commands.
date: "2026-08-18T22:52:06Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - windows
  - powershell
  - adsi
  - detection-engineering
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Create Account
    evidence: Detects PowerShell command line arguments containing ADSI patterns trying to create a new user account.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136
    technique_name: Create Account
    evidence: Detects PowerShell command line arguments containing ADSI patterns trying to create a new user account via the WinNT or LDAP provider.
    confidence_band: high
rules:
  - title: Detect ADSI-based User Account Creation via PowerShell
    description: Detects PowerShell command line arguments containing ADSI patterns trying to create a new user account via the WinNT or LDAP provider.
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
    - action: Deploy the provided Sigma rule to capture ADSI user creation attempts.
      owner: Detection Engineering
      due: 48h
      evidence: Rule enables detection of previously opaque persistence technique.
  hunt_leads:
    - lead: Search historic process execution logs for strings containing [ADSI] in combination with .Create('user') or .Create("user").
      technique_id: T1136
      data_needed:
        - Process creation telemetry with command line visibility
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Source identifies this pattern as a mechanism for user creation.
---

Security researchers have identified a technique where attackers leverage Active Directory Service Interfaces (ADSI) via PowerShell to create new user accounts on Windows systems. By utilizing the WinNT or LDAP providers directly within PowerShell scripts, an attacker can programmatically interact with the directory service, allowing for user creation without triggering standard detection logic that typically monitors for binaries like net.exe or cmdlets like New-LocalUser. This approach is primarily aimed at persistence and privilege escalation, as it allows for the quiet creation of backdoor accounts. Because this method interacts directly with the underlying directory infrastructure, it is rarely observed in typical day-to-day administrative operations, making it a high-fidelity indicator of potentially malicious activity when detected.

## Impact

Successful exploitation of this technique enables attackers to establish persistent access to a compromised machine or domain. By creating hidden or unmonitored accounts, adversaries can maintain a foothold, facilitate lateral movement, and escalate privileges. This method is particularly concerning because it evades common heuristic and signature-based detections focused on standard user management tools, potentially increasing the dwell time of an unauthorized actor within an enterprise environment.

## Recommendation

Deploy the provided Sigma detection rule to monitor for PowerShell command-line activity utilizing ADSI interfaces for user account creation. Investigate any findings to distinguish between legitimate automated provisioning tasks and anomalous creation events.

- Deploy the Sigma rule below to your SIEM and enable logging for PowerShell command-line arguments via Sysmon Event ID 1 or native PowerShell script block logging (Event ID 4104).
- Investigate any hits in the SOC to determine if the account creation was initiated by authorized IT automation tools or unauthorized scripts.
- Baseline administrative scripts in your environment that legitimately leverage ADSI to reduce noise from the detection rule.
