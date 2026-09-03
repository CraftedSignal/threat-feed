---
title: PowerShell Local Account Manipulation
slug: 2026-09-powershell-localaccount-manipulation
description: Adversaries leverage native PowerShell cmdlets to manage and manipulate local user accounts for persistence and privilege escalation.
date: "2026-09-03T13:40:41Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - privilege-escalation
  - powershell
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: Adversaries may manipulate accounts to maintain access to victim systems.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: Account manipulation may consist of any action that preserves adversary access to a compromised account.
    confidence_band: high
rules:
  - title: Detect PowerShell Local Account Manipulation
    description: Detects the use of PowerShell cmdlets designed to manipulate local user accounts, a technique often used by adversaries for persistence or privilege escalation.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege-escalation
    techniques:
      - T1098
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Enable PowerShell Script Block Logging (Event ID 4104) across all endpoints.
      owner: IT Operations
      due: 72h
      evidence: Required telemetry for the detection rule.
  mitigation_plan:
    - priority: medium_term
      action: Restrict usage of local account modification cmdlets to approved service accounts via constrained language mode.
      owner: IT Operations
      addresses: T1098
      evidence: Technique mitigation strategy
---

Adversaries often manipulate local user accounts on compromised Windows systems to maintain persistent access or escalate privileges. This activity involves the use of standard PowerShell cmdlets from the Microsoft.PowerShell.LocalAccounts module, which are frequently abused for tasks such as creating new backdoored accounts, renaming existing accounts to evade detection, or modifying account permissions. Because these cmdlets are legitimate administrative tools, their usage is common in enterprise environments, making it difficult to distinguish between benign system administration and malicious unauthorized activity. Monitoring Script Block Logging (Event ID 4104) is critical for capturing the command-line parameters used during these operations, as attackers typically execute these commands via obfuscated scripts or direct interactive shells. Defenders should baseline common administrative behavior to reduce the noise associated with these detections.

## Impact

Successful manipulation of local accounts allows an attacker to establish long-term persistence, bypass credential expiration policies, or elevate privileges, significantly increasing the difficulty of eviction. Organizations that do not monitor for account modification events may fail to detect the unauthorized creation or takeover of local accounts, potentially leading to unauthorized data access and lateral movement across the internal network.

## Recommendation

Deploy the provided Sigma rule to capture unauthorized account manipulation attempts and tune for environment-specific administrative scripts.
- Enable PowerShell Script Block Logging (Event ID 4104) across all Windows endpoints.
- Implement monitoring for the use of LocalAccount cmdlets in scripts or interactive sessions.
- Establish a baseline of authorized administrative tasks to filter out false positives from legitimate management tools.
