---
title: Detection of UAC Notification Suppression via Registry
slug: 2026-09-uac-tampering
description: Detection of attackers suppressing Windows User Account Control (UAC) prompts by modifying the UACDisableNotify registry value to facilitate unauthorized system changes.
date: "2026-09-01T12:14:28Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - privilege-escalation
  - windows
  - registry
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
    evidence: Detects when an attacker tries to disable User Account Control (UAC) notification by tampering with the UACDisableNotify value.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_uac_disable_notification.yml
  - https://github.com/redcanaryco/atomic-red-team/blob/7e11e9b79583545f208a6dc3fa062f2ed443d999/atomics/T1548.002/T1548.002.md
rules:
  - title: Detect UAC Notification Suppression
    description: Detects when an attacker attempts to disable User Account Control (UAC) notification by tampering with the UACDisableNotify registry value.
    platform: sigma
    severity: medium
    tactics:
      - privilege-escalation
    techniques:
      - T1548.002
    data_sources:
      - registry_set
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule for registry monitoring
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific registry path and value to alert on
  mitigation_plan:
    - priority: medium_term
      action: Enforce GPO to prevent modification of UAC registry keys
      owner: IT Operations
      addresses: T1548.002
      evidence: Registry tampering is a known method for bypassing UAC
---

Windows User Account Control (UAC) acts as a primary security barrier, requiring administrative authorization for system-level modifications. Attackers commonly attempt to bypass or suppress these prompts to execute malicious binaries or alter system configurations without triggering user alerts. By modifying the registry key 'UACDisableNotify' to a value of 1, an attacker effectively silences UAC notifications, allowing for stealthier persistence and privilege escalation. This technique is frequently observed in post-compromise activity across various malware families, including banking trojans and modular backdoors, to ensure the environment remains permissive for subsequent stages of an attack.

## Impact

Successful suppression of UAC notifications reduces the likelihood of user intervention during malicious activity. This permits attackers to escalate privileges or modify sensitive system settings, such as disabling security software or establishing persistence, without alerting the local user or security administrators.

## Recommendation

Deploy the provided Sigma rule to monitor for registry modifications that disable UAC security prompts. Audit administrative accounts and Group Policy Objects (GPO) to ensure that UAC notification settings cannot be altered by standard or low-privileged processes.
