---
title: Modification of DisallowRun Registry Policy
slug: 2026-09-disallowrun-registry
description: An adversary or administrator can modify the DisallowRun registry key to prevent specific applications from executing, a technique often used to impair security tools or enforce restrictive environment configurations.
date: "2026-09-01T12:11:28Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - defense-impairment
  - registry
  - windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1112
    technique_name: Modify Registry
    evidence: The DisallowRun registry key is a Windows policy mechanism that allows administrators to explicitly prevent specific executable files from running.
    confidence_band: high
rules:
  - title: Detect Modification of DisallowRun Registry Policy
    description: Detects when the DisallowRun policy is set to 1, which blocks the execution of specified applications.
    platform: sigma
    severity: medium
    tactics:
      - defense-impairment
      - persistence
    techniques:
      - T1112
    data_sources:
      - registry_set
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection rule to production SIEM
      owner: Detection Engineering
      due: 48h
      evidence: Rule provided in brief
  mitigation_plan:
    - priority: medium_term
      action: Review Group Policy settings to ensure authorized use of DisallowRun
      owner: IT Operations
      addresses: Unauthorized registry modifications
---

The DisallowRun registry key is a Windows policy mechanism that allows administrators to explicitly prevent specific executable files from running. When a user or process sets the 'DisallowRun' value to 1 under 'HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer', the operating system will block the execution of any files defined in the corresponding 'DisallowRun' subkey. While intended for administrative control, threat actors may use this technique to impair security tools, disable EDR agents, or block analysis utilities from launching on a compromised host. Monitoring these registry modifications is essential for detecting unauthorized defense impairment and persistence-related hardening of a compromised system.

## Attack Chain

1. Attacker gains initial access to the target host via phishing or exploited service.
2. Attacker establishes command execution capability via a shell or script.
3. Attacker identifies security software binaries or administrative tools to block.
4. Attacker modifies the registry path 'HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun' to enable the policy.
5. Attacker populates the 'DisallowRun' subkey with names of targeted binaries (e.g., 'processhacker.exe', 'wireshark.exe').
6. The target application fails to launch, receiving a system access denied error when the user or actor attempts to run the binary.
7. The objective is achieved through the successful impairment of security visibility or response capabilities.

## Impact

Successful abuse of the DisallowRun policy results in the forced termination or prevention of legitimate security software. This impact disrupts incident response efforts, prevents the execution of anti-malware scanners, and limits the ability of security teams to monitor attacker activity on the affected endpoint.

## Recommendation

* Deploy the Sigma rule below to detect modifications to the DisallowRun policy key.
* Enable Windows Registry auditing (SACL) for 'Set Value' operations on 'HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\'.
* Investigate any processes modifying this key that are not associated with managed software deployment or authorized administrative tasks.
