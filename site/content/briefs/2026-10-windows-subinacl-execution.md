---
title: Detection of Legacy Windows SubInAcl Utility Execution
slug: 2026-10-windows-subinacl-execution
description: The legacy Windows Resource Kit tool SubInAcl is being identified as a potential indicator of unauthorized security descriptor tampering or defense evasion on modern Windows environments.
date: "2026-10-12T18:22:59Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - privilege-escalation
  - windows
  - utility
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1222
    technique_name: File and Directory Permissions Modification
    evidence: The following analytic detects the execution of the SubInAcl utility to manipulate security descriptors of securable objects.
    confidence_band: high
references:
  - https://attack.mitre.org/techniques/T1222/001/
  - https://github.com/redcanaryco/atomic-red-team/blob/388942adbd9641f4dfdcf079d7efe9a75ec0ac43/atomics/T1222.001/T1222.001.yaml
rules:
  - title: Detect Execution of Legacy SubInAcl Utility
    description: Detects the execution of the SubInAcl utility which is commonly used to modify security descriptors for defense evasion or privilege escalation purposes.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1222.001
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
    - action: Deploy the Sigma detection rule to SIEM environment.
      owner: Detection Engineering
      due: 24h
      evidence: Source provides analytic logic for SubInAcl detection.
  hunt_leads:
    - lead: Search historical logs for any execution of subinacl.exe.
      technique_id: T1222.001
      data_needed:
        - Process creation events
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Utility is rare on modern systems.
---

SubInAcl is a legacy command-line utility originally released as part of the Windows 2003 Resource Kit. It is designed to allow administrators to modify security descriptors for files, registry keys, and services. In modern enterprise environments, the presence and execution of SubInAcl are highly anomalous, as the tool is deprecated and replaced by native PowerShell cmdlets or more modern administration tools. Attackers often leverage this utility to modify Access Control Lists (ACLs) on sensitive objects, such as Event Logs or security-related services, to blind EDR telemetry or grant themselves unauthorized access to protected resources. The rarity of this utility in a contemporary Windows environment makes its execution a high-fidelity signal for investigation into potential privilege escalation or defense evasion attempts.

## Attack Chain

1. Attacker gains initial access to a compromised Windows host via phishing or exploit.
2. Attacker downloads or stages the legitimate 'subinacl.exe' binary on the host to avoid using native modern tools.
3. Attacker identifies a target object, such as a security service or log file, with restrictive permissions.
4. Attacker executes 'subinacl.exe' to modify the security descriptors of the target object.
5. The utility updates the DACL (Discretionary Access Control List) to grant the attacker modify or full-control access.
6. Attacker leverages the modified access to disable security services, clear event logs, or exfiltrate protected sensitive data.

## Impact

Successful abuse of SubInAcl allows an attacker to bypass standard Windows security permissions, potentially resulting in the permanent disabling of security logging, modification of critical system service configurations, and unauthorized access to sensitive data files that are otherwise locked to the system or administrator accounts.

## Recommendation

Deploy the provided Sigma detection rule to all Windows endpoints to monitor for the unauthorized execution of the SubInAcl utility. Organizations should prioritize alerting on this process execution, as it is non-essential for daily operations on modern server or workstation builds.
