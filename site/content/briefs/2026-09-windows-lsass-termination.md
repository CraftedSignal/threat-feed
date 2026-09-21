---
title: Detection of Unauthorized Lsass.exe Process Termination
slug: 2026-09-windows-lsass-termination
description: Detection of malicious processes attempting to terminate the Local Security Authority Subsystem Service (lsass.exe) using the PROCESS_TERMINATE access mask to facilitate system instability or disable security controls.
date: "2026-09-21T19:10:33Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - credential-access
  - windows
  - sysmon
vendors:
  - Microsoft
products:
  - Local Security Authority Subsystem Service (lsass.exe)
affected_os:
  - Windows
rules:
  - title: Detect Lsass.exe Process Termination Attempt
    description: Detects a process attempting to terminate the Lsass.exe process by checking for the PROCESS_TERMINATE (0x1) access mask in Sysmon Event ID 10 logs.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
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
    - action: Deploy the Sigma rule for Sysmon Event 10 monitoring.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific logic for EventCode 10 and GrantedAccess masks.
  hunt_leads:
    - lead: Search historical logs for any process requesting access to lsass.exe with the 0x1 mask.
      technique_id: T1685
      data_needed:
        - Sysmon Event ID 10 logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Analytic story highlights this as a primary indicator of wiper activity.
---

The Local Security Authority Subsystem Service (lsass.exe) is a core Windows process responsible for enforcing security policies and managing user credentials. Malicious actors, particularly those deploying destructive wipers like DoubleZero, often target this process to force a system shutdown, bypass security logging, or disable endpoint protection mechanisms. This brief focuses on the behavioral detection of unauthorized processes requesting the PROCESS_TERMINATE access mask (0x1) against lsass.exe. Monitoring this activity via Sysmon is critical for identifying potential data destruction attempts or sophisticated evasion techniques where an attacker seeks to cripple the host security posture.

## Impact

Successful termination of lsass.exe on a Windows system typically results in an immediate system crash or forced reboot, leading to service disruption, potential data loss, and the disabling of security monitoring and authentication services. This technique is characteristic of destructive campaigns where the goal is to render the system inoperable or to hide subsequent malicious activities from endpoint detection solutions.

## Recommendation

Prioritized actions for detection engineering teams:
- Enable Sysmon Event ID 10 across the environment with a configuration that includes monitoring for access requests to lsass.exe.
- Deploy the provided Sigma rule to detect processes requesting PROCESS_TERMINATE access.
- Investigate any process triggering this detection to identify the parent process, binary origin, and execution context.
- Implement memory protection policies for core system processes where possible to prevent unauthorized handle acquisition.
