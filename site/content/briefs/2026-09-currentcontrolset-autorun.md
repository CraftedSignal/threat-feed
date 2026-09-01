---
title: Modification of CurrentControlSet Registry Autorun Extensibility Points
slug: 2026-09-currentcontrolset-autorun
description: Detects unauthorized modification of Windows Registry keys within CurrentControlSet used for persistent execution via system extensibility points.
date: "2026-09-01T13:09:51Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - privilege-escalation
  - registry
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: Detects modification of autostart extensibility point (ASEP) in registry.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: Detects modification of autostart extensibility point (ASEP) in registry.
    confidence_band: high
rules:
  - title: Detect Modification of ASEP Registry Keys in CurrentControlSet
    description: Detects modification of autostart extensibility point (ASEP) keys in the CurrentControlSet registry hive
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege-escalation
    techniques:
      - T1547.001
    data_sources:
      - registry_set
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy Sigma rules to SIEM to detect unauthorized registry modifications
      owner: Detection Engineering
      due: 72h
      evidence: Rule ID f674e36a-4b91-431e-8aef-f8a96c2aca35
  hunt_leads:
    - lead: Search for non-standard processes modifying registry keys in CurrentControlSet
      technique_id: T1547.001
      data_needed:
        - Sysmon registry events
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Sigma registry rules provide the logic for this hunt
  mitigation_plan:
    - priority: medium_term
      action: Implement strict change management for system-level registry modifications
      owner: IT Operations
      addresses: Unauthorized registry persistence
      evidence: General security hardening practice for ASEP monitoring
---

This brief addresses the monitoring of critical Windows Registry keys within 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control' that act as Autostart Extensibility Points (ASEPs). Threat actors frequently target these keys to achieve persistence or perform privilege escalation by ensuring malicious code executes during system startup or service initialization. Because these locations are rarely modified by standard user activity, changes to these keys by non-system processes or unexpected binaries often indicate malicious intent. Defenders should monitor these registry paths to identify unauthorized persistence mechanisms that survive reboots and bypass common user-land startup detection.

## Attack Chain

1. Attacker gains administrative access to the target host.
2. Attacker identifies a registry-based persistence target, such as 'Lsa\Notification Packages' or 'Print\Monitors'.
3. Attacker develops or drops a malicious DLL or executable intended for persistence.
4. Attacker uses legitimate tools (e.g., reg.exe) or custom scripts to modify the targeted registry key.
5. The Windows system reads the registry configuration upon the next boot or service restart.
6. The system executes the path or loads the DLL specified in the modified registry key with system-level privileges.
7. The malicious code achieves execution in a privileged context, completing the persistence cycle.

## Impact

Successful manipulation of these keys allows attackers to maintain long-term, stealthy access to a compromised system with high-level privileges. Because these points execute early in the OS lifecycle, they can be used to inject code into critical system processes, potentially leading to full system compromise, data exfiltration, or further lateral movement within the network.

## Recommendation

1. Deploy the provided Sigma rule to monitor for 'registry_set' activity targeting the 'CurrentControlSet\Control' hive.
2. Baseline your environment by identifying legitimate installers or administrative tools that modify these keys to reduce noise.
3. Investigate any process other than trusted system installers (e.g., spoolsv.exe with legitimate drivers) that performs write operations to these specific registry paths.
