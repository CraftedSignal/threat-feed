---
title: Modification of Session Manager Autorun Registry Keys
slug: 2026-09-session-manager-autorun-keys
description: This brief documents detection logic for monitoring unauthorized modifications to Windows Session Manager registry keys, which are often leveraged by attackers for persistence and privilege escalation.
date: "2026-09-01T12:09:21Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - privilege-escalation
  - registry
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547.001
    technique_name: 'Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder'
    evidence: Detects modification of autostart extensibility point (ASEP) in registry.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1546.009
    technique_name: 'Event Triggered Execution: AppCert DLLs'
    evidence: The rule monitors Session Manager keys including AppCertDlls which are used for Event Triggered Execution.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_session_manager.yml
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1547.001/T1547.001.md
rules:
  - title: Detect Session Manager Autorun Keys Modification
    description: Detects unauthorized modification of Session Manager autostart extensibility point (ASEP) registry keys.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege-escalation
    techniques:
      - T1546.009
      - T1547.001
    data_sources:
      - registry_set
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma rule to monitor for registry modifications in the specified Session Manager paths.
      owner: Detection Engineering
      due: 48h
  hunt_leads:
    - lead: Search for historical registry set events targeting Session Manager keys.
      technique_id: T1547.001
      data_needed:
        - Registry modification logs (Sysmon ID 12/13)
      priority: medium
      confidence: medium
      disposition: hunt_now
---

Windows Session Manager registry keys control critical system boot and execution processes. Adversaries frequently target these keys to achieve persistence or maintain high-privilege execution across reboots. By modifying values such as 'BootExecute', 'SetupExecute', or 'AppCertDlls', attackers can force the system to execute malicious code early in the boot sequence, often bypassing standard user-mode security controls. This activity is a known technique for both persistence and privilege escalation. Detection engineering teams should monitor registry modifications targeting these specific paths to identify suspicious additions or changes to execution strings that do not align with known software installations or legitimate administrative activity.

## Impact

Successful exploitation of Session Manager registry keys allows attackers to gain persistence at the system level, ensuring their malware executes every time the machine boots. This can lead to full system compromise, exfiltration of sensitive data, and the ability to maintain long-term access within a target environment.

## Recommendation

Deploy the provided Sigma rule to your SIEM to monitor for unauthorized modifications to Session Manager keys. 

- Enable Sysmon or Windows Security event logging (specifically Event ID 12 or 13 for registry set/value set) to capture registry modifications.
- Tune the detection logic by creating an allowlist for known legitimate software installers or administrative scripts that require modifications to these specific registry keys.
