---
title: Modification of Windows NT CurrentVersion Autorun Registry Keys
slug: 2026-09-currentversion-nt-autorun
description: Detection of unauthorized modifications to Windows registry keys that enable persistence through autostart extensibility points within the NT CurrentVersion hive.
date: "2026-09-01T12:27:45Z"
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
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_currentversion_nt.yml
  - https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns
rules:
  - title: Detect Modification of Windows NT Autorun Keys
    description: Detects modification of autostart extensibility points (ASEP) in the Windows NT CurrentVersion registry hive.
    platform: sigma
    severity: medium
    tactics:
      - persistence
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
  immediate_actions:
    - action: Deploy Sigma rule to monitor for registry persistence
      owner: Detection Engineering
      due: 48h
  hunt_leads:
    - lead: Review registry change logs for unusual Image path execution in NT CurrentVersion keys
      technique_id: T1547.001
      data_needed:
        - Registry set telemetry
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Source document identifies these as ASEP keys
---

This detection brief addresses the monitoring of registry modifications targeting Autostart Extensibility Points (ASEPs) located under the 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion' registry hive. Attackers frequently modify these keys to achieve persistence, as they control system processes, login shells, and initialization routines executed by the Windows operating system upon startup or user logon. Unauthorized changes to keys such as 'Winlogon', 'Appinit_Dlls', or 'Run' allow for the execution of arbitrary code with elevated privileges. Monitoring these paths is essential for detecting the initial stage of post-compromise persistence. This activity is a well-documented technique for maintaining long-term access in a compromised Windows environment and is frequently targeted by various threat actors.

## Impact

Successful modification of these registry keys enables attackers to maintain persistence, execute malicious payloads automatically upon system reboot or user login, and potentially gain elevated system privileges if the modified key interacts with high-integrity processes like 'Winlogon' or 'Userinit'. This can lead to total system compromise, exfiltration of sensitive data, and long-term undetected access to the internal network.

## Recommendation

Deploy the provided Sigma rule to monitor registry modification events ('registry_set') on Windows endpoints. Focus on filtering known-good administrative and installation activity to reduce noise, as installers often write to these keys during software deployment. Prioritize investigations of modifications by processes other than standard system installers or verified enterprise management software.
