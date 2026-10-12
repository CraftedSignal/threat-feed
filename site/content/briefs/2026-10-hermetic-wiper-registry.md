---
title: Hermetic Wiper Registry Modification Techniques
slug: 2026-10-hermetic-wiper-registry
description: Detection of Hermetic Wiper malware activities involving the manipulation of Windows registry keys 'ShowCompColor' and 'ShowInfoTip' to alter file visibility and UI elements.
date: "2026-10-12T18:13:51Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - windows
  - malware
  - registry
  - defense-evasion
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
    evidence: The following analytic detects suspicious modifications to the Windows registry keys related to file compression color and information tips.
    confidence_band: high
references:
  - https://blog.talosintelligence.com/2022/02/threat-advisory-hermeticwiper.html
rules:
  - title: Detect Modification of Windows Explorer Registry Settings
    description: Detects modifications to ShowCompColor and ShowInfoTip registry values associated with Hermetic Wiper malware
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1112
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
    - action: Deploy the registry modification detection rule to the SIEM environment
      owner: Detection Engineering
      due: 24h
      evidence: Source detection criteria for Hermetic Wiper
  hunt_leads:
    - lead: Search for historical changes to the specified registry keys on endpoints
      technique_id: T1112
      data_needed:
        - Registry modification logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Registry modifications observed in Hermetic Wiper malware
---

The Hermetic Wiper malware, first identified in early 2022, includes functionality to modify specific Windows registry keys that control the appearance and behavior of the Windows Explorer interface. Specifically, the malware alters 'ShowCompColor' and 'ShowInfoTip' values within the 'Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced' registry path. These modifications are associated with attempts to deceive users regarding file states or to manipulate the operating system's UI elements during the infection process. Defenders should treat modifications to these specific registry keys as a high-fidelity signal for potentially malicious activity, particularly in environments where unauthorized persistence or destructive wiping tools are a concern.

## Attack Chain

1. Initial access is established via exploitation or delivery of a malicious payload.
2. The malware gains elevated privileges to access sensitive registry hives.
3. The process targets the 'Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced' registry path.
4. The malware modifies the 'ShowCompColor' value to alter the display color of compressed files.
5. The malware modifies the 'ShowInfoTip' value to manipulate system information display tips.
6. These changes are intended to obfuscate malicious file attributes or modify user interface feedback.
7. Final objective: Destructive wiper activity, such as file system corruption or data destruction.

## Impact

The observed registry modifications are tied to the execution of Hermetic Wiper, a destructive wiper malware. If successful, this activity can lead to widespread data destruction, system inoperability, and the obfuscation of malicious file attributes, significantly complicating incident response and recovery efforts.

## Recommendation

* Deploy detection logic to monitor 'registry_set' events targeting 'ShowCompColor' and 'ShowInfoTip' within the specified Explorer path.
* Use Sysmon Event ID 13 to capture registry modifications and enrich with process information to identify the spawning parent application.
* Enable the provided Sigma rule in the SIEM to alert on unauthorized changes to these specific Windows Explorer configuration keys.
