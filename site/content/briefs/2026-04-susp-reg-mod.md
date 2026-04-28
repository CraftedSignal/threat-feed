---
title: Suspicious Registry Modifications by Scripting Engines
slug: 2026-04-susp-reg-mod
description: Scripting engines such as WScript, CScript, and MSHTA are being used to make registry modifications, potentially for persistence or defense evasion.
date: "2026-04-14T12:50:16Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - registry-modification
  - persistence
  - defense-evasion
  - scripting-engine
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1059.005
    technique_name: 'Command and Scripting Interpreter: Visual Basic Script'
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.005
    technique_name: 'Command and Scripting Interpreter: Visual Basic Script'
references:
  - https://www.nextron-systems.com/2025/07/29/detecting-the-most-popular-mitre-persistence-method-registry-run-keys-startup-folder/
  - https://www.linkedin.com/posts/mauricefielenbach_livingofftheland-redteam-persistence-activity-7344801774182051843-TE00/
rules:
  - title: Registry Tampering by Potentially Suspicious Processes
    description: Detects suspicious registry modifications made by suspicious processes such as script engine processes such as WScript, or CScript etc.
    platform: sigma
    severity: medium
    tactics:
      - defense-evasion
      - execution
      - persistence
    techniques:
      - T1059.005
      - T1112
    data_sources:
      - registry_event
      - windows
rules_count: 1
---

This brief covers suspicious registry modifications made by scripting engine processes like WScript, CScript, and MSHTA. These processes are often abused by attackers to modify the registry without using standard tools like regedit.exe or reg.exe, potentially for evasion and persistence. Legitimate use of these scripting engines to modify the registry is uncommon, making this behavior a good indicator of potential malicious activity. Defenders should monitor for these processes interacting with sensitive registry keys. This activity was observed as of 2025 and continues to be a relevant technique for persistence and defense evasion in 2026.

## Attack Chain

1. An attacker gains initial access to a system via an exploit or social engineering.
2. The attacker uses MSHTA.exe to execute malicious HTML Application code.
3. MSHTA.exe is used to launch a PowerShell script.
4. The PowerShell script uses the Registry module to add a new registry key.
5. The registry key is configured to execute a payload upon system startup.
6. The attacker uses wscript.exe or cscript.exe to execute VBScript or JScript.
7. The script modifies registry values to disable security features.
8. The compromised system restarts, executing the payload defined in the registry, granting the attacker persistent access.

## Impact

Successful exploitation allows attackers to establish persistence on the targeted system, enabling them to maintain access even after a reboot. This can lead to data theft, further malware deployment, or complete system compromise. The impact ranges from minor data breaches to significant operational disruptions. The scope of the impact depends on the attacker's objectives and the compromised system's role within the organization.

## Recommendation

*   Deploy the Sigma rule "Registry Tampering by Potentially Suspicious Processes" to your SIEM to detect this specific activity, and tune for your environment (rules).
*   Investigate any instances of wscript.exe, cscript.exe or mshta.exe modifying registry keys outside of known-good paths (rules).
*   Monitor registry events for unexpected modifications by scripting engines, focusing on persistence-related keys (rules).
