---
title: Suspicious Registry Modifications by Scripting Engines
slug: 2026-04-susp-reg-mod
description: Scripting engines such as WScript, CScript, and MSHTA are being used to make registry modifications, potentially for persistence or defense evasion.
date: "2026-04-14T12:50:16Z"
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

This brief covers suspicious registry modifications made by scripting engine processes like WScript, CScript, and MSHTA. These processes are often abused by attackers to modify the registry without using standard tools like regedit.exe or reg.exe, potentially for evasion and persistence. Legitimate use of these scripting engines to modify the registry is uncommon, making this behavior a good indicator of potential malicious activity. Defenders should monitor for these processes interacting with…
